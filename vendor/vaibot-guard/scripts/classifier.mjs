// @vaibot/shared — stateless risk classifier for tool calls.
//
// Pure, deterministic classification of a SINGLE tool call by its intrinsic
// properties — category (read/write/exec/network), risk, trust-boundary
// crossing (ingress/egress), and reversibility. This drives three things in
// the no-allowlist model:
//   1. the local verdict hint (allow / ask / deny),
//   2. the offline fail-closed fallback (the breaker consults this when the
//      governance API is unreachable), and
//   3. the receipt tier (ledger vs signed receipt).
//
// There is deliberately NO allowlist. "Safe" is COMPUTED from properties on
// every call — never granted once and remembered — so there is no mutable,
// poisonable grant store. The built-in rule tables below are a sane baseline;
// they are overridable via `cfg.tables` so a signed policy bundle can inject
// an authoritative, richer ruleset without changing this engine.
//
// Authored as plain ESM (.mjs), same constraint as circuit-breaker.mjs and
// creds.mjs: the codex/claudecode hooks run as standalone node scripts and
// vendor a byte-identical copy under scripts/lib/classifier.mjs (guarded by a
// parity test). The openclaw plugin imports it from @vaibot/shared directly.

export const RISK = Object.freeze({
  SAFE: 'safe',
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  DANGEROUS: 'dangerous',
})

export const CATEGORY = Object.freeze({
  READ: 'read',
  WRITE: 'write',
  EXEC: 'exec',
  NETWORK: 'network',
  UNKNOWN: 'unknown',
})

export const BOUNDARY = Object.freeze({
  NONE: 'none',
  INGRESS: 'ingress',
  EGRESS: 'egress',
  BOTH: 'both',
})

export const VERDICT = Object.freeze({ ALLOW: 'allow', ASK: 'ask', DENY: 'deny' })
export const RECEIPT_TIER = Object.freeze({ NONE: 'none', LEDGER: 'ledger', RECEIPT: 'receipt' })

const RISK_RANK = { safe: 0, low: 1, medium: 2, high: 3, dangerous: 4 }

// The vaibot self/governance MCP namespace — the agent querying its own
// governance must never be gated by governance (matches the existing
// `mcp__vaibot__.*` self-skip in the hooks).
const SELF_MCP_PREFIX = 'mcp__vaibot__'

// ── Built-in rule tables (overridable via cfg.tables) ───────────────────────

function defaultTables() {
  return {
    readTools: ['read', 'grep', 'glob', 'ls', 'notebookread'],
    writeTools: ['write', 'edit', 'multiedit', 'apply_patch', 'applypatch', 'notebookedit'],
    networkTools: ['webfetch', 'web_fetch', 'fetch'],
    searchTools: ['websearch', 'web_search'],
    execTools: ['bash', 'shell', 'sh', 'exec', 'run', 'run_command', 'local_shell'],

    // Bash leading-word tables.
    safeCmds: [
      'ls', 'pwd', 'echo', 'cat', 'head', 'tail', 'wc', 'grep', 'egrep', 'fgrep',
      'rg', 'find', 'which', 'type', 'file', 'stat', 'du', 'df', 'date', 'whoami',
      'hostname', 'uname', 'true', 'dirname', 'basename', 'realpath', 'readlink',
      'tree', 'sort', 'uniq', 'cut', 'tr', 'diff', 'cmp', 'sha256sum', 'md5sum',
    ],
    networkCmds: [
      'curl', 'wget', 'nc', 'ncat', 'netcat', 'ssh', 'scp', 'sftp', 'rsync',
      'telnet', 'ftp',
    ],
    writeCmds: [
      'mv', 'cp', 'mkdir', 'rmdir', 'touch', 'tee', 'ln', 'install', 'make',
      'sed', 'awk', 'npm', 'pnpm', 'yarn', 'npx', 'pip', 'pip3', 'python',
      'python3', 'node', 'cargo', 'go', 'docker', 'kubectl', 'git', 'chmod',
      'chown', 'apt', 'apt-get', 'brew', 'systemctl', 'service',
    ],
    // git subcommands that only read.
    readGitSub: [
      'status', 'log', 'diff', 'show', 'branch', 'remote', 'rev-parse',
      'describe', 'blame', 'tag', 'ls-files', 'cat-file',
    ],
  }
}

// High-confidence destructive patterns → DENY. Kept conservative on purpose:
// the signed bundle carries the authoritative richer set. Anchored / bounded
// to avoid catastrophic backtracking.
const DENY_PATTERNS = [
  /\brm\s+(?:-[a-z]+\s+)*-[a-z]*[rf][a-z]*\s+(?:-[a-z]+\s+)*(?:\/|~|\*|\$HOME|\.\.)/i, // rm -rf on / ~ * .. $HOME
  /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, // fork bomb
  /\bmkfs(\.\w+)?\b/i,
  /\bdd\b[^|&;]*\bof=\/dev\/(sd|nvme|disk|hd)/i,
  /(^|[\s>])>\s*\/dev\/(sd|nvme|disk|hd)/i,
  /\bchmod\s+-R\s+0?777\s+\//i,
  /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh|dash)\b/i, // pipe remote → shell
  /\b(shutdown|reboot|halt|poweroff|init\s+0|init\s+6)\b/i,
]

// VAIBot guard self-protection (Tier-0 floor). A governed agent must never be
// able to kill the guard's singleton (port 39111) or stop/disable its process or
// systemd unit — doing so would silently switch off enforcement itself. Matched
// by port AND by name; un-overridable by any signed bundle, enforced offline.
// Stateless limitation: a two-step `pid=$(lsof -ti:39111); kill $pid` split across
// separate commands, or obfuscated/encoded forms, can still evade — this blocks
// the discoverable one-liners, not every conceivable path. `restart`/`status` stay
// allowed so the guard's own lifecycle isn't broken.
const GUARD_PROTECT_PATTERNS = [
  // by the singleton port: fuser -k 39111, lsof -ti:39111 | xargs kill,
  // kill $(lsof -t -i:39111), npx kill-port 39111, P=39111; fuser -k $P/tcp …
  /(?=[\s\S]*\b39111\b)(?=[\s\S]*\b(?:kill|pkill|killall|fuser|kill-port)\b)/i,
  // by process/service name: pkill -f vaibot-guard-service, killall vaibot-guard,
  // systemctl --user stop|disable|mask vaibot-guard
  /(?=[\s\S]*\bvaibot-guard(?:-service)?\b)(?=[\s\S]*\b(?:kill|pkill|killall|stop|disable|mask|fuser|kill-port|sigkill|sigterm)\b)/i,
  // the guard's own CLI teardown, run by an agent
  /\bvaibot\s+guard\s+(?:stop|disable|uninstall|remove)\b/i,
]

// Elevated-risk patterns → HIGH (ask). Recoverable-but-consequential.
const HIGH_PATTERNS = [
  /\bsudo\b/i,
  /(^|[\n|&;]\s*)su\b/i, // bare `su` — privilege escalation, same class as sudo
  /\bgit\s+push\b/i,
  /\b(npm|pnpm|yarn)\s+publish\b/i,
  /\b(flyctl?|fly|vercel|netlify)\s+deploy\b/i,
  /\bgit\s+reset\s+--hard\b/i,
  /\bgit\s+clean\s+-[a-z]*f/i,
  /(^|[\s>])>\s*\/etc\//i,
  /\bchown\s+-R\b[^|&;]*\s\/(?:\s|$)/i,
  /\beval\b/i,
  /\bbase64\s+-d\b[^|]*\|\s*(sh|bash)/i,
]

// Sensitive paths/identifiers — reading or touching these is high-value
// ingress/egress (secrets) → HIGH + always receipt.
const SENSITIVE_PATTERNS = [
  /\.ssh\b/i, /\bid_rsa\b/i, /\bid_ed25519\b/i, /\.aws(\/|\b)/i,
  /(^|\/|\s)\.env(\.[\w-]+)?(\s|$|['"])/i, /\/etc\/shadow\b/i, /\.npmrc\b/i,
  /\.git-credentials\b/i, /private[_-]?key/i, /\.pem\b/i, /credentials\.json\b/i,
  /\.kube\/config\b/i, /\bprintenv\b/i,
]

// ── Helpers ─────────────────────────────────────────────────────────────────

function norm(s) {
  return String(s ?? '').trim().toLowerCase()
}

function maxRisk(a, b) {
  return RISK_RANK[a] >= RISK_RANK[b] ? a : b
}

function unionBoundary(a, b) {
  if (a === b) return a
  if (a === BOUNDARY.NONE) return b
  if (b === BOUNDARY.NONE) return a
  return BOUNDARY.BOTH
}

function anyMatch(patterns, text) {
  for (const re of patterns) if (re.test(text)) return true
  return false
}

// Split a shell command into segments on pipes, sequencing, and logical ops.
function splitPipeline(command) {
  return String(command ?? '')
    .split(/\n|\||;|&&|\|\||&/)
    .map((s) => s.trim())
    .filter(Boolean)
}

function leadingWord(segment) {
  // Strip leading env-var assignments (FOO=bar cmd ...) to find the real
  // command word. (sudo is caught separately by HIGH_PATTERNS.)
  const tokens = segment.split(/\s+/).filter(Boolean)
  let i = 0
  while (i < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i])) i++
  return norm(tokens[i] ?? '')
}

/**
 * Classify a raw shell command string.
 * @param {string} command
 * @param {object} tables
 * @returns {{category:string, risk:string, boundary:string, reversible:boolean, reasons:string[]}}
 */
export function classifyBash(command, tables = defaultTables()) {
  const reasons = []
  const full = String(command ?? '')
  if (!full.trim()) {
    return { category: CATEGORY.EXEC, risk: RISK.MEDIUM, boundary: BOUNDARY.NONE, reversible: true, reasons: ['empty command'] }
  }

  if (anyMatch(GUARD_PROTECT_PATTERNS, full)) {
    return { category: CATEGORY.EXEC, risk: RISK.DANGEROUS, boundary: BOUNDARY.EGRESS, reversible: false, reasons: ['would disable the VAIBot guard (protected: port 39111 / vaibot-guard)'] }
  }

  if (anyMatch(DENY_PATTERNS, full)) {
    return { category: CATEGORY.EXEC, risk: RISK.DANGEROUS, boundary: BOUNDARY.EGRESS, reversible: false, reasons: ['matches destructive pattern'] }
  }

  let risk = RISK.SAFE
  let category = CATEGORY.READ
  let boundary = BOUNDARY.NONE
  let reversible = true

  if (anyMatch(HIGH_PATTERNS, full)) {
    risk = maxRisk(risk, RISK.HIGH)
    reversible = false
    reasons.push('matches elevated-risk pattern')
  }
  if (anyMatch(SENSITIVE_PATTERNS, full)) {
    risk = maxRisk(risk, RISK.HIGH)
    boundary = unionBoundary(boundary, BOUNDARY.BOTH)
    reasons.push('touches a sensitive path/secret')
  }

  const safe = new Set(tables.safeCmds)
  const net = new Set(tables.networkCmds)
  const write = new Set(tables.writeCmds)
  const readGit = new Set(tables.readGitSub)

  for (const seg of splitPipeline(full)) {
    const cmd = leadingWord(seg)
    if (!cmd) continue
    if (net.has(cmd)) {
      category = CATEGORY.NETWORK
      boundary = unionBoundary(boundary, BOUNDARY.BOTH)
      risk = maxRisk(risk, RISK.HIGH) // egress stays on the ask lane even at balanced's HIGH threshold
      reversible = false
      reasons.push(`network command: ${cmd}`)
    } else if (cmd === 'git') {
      const sub = norm(seg.split(/\s+/).filter(Boolean)[1])
      if (readGit.has(sub)) {
        category = maxRisk(risk, RISK.SAFE) === RISK.SAFE ? CATEGORY.READ : category
        boundary = unionBoundary(boundary, BOUNDARY.INGRESS)
        reasons.push(`git read: ${sub || '(none)'}`)
      } else {
        category = CATEGORY.WRITE
        boundary = unionBoundary(boundary, BOUNDARY.EGRESS)
        risk = maxRisk(risk, RISK.LOW)
        reversible = false
        reasons.push(`git mutating: ${sub || '(none)'}`)
      }
    } else if (write.has(cmd)) {
      category = CATEGORY.WRITE
      boundary = unionBoundary(boundary, BOUNDARY.EGRESS)
      risk = maxRisk(risk, RISK.LOW)
      reversible = false
      reasons.push(`mutating command: ${cmd}`)
    } else if (safe.has(cmd)) {
      boundary = unionBoundary(boundary, BOUNDARY.INGRESS)
      reasons.push(`safe command: ${cmd}`)
    } else {
      // Unknown command → ambiguous → ask.
      category = category === CATEGORY.READ ? CATEGORY.EXEC : category
      risk = maxRisk(risk, RISK.MEDIUM)
      reversible = false
      reasons.push(`unknown command: ${cmd}`)
    }
  }

  return { category, risk, boundary, reversible, reasons }
}

/**
 * Map a risk level to a verdict hint, given the (per-preset) escalation
 * threshold. DANGEROUS always denies (Tier-0 floor). Otherwise, risk that
 * meets/exceeds `escalateAt` asks; below it allows. Default MEDIUM preserves
 * the prior behavior; the balanced preset raises it to HIGH ("medium = safe").
 */
export function verdictForRisk(risk, escalateAt = RISK.MEDIUM) {
  if (risk === RISK.DANGEROUS) return VERDICT.DENY
  const threshold = RISK_RANK[escalateAt] ?? RISK_RANK[RISK.MEDIUM]
  if (RISK_RANK[risk] >= threshold) return VERDICT.ASK
  return VERDICT.ALLOW
}

/** Map risk + boundary to a receipt tier. */
export function receiptTierFor(risk, boundary) {
  if (
    RISK_RANK[risk] >= RISK_RANK[RISK.HIGH] ||
    boundary === BOUNDARY.EGRESS ||
    boundary === BOUNDARY.BOTH
  ) {
    return RECEIPT_TIER.RECEIPT
  }
  return RECEIPT_TIER.LEDGER // every governed call is at least ledgered
}

function inputText(input) {
  if (input == null) return ''
  if (typeof input === 'string') return input
  try {
    return JSON.stringify(input)
  } catch {
    return ''
  }
}

function inputPath(input) {
  if (!input || typeof input !== 'object') return ''
  return String(input.file_path ?? input.filePath ?? input.path ?? '')
}

/**
 * Classify a single tool call.
 *
 * @param {{tool: string, input?: any}} call
 * @param {{tables?: object}} [cfg]
 * @returns {{tool:string, category:string, risk:string, boundary:string, reversible:boolean, verdictHint:string, receiptTier:string, reasons:string[]}}
 */
export function classify(call, cfg = {}) {
  const tables = cfg.tables ?? defaultTables()
  const escalateAt = cfg.escalateAt // per-preset ask threshold (undefined ⇒ default MEDIUM)
  const rawTool = String(call?.tool ?? '')
  const tool = norm(rawTool)
  const input = call?.input
  const reasons = []

  let category = CATEGORY.UNKNOWN
  let risk = RISK.MEDIUM
  let boundary = BOUNDARY.BOTH
  let reversible = false

  if (rawTool.startsWith(SELF_MCP_PREFIX)) {
    // vaibot's own governance tools — never gate, never escalate.
    return finalize(rawTool, CATEGORY.READ, RISK.SAFE, BOUNDARY.NONE, true, ['vaibot self/governance call'])
  }

  const execTools = new Set(tables.execTools)
  const readTools = new Set(tables.readTools)
  const writeTools = new Set(tables.writeTools)
  const networkTools = new Set(tables.networkTools)
  const searchTools = new Set(tables.searchTools)

  if (execTools.has(tool)) {
    const command = typeof input === 'string' ? input : input?.command ?? input?.cmd ?? ''
    const b = classifyBash(command, tables)
    return finalize(rawTool, b.category, b.risk, b.boundary, b.reversible, b.reasons, escalateAt)
  }

  if (readTools.has(tool)) {
    category = CATEGORY.READ
    boundary = BOUNDARY.INGRESS
    reversible = true
    risk = RISK.SAFE
    reasons.push(`read tool: ${tool}`)
  } else if (writeTools.has(tool)) {
    category = CATEGORY.WRITE
    boundary = BOUNDARY.EGRESS
    reversible = false
    risk = RISK.LOW
    reasons.push(`write tool: ${tool}`)
  } else if (searchTools.has(tool)) {
    category = CATEGORY.NETWORK
    boundary = BOUNDARY.INGRESS
    reversible = true
    risk = RISK.LOW
    reasons.push(`search tool: ${tool}`)
  } else if (networkTools.has(tool)) {
    category = CATEGORY.NETWORK
    boundary = BOUNDARY.BOTH
    reversible = false
    risk = RISK.HIGH // egress stays on the ask lane even at balanced's HIGH threshold
    reasons.push(`network tool: ${tool}`)
  } else if (rawTool.startsWith('mcp__')) {
    // Third-party MCP tool — its result is untrusted ingress; could egress too.
    category = CATEGORY.UNKNOWN
    boundary = BOUNDARY.BOTH
    reversible = false
    risk = RISK.MEDIUM
    reasons.push('third-party MCP tool')
  } else {
    reasons.push(`unknown tool: ${tool || '(empty)'}`)
  }

  // Path/secret escalation for read/write tools.
  const text = `${inputPath(input)} ${inputText(input)}`
  if (anyMatch(SENSITIVE_PATTERNS, text)) {
    risk = maxRisk(risk, RISK.HIGH)
    boundary = unionBoundary(boundary, BOUNDARY.BOTH)
    reasons.push('touches a sensitive path/secret')
  }

  return finalize(rawTool, category, risk, boundary, reversible, reasons, escalateAt)
}

function finalize(tool, category, risk, boundary, reversible, reasons, escalateAt) {
  return {
    tool,
    category,
    risk,
    boundary,
    reversible,
    verdictHint: verdictForRisk(risk, escalateAt),
    receiptTier: receiptTierFor(risk, boundary),
    reasons,
  }
}
