import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { mkdtempSync, mkdirSync, rmSync, existsSync, readFileSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const SCRIPT = join(__dirname, '..', 'scripts', 'pre-tool-use.mjs')

function startMockServer(handler) {
  return new Promise((resolve) => {
    const requests = []
    const server = createServer((req, res) => {
      let body = ''
      req.on('data', (c) => { body += c })
      req.on('end', () => {
        const parsed = body ? JSON.parse(body) : null
        requests.push({ method: req.method, url: req.url, body: parsed })
        const r = handler({ method: req.method, url: req.url, body: parsed }) ?? { status: 200, body: { ok: true } }
        res.writeHead(r.status, { 'content-type': 'application/json' })
        res.end(JSON.stringify(r.body))
      })
    })
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      resolve({ url: `http://127.0.0.1:${port}`, requests, close: () => new Promise((r) => server.close(r)) })
    })
  })
}

// Per-test fake HOME (and TMPDIR-sandboxed STATE_DIR underneath) so breaker
// state at ~/.vaibot/breaker-state/claudecode.json and run state at
// $TMPDIR/vaibot-claudecode/ don't leak between tests or pollute the user's
// real ~/.vaibot.
function withFakeHome(fn) {
  return async (t) => {
    const home = mkdtempSync(join(tmpdir(), 'vaibot-cc-breaker-'))
    try {
      await fn(t, home)
    } finally {
      try { rmSync(home, { recursive: true, force: true }) } catch {}
    }
  }
}

function runHook({ apiUrl, mode = 'enforce', input, env = {}, home }) {
  const fakeTmp = join(home, 'tmp')
  try { mkdirSync(fakeTmp, { recursive: true }) } catch {}
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SCRIPT], {
      env: {
        ...process.env,
        HOME: home,
        TMPDIR: fakeTmp,
        VAIBOT_API_URL: apiUrl,
        VAIBOT_API_KEY: 'test-key',
        VAIBOT_MODE: mode,
        VAIBOT_TIMEOUT_MS: '2000',
        VAIBOT_DASHBOARD_URL: 'https://www.vaibot.io',
        VAIBOT_BREAKER_FAILURE_THRESHOLD: '3',
        VAIBOT_BREAKER_WINDOW_MS: '60000',
        VAIBOT_BREAKER_COOLDOWN_MS: '60000',
        VAIBOT_BREAKER_ALLOWLIST: 'Read,Grep,Glob',
        VAIBOT_BREAKER_DENYLIST: '',
        ...env,
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (c) => { stdout += c })
    child.stderr.on('data', (c) => { stderr += c })
    child.on('error', reject)
    child.on('exit', (code) => resolve({ code, stdout, stderr }))
    child.stdin.write(JSON.stringify(input))
    child.stdin.end()
  })
}

const baseInput = {
  session_id: 'sess_b',
  tool_name: 'Bash',
  tool_use_id: 'tu_b',
  tool_input: { command: 'echo hi' },
  hook_event_name: 'PreToolUse',
  cwd: process.cwd(),
}

function breakerStateFile(home) {
  return join(home, '.vaibot', 'breaker-state', 'claudecode.json')
}

test('three consecutive 5xx trip the breaker; next non-allowlisted call denies locally without hitting API', withFakeHome(async (t, home) => {
  const server = await startMockServer(() => ({ status: 500, body: { error: 'oops' } }))

  for (let i = 0; i < 3; i++) {
    await runHook({ apiUrl: server.url, input: { ...baseInput, tool_input: { command: `attempt ${i}` } }, home })
  }

  const preCount = server.requests.length
  const r = await runHook({
    apiUrl: server.url,
    input: { ...baseInput, tool_input: { command: 'echo blocked' } },
    home,
  })
  assert.equal(server.requests.length, preCount, 'tripped breaker must short-circuit the API call')

  assert.equal(r.code, 0)
  const out = JSON.parse(r.stdout)
  assert.equal(out.hookSpecificOutput.permissionDecision, 'deny')
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /circuit breaker tripped/i)
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /not on the breaker allowlist/i)
  await server.close()
}))

test('allowlisted tool passes through when breaker is tripped — emits explicit allow', withFakeHome(async (t, home) => {
  const server = await startMockServer(() => ({ status: 500, body: { error: 'oops' } }))

  for (let i = 0; i < 3; i++) {
    await runHook({ apiUrl: server.url, input: { ...baseInput, tool_input: { command: `trip ${i}` } }, home })
  }

  const preCount = server.requests.length
  const r = await runHook({
    apiUrl: server.url,
    input: { ...baseInput, tool_name: 'Read', tool_input: { file_path: '/etc/hostname' } },
    home,
  })
  assert.equal(server.requests.length, preCount, 'allowlist pass-through must not call the API')
  assert.equal(r.code, 0)
  const out = JSON.parse(r.stdout)
  assert.equal(out.hookSpecificOutput.permissionDecision, 'allow',
    'claudecode emits explicit allow shape (unlike codex empty-stdout convention)')
  assert.match(r.stderr, /breaker.*allowlist pass-through for Read/i)
  await server.close()
}))

test('denylist denies even with API healthy when breaker is tripped', withFakeHome(async (t, home) => {
  const trip = await startMockServer(() => ({ status: 500, body: { error: 'oops' } }))
  for (let i = 0; i < 3; i++) {
    await runHook({ apiUrl: trip.url, input: { ...baseInput, tool_input: { command: `t ${i}` } }, home })
  }
  await trip.close()

  const healthy = await startMockServer(() => ({
    status: 200,
    body: {
      ok: true, run_id: 'r', risk: { risk: 'low' },
      decision: { decision: 'allow', reason: 'ok' },
      shadow_decision: { decision: 'allow', reason: 'ok' },
      content_hash: 'sha256:x',
    },
  }))
  const preCount = healthy.requests.length
  const r = await runHook({
    apiUrl: healthy.url,
    input: { ...baseInput, tool_name: 'DangerousTool' },
    env: { VAIBOT_BREAKER_DENYLIST: 'DangerousTool' },
    home,
  })
  assert.equal(healthy.requests.length, preCount, 'tripped denylist tool: API not called')
  assert.equal(r.code, 0)
  const out = JSON.parse(r.stdout)
  assert.equal(out.hookSpecificOutput.permissionDecision, 'deny')
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /breaker denylist/i)
  await healthy.close()
}))

test('401 (auth) does NOT count as a transient failure', withFakeHome(async (t, home) => {
  const server = await startMockServer(() => ({ status: 401, body: { error: 'unauthorized' } }))
  for (let i = 0; i < 5; i++) {
    await runHook({ apiUrl: server.url, input: { ...baseInput, tool_input: { command: `auth ${i}` } }, home })
  }
  const stateFile = breakerStateFile(home)
  if (existsSync(stateFile)) {
    const state = JSON.parse(readFileSync(stateFile, 'utf-8'))
    assert.deepEqual(state.breaker.failures, [], '401 must not record a breaker failure')
    assert.equal(state.breaker.trippedAt, null, '401 must not trip the breaker')
  }
  await server.close()
}))

test('successful API call resets the failure window', withFakeHome(async (t, home) => {
  let calls = 0
  const server = await startMockServer(() => {
    calls++
    if (calls <= 2) return { status: 500, body: { error: 'oops' } }
    return {
      status: 200,
      body: {
        ok: true, run_id: 'r', risk: { risk: 'low' },
        decision: { decision: 'allow', reason: 'ok' },
        shadow_decision: { decision: 'allow', reason: 'ok' },
        content_hash: 'sha256:x',
      },
    }
  })
  for (let i = 0; i < 3; i++) {
    await runHook({ apiUrl: server.url, input: { ...baseInput, tool_input: { command: `c ${i}` } }, home })
  }
  const state = JSON.parse(readFileSync(breakerStateFile(home), 'utf-8'))
  assert.deepEqual(state.breaker.failures, [], 'successful call must clear the failure window')
  assert.equal(state.breaker.trippedAt, null)
  await server.close()
}))

test('cooldown auto-resets the breaker after the window elapses', withFakeHome(async (t, home) => {
  const trip = await startMockServer(() => ({ status: 500, body: { error: 'oops' } }))
  for (let i = 0; i < 3; i++) {
    await runHook({
      apiUrl: trip.url,
      input: { ...baseInput, tool_input: { command: `t ${i}` } },
      env: { VAIBOT_BREAKER_COOLDOWN_MS: '200' },
      home,
    })
  }
  await trip.close()
  let state = JSON.parse(readFileSync(breakerStateFile(home), 'utf-8'))
  assert.ok(state.breaker.trippedAt, 'precondition: breaker tripped')

  await new Promise((r) => setTimeout(r, 300))

  const healthy = await startMockServer(() => ({
    status: 200,
    body: {
      ok: true, run_id: 'r2', risk: { risk: 'low' },
      decision: { decision: 'allow', reason: 'ok' },
      shadow_decision: { decision: 'allow', reason: 'ok' },
      content_hash: 'sha256:y',
    },
  }))
  const r = await runHook({
    apiUrl: healthy.url,
    input: { ...baseInput, tool_input: { command: 'after cooldown' } },
    env: { VAIBOT_BREAKER_COOLDOWN_MS: '200' },
    home,
  })
  assert.equal(r.code, 0)
  state = JSON.parse(readFileSync(breakerStateFile(home), 'utf-8'))
  assert.equal(state.breaker.trippedAt, null, 'breaker should be closed again')
  assert.deepEqual(state.breaker.failures, [])
  await healthy.close()
}))

test('observe mode + tripped breaker logs breadcrumb and allows (no block)', withFakeHome(async (t, home) => {
  const server = await startMockServer(() => ({ status: 500, body: { error: 'oops' } }))
  for (let i = 0; i < 3; i++) {
    await runHook({ apiUrl: server.url, input: { ...baseInput, tool_input: { command: `t ${i}` } }, home })
  }
  const r = await runHook({
    apiUrl: server.url,
    mode: 'observe',
    input: { ...baseInput, tool_input: { command: 'observe attempt' } },
    home,
  })
  assert.equal(r.code, 0)
  assert.match(r.stderr, /\[breaker observe\]: tripped/i)
  await server.close()
}))

test('breaker state file is 0o600 and dir is 0o700', withFakeHome(async (t, home) => {
  const server = await startMockServer(() => ({ status: 500, body: { error: 'oops' } }))
  await runHook({ apiUrl: server.url, input: baseInput, home })
  await server.close()

  const stateFile = breakerStateFile(home)
  assert.ok(existsSync(stateFile), 'state file should exist after a failure')
  const fileMode = statSync(stateFile).mode & 0o777
  const dirMode = statSync(join(home, '.vaibot', 'breaker-state')).mode & 0o777
  assert.equal(fileMode, 0o600, `state file should be 0o600, got 0o${fileMode.toString(8)}`)
  assert.equal(dirMode, 0o700, `state dir should be 0o700, got 0o${dirMode.toString(8)}`)
}))
