// @vaibot/shared — credential store + environment resolver.
//
// Single source of truth for: which environment a surface is operating in,
// where its credentials live on disk, and how to read/write them without one
// environment clobbering the other. See the bifurcation plan
// (credential-environment-bifurcation-plan-2026-05-22).
//
// Authored as plain ESM (.mjs) on purpose: the Claude Code and Codex hook
// plugins run as standalone node scripts and cannot import a workspace package
// at runtime, so they vendor a *verbatim copy* of this file at
// scripts/lib/creds.mjs, guarded by a parity test. TypeScript consumers
// (@vaibot/cli, the OpenClaw plugin) import it via the bundled creds.d.mts.
//
// Store schema (v2), ~/.vaibot/credentials.json:
//   {
//     "version": 2,
//     "active_env": "production",
//     "environments": {
//       "production": { "api_key": "vb_live_…", "wallet_address": "0x…" },
//       "staging":    { "api_key": "vb_stg_…", "wallet_address": "0x…" }
//     }
//   }
// Only api_key + wallet_address are persisted — everything else is derivable
// (api_url from env) or fetchable (/v2/accounts/me).

import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

export const STORE_VERSION = 2
export const ENVS = /** @type {const} */ (['production', 'staging'])
export const DEFAULT_ENV = 'production'

const API_BASE = {
  production: 'https://api.vaibot.io',
  staging: 'https://staging-api.vaibot.io',
}

// Server-enforced key prefixes (apps/api): vb_live_* on prod, vb_stg_* on staging.
const KEY_PREFIX = {
  production: 'vb_live_',
  staging: 'vb_stg_',
}

// ── Env helpers ──────────────────────────────────────────────────────────────

export function isEnv(value) {
  return value === 'production' || value === 'staging'
}

export function apiBaseForEnv(envName, override) {
  if (override) return String(override).replace(/\/+$/, '')
  return API_BASE[envName] ?? API_BASE[DEFAULT_ENV]
}

export function keyPrefixForEnv(envName) {
  return KEY_PREFIX[envName] ?? ''
}

// Which env does an api_key's prefix indicate? null if unrecognized
// (custom / legacy / test keys are intentionally not forced into an env).
export function envForKey(apiKey) {
  if (typeof apiKey !== 'string') return null
  if (apiKey.startsWith(KEY_PREFIX.production)) return 'production'
  if (apiKey.startsWith(KEY_PREFIX.staging)) return 'staging'
  return null
}

// Lenient prefix guard: a key with a *recognized* prefix must match envName;
// an unrecognized prefix is allowed rather than blocked (avoids false denials).
export function keyPrefixMatchesEnv(apiKey, envName) {
  const keyEnv = envForKey(apiKey)
  return keyEnv === null || keyEnv === envName
}

// Map an API base URL to an env. Unknown hosts → null (no custom/local envs;
// the env set is closed at production/staging).
export function envForApiUrl(url) {
  if (typeof url !== 'string' || !url) return null
  let host
  try { host = new URL(url).host } catch { return null }
  if (host === 'api.vaibot.io') return 'production'
  if (host === 'staging-api.vaibot.io' || host.includes('staging')) return 'staging'
  return null
}

// ── Path resolution ──────────────────────────────────────────────────────────

export function resolveCredsDir(opts = {}) {
  if (opts.dir) return opts.dir
  const env = opts.env ?? process.env
  return env.VAIBOT_CREDS_DIR || join(homedir(), '.vaibot')
}

export function credsPath(opts = {}) {
  return join(resolveCredsDir(opts), 'credentials.json')
}

// ── Environment resolution ───────────────────────────────────────────────────
// Precedence: VAIBOT_ENV → VAIBOT_API_URL → VAIBOT_API_KEY prefix →
//             stored active key prefix → stored active_env → default.

export function resolveEnv(opts = {}) {
  const env = opts.env ?? process.env
  if (isEnv(env.VAIBOT_ENV)) return env.VAIBOT_ENV

  const fromUrl = envForApiUrl(env.VAIBOT_API_URL)
  if (fromUrl) return fromUrl

  const fromEnvKey = envForKey(env.VAIBOT_API_KEY)
  if (fromEnvKey) return fromEnvKey

  const store = opts.store ?? loadStore(opts)
  const fromStoreKey = envForKey(store.environments?.[store.active_env]?.api_key)
  if (fromStoreKey) return fromStoreKey
  if (isEnv(store.active_env)) return store.active_env

  return DEFAULT_ENV
}

// ── Store: load / migrate / save ─────────────────────────────────────────────

export function emptyStore() {
  return { version: STORE_VERSION, active_env: DEFAULT_ENV, environments: {} }
}

// Persist only the slim schema, regardless of what extra fields a caller passes.
function slimRecord(rec) {
  const out = { api_key: rec.api_key }
  if (typeof rec.wallet_address === 'string' && rec.wallet_address) {
    out.wallet_address = rec.wallet_address
  }
  return out
}

// Pure: normalize any parsed JSON into a v2 store (in memory). Never throws.
export function migrateStore(raw) {
  if (!raw || typeof raw !== 'object') return emptyStore()

  // Already v2 (or newer with environments) — normalize defensively.
  if (raw.version >= STORE_VERSION && raw.environments && typeof raw.environments === 'object') {
    const out = emptyStore()
    out.active_env = isEnv(raw.active_env) ? raw.active_env : DEFAULT_ENV
    for (const e of ENVS) {
      const rec = raw.environments[e]
      if (rec && typeof rec.api_key === 'string' && rec.api_key) {
        out.environments[e] = slimRecord(rec)
      }
    }
    return out
  }

  // v1 flat: { api_key, api_url?, wallet_address?, account_id?, ... }
  if (typeof raw.api_key === 'string' && raw.api_key) {
    const e = envForApiUrl(raw.api_url) ?? envForKey(raw.api_key) ?? DEFAULT_ENV
    const out = emptyStore()
    out.active_env = e
    out.environments[e] = slimRecord(raw)
    return out
  }

  return emptyStore()
}

// Read + migrate in memory. Never writes, never throws. Missing/corrupt → empty.
export function loadStore(opts = {}) {
  const path = opts.path ?? credsPath(opts)
  let raw
  try {
    raw = JSON.parse(readFileSync(path, 'utf-8'))
  } catch {
    return emptyStore()
  }
  return migrateStore(raw)
}

export function loadCredsForEnv(envName, opts = {}) {
  const store = opts.store ?? loadStore(opts)
  return store.environments?.[envName] ?? null
}

function atomicWriteJson(dir, path, value) {
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const tmp = join(dir, `credentials.json.tmp-${process.pid}-${Math.random().toString(36).slice(2)}`)
  writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 })
  renameSync(tmp, path)
}

// Merge-on-write: read the latest store, set ONLY this env's slot (slimmed),
// bump active_env, then write atomically (temp + rename). The merge prevents a
// concurrent save to the *other* env from being clobbered; the rename prevents
// a crash from truncating the file.
export function saveCredsForEnv(envName, record, opts = {}) {
  if (!isEnv(envName)) throw new Error(`saveCredsForEnv: unknown env "${envName}"`)
  if (!record || typeof record.api_key !== 'string' || !record.api_key) {
    throw new Error('saveCredsForEnv: record.api_key is required')
  }
  const dir = resolveCredsDir(opts)
  const path = join(dir, 'credentials.json')

  const store = loadStore({ ...opts, path })
  store.environments[envName] = slimRecord(record)
  store.active_env = envName

  atomicWriteJson(dir, path, store)
  return store
}

// One-time on-disk migration: if the file isn't already v2, back it up to
// credentials.json.bak (once) and rewrite it in v2 shape. Safe to call on every
// startup — a no-op when already v2, when no file exists, or when corrupt.
export function migrateFileIfNeeded(opts = {}) {
  const dir = resolveCredsDir(opts)
  const path = join(dir, 'credentials.json')

  let rawText
  try {
    rawText = readFileSync(path, 'utf-8')
  } catch {
    return { migrated: false, reason: 'no-file' }
  }

  let parsed
  try {
    parsed = JSON.parse(rawText)
  } catch {
    return { migrated: false, reason: 'unparseable' } // never touch corrupt files
  }

  if (parsed && parsed.version >= STORE_VERSION) {
    return { migrated: false, reason: 'already-v2' }
  }

  const store = migrateStore(parsed)
  const bak = join(dir, 'credentials.json.bak')
  if (!existsSync(bak)) {
    try { writeFileSync(bak, rawText, { mode: 0o600 }) } catch { /* best-effort */ }
  }
  atomicWriteJson(dir, path, store)
  return { migrated: true, store }
}

// All-in-one resolver — the entry point surfaces call to talk to the right API.
//
//   { env, apiBaseUrl, apiKey, walletAddress, keyMismatch }
//
// - env:          production | staging (resolveEnv precedence)
// - apiBaseUrl:   VAIBOT_API_URL override, else the env's canonical base URL
// - apiKey:       VAIBOT_API_KEY override, else the stored key for env.
//                 null when the only candidate fails the prefix guard.
// - walletAddress:stored public address for env (display only), or null
// - keyMismatch:  true when a candidate key's prefix names a different env
//                 (e.g. a vb_live_ key while resolving staging). Callers should
//                 treat apiKey as missing and re-bootstrap for this env.
export function resolveCredentials(opts = {}) {
  const env = opts.env ?? process.env
  const store = opts.store ?? loadStore(opts)
  const envName = resolveEnv({ ...opts, env, store })
  const apiBaseUrl = apiBaseForEnv(envName, env.VAIBOT_API_URL)

  const record = store.environments?.[envName] ?? null
  const walletAddress = record?.wallet_address ?? null

  const candidate = env.VAIBOT_API_KEY || record?.api_key || null
  let apiKey = candidate
  let keyMismatch = false
  if (candidate && !keyPrefixMatchesEnv(candidate, envName)) {
    apiKey = null
    keyMismatch = true
  }

  return { env: envName, apiBaseUrl, apiKey, walletAddress, keyMismatch }
}
