// Type declarations for guard-bootstrap.mjs — idempotent discover-or-launch
// of the shared local guard daemon. Hand-written to pair with the ESM source.

export const GUARD_DIR: string
export const LOCK_FILE: string
export const DEFAULT_HOST: '127.0.0.1'
export const DEFAULT_PORT: 39111
export const PORT_SCAN_COUNT: 10

export interface GuardLock {
  version: string | null
  host: string
  port: number
  token: string
  pid?: number | null
  startedAt?: number
  updatedAt?: number
}

export interface GuardHealth {
  ok: boolean
  version: string | null
  instanceId?: string | null
}

export type LaunchResult =
  | { outcome: 'launched'; health: GuardHealth; pid?: number | null }
  | { outcome: 'in-use' }
  | { outcome: 'failed'; error?: unknown }

export interface EnsureGuardOpts {
  host?: string
  requiredVersion?: string | null
  candidatePorts?: number[]
  lockPath?: string
}

export interface EnsureGuardDeps {
  readLock?: () => GuardLock | null
  writeLock?: (lock: GuardLock) => GuardLock
  health?: (host: string, port: number, token?: string) => Promise<GuardHealth | null>
  launch?: (host: string, port: number, token: string) => Promise<LaunchResult>
  acquireLock?: () => Promise<boolean>
  releaseLock?: () => Promise<void>
  genToken?: () => string
  now?: () => number
}

export type EnsureGuardResult =
  | (GuardLock & { ok: true; status: 'reused' | 'launched' })
  | { ok: false; status: 'no-launcher' | 'launch-failed'; reason: string }

export function defaultCandidatePorts(base?: number, count?: number): number[]
export function readLock(path?: string): GuardLock | null
export function writeLock(lock: GuardLock, path?: string, dir?: string): GuardLock
export function genToken(): string
export function isCompatible(running: string | null | undefined, required: string | null | undefined): boolean
export function httpHealth(
  host: string,
  port: number,
  token?: string,
  opts?: { timeoutMs?: number; fetchImpl?: typeof fetch },
): Promise<GuardHealth | null>
export function ensureGuard(opts?: EnsureGuardOpts, deps?: EnsureGuardDeps): Promise<EnsureGuardResult>
