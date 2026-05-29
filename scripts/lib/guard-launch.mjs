// @vaibot/shared — real launch dep + default wiring for ensureGuard.
//
// Provides the process-spawning half of the guard bootstrapper: a TCP probe to
// detect an occupied port (port-as-mutex) and a launcher that spawns the guard
// service detached, waits for /health, and reports launched|in-use|failed in
// the shape ensureGuard() expects. ensureGuardDefault() wires it together with
// the real httpHealth + fs lock I/O from guard-bootstrap.
//
// Plain ESM so the guard + vendored hook copies can use it at runtime.

import { spawn } from 'node:child_process'
import net from 'node:net'
import { ensureGuard, httpHealth } from './guard-bootstrap.mjs'

/** Resolve true if something is already listening on host:port. */
export function tcpProbe(host, port, opts = {}) {
  const { timeoutMs = 600 } = opts
  return new Promise((resolve) => {
    let done = false
    const finish = (v) => {
      if (done) return
      done = true
      try {
        sock.destroy()
      } catch {
        /* ignore */
      }
      resolve(v)
    }
    const sock = net.createConnection({ host, port })
    sock.setTimeout(timeoutMs)
    sock.once('connect', () => finish(true))
    sock.once('timeout', () => finish(false))
    sock.once('error', () => finish(false))
  })
}

/**
 * Build a launch(host, port, token) for ensureGuard that spawns the guard
 * service script detached and waits for an identity-bearing /health.
 *   - port already occupied → { outcome: 'in-use' } (ensureGuard identity-checks)
 *   - became healthy        → { outcome: 'launched', health, pid }
 *   - never healthy / error  → { outcome: 'failed', error }
 */
export function makeLauncher(cfg = {}) {
  const { guardScript, baseEnv = {}, healthTimeoutMs = 4000, pollMs = 150 } = cfg
  return async function launch(host, port, token) {
    if (await tcpProbe(host, port)) return { outcome: 'in-use' }

    let child
    try {
      child = spawn(process.execPath, [guardScript], {
        env: {
          ...process.env,
          ...baseEnv,
          VAIBOT_GUARD_HOST: host,
          VAIBOT_GUARD_PORT: String(port),
          VAIBOT_GUARD_TOKEN: token,
        },
        detached: true,
        stdio: 'ignore',
      })
      child.unref()
    } catch (error) {
      return { outcome: 'failed', error }
    }

    const deadline = Date.now() + healthTimeoutMs
    while (Date.now() < deadline) {
      const h = await httpHealth(host, port, token, { timeoutMs: 800 })
      if (h && h.ok) return { outcome: 'launched', health: h, pid: child.pid }
      await new Promise((r) => setTimeout(r, pollMs))
    }
    try {
      if (child.pid) process.kill(child.pid)
    } catch {
      /* ignore */
    }
    return { outcome: 'failed', error: new Error('guard did not become healthy within timeout') }
  }
}

/**
 * ensureGuard with real defaults: httpHealth + fs lock I/O (from
 * guard-bootstrap) + a spawning launcher. `opts.guardScript` is the path to
 * vaibot-guard-service.mjs; `opts.guardEnv` supplies the guard's runtime env
 * (workspace, log dir, policy path, API creds, etc.).
 */
export async function ensureGuardDefault(opts = {}) {
  const launch = makeLauncher({
    guardScript: opts.guardScript,
    baseEnv: opts.guardEnv,
    healthTimeoutMs: opts.healthTimeoutMs,
    pollMs: opts.pollMs,
  })
  return ensureGuard(opts, { launch })
}
