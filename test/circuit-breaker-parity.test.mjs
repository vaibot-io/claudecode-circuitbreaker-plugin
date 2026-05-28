import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

// Guards the vendored copy of the CircuitBreaker module. The Claude Code hooks
// run as standalone node scripts and can't import @vaibot/shared at runtime,
// so scripts/lib/circuit-breaker.mjs is a verbatim copy of
// packages/shared/src/circuit-breaker.mjs. This test fails if the copy drifts
// from the canonical source.

const __dirname = dirname(fileURLToPath(import.meta.url))
const VENDORED = join(__dirname, '..', 'scripts', 'lib', 'circuit-breaker.mjs')
const CANONICAL = join(__dirname, '..', '..', 'shared', 'src', 'circuit-breaker.mjs')

test('vendored circuit-breaker.mjs is byte-identical to @vaibot/shared source', () => {
  assert.equal(
    readFileSync(VENDORED, 'utf-8'),
    readFileSync(CANONICAL, 'utf-8'),
    'scripts/lib/circuit-breaker.mjs has drifted — re-copy from packages/shared/src/circuit-breaker.mjs',
  )
})

test('vendored circuit-breaker.mjs exposes the expected API', async () => {
  const m = await import(VENDORED)
  assert.equal(typeof m.CircuitBreaker, 'function', 'missing CircuitBreaker class')
  assert.equal(typeof m.DEFAULT_FAILURE_THRESHOLD, 'number')
  assert.equal(typeof m.DEFAULT_WINDOW_MS, 'number')
  assert.equal(typeof m.DEFAULT_COOLDOWN_MS, 'number')

  const cb = new m.CircuitBreaker({ failureThreshold: 3, windowMs: 10_000 })
  for (const fn of ['load', 'snapshot', 'recordFailure', 'recordSuccess', 'isTripped', 'canAllow', 'isDenied']) {
    assert.equal(typeof cb[fn], 'function', `missing method: ${fn}`)
  }
})
