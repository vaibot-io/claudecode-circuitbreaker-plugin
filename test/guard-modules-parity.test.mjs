import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

// Guards the vendored copies of the guard adapter modules. The Claude Code
// hooks run as standalone node scripts and can't import @vaibot/shared at
// runtime, so
// scripts/lib/{guard-bootstrap,guard-launch,guard-client}.mjs are verbatim
// copies. These tests fail if a copy drifts from the canonical source.

const __dirname = dirname(fileURLToPath(import.meta.url))
const libDir = join(__dirname, '..', 'scripts', 'lib')
const srcDir = join(__dirname, '..', '..', 'shared', 'src')
const MODULES = ['guard-bootstrap.mjs', 'guard-launch.mjs', 'guard-client.mjs']

for (const m of MODULES) {
  test(`vendored ${m} is byte-identical to @vaibot/shared source`, () => {
    assert.equal(
      readFileSync(join(libDir, m), 'utf-8'),
      readFileSync(join(srcDir, m), 'utf-8'),
      `scripts/lib/${m} has drifted — re-copy from packages/shared/src/${m}`,
    )
  })
}

test('vendored guard modules expose the expected API', async () => {
  const boot = await import(join(libDir, 'guard-bootstrap.mjs'))
  assert.equal(typeof boot.ensureGuard, 'function')
  assert.equal(typeof boot.isCompatible, 'function')
  const launch = await import(join(libDir, 'guard-launch.mjs'))
  assert.equal(typeof launch.ensureGuardDefault, 'function')
  assert.equal(typeof launch.tcpProbe, 'function')
  const client = await import(join(libDir, 'guard-client.mjs'))
  assert.equal(typeof client.decideViaGuard, 'function')
  assert.equal(typeof client.guardDecisionToVerdict, 'function')
})
