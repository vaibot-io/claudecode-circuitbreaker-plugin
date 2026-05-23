import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

// Guards the vendored copy of the credential resolver. The Claude Code hooks
// run as standalone node scripts and can't import @vaibot/shared at runtime, so
// scripts/lib/creds.mjs is a verbatim copy of packages/shared/src/creds.mjs.
// This test fails if the copy drifts from the canonical source.

const __dirname = dirname(fileURLToPath(import.meta.url))
const VENDORED = join(__dirname, '..', 'scripts', 'lib', 'creds.mjs')
const CANONICAL = join(__dirname, '..', '..', 'shared', 'src', 'creds.mjs')

test('vendored creds.mjs is byte-identical to @vaibot/shared source', () => {
  assert.equal(
    readFileSync(VENDORED, 'utf-8'),
    readFileSync(CANONICAL, 'utf-8'),
    'scripts/lib/creds.mjs has drifted — run `pnpm sync:vendored-creds` at the repo root',
  )
})

test('vendored creds.mjs loads and exports the resolver API', async () => {
  const m = await import(VENDORED)
  for (const fn of [
    'resolveCredentials', 'resolveEnv', 'loadCredsForEnv',
    'saveCredsForEnv', 'migrateFileIfNeeded', 'keyPrefixMatchesEnv',
  ]) {
    assert.equal(typeof m[fn], 'function', `missing export: ${fn}`)
  }
})
