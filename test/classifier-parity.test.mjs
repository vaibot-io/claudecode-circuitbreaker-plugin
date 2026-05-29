import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

// Guards the vendored copy of the classifier module. The Claude Code hooks run
// as standalone node scripts and can't import @vaibot/shared at runtime, so
// scripts/lib/classifier.mjs is a verbatim copy of
// packages/shared/src/classifier.mjs. This test fails if the copy drifts.

const __dirname = dirname(fileURLToPath(import.meta.url))
const VENDORED = join(__dirname, '..', 'scripts', 'lib', 'classifier.mjs')
const CANONICAL = join(__dirname, '..', '..', 'shared', 'src', 'classifier.mjs')

test('vendored classifier.mjs is byte-identical to @vaibot/shared source', () => {
  assert.equal(
    readFileSync(VENDORED, 'utf-8'),
    readFileSync(CANONICAL, 'utf-8'),
    'scripts/lib/classifier.mjs has drifted — re-copy from packages/shared/src/classifier.mjs',
  )
})

test('vendored classifier.mjs exposes the expected API and classifies', async () => {
  const m = await import(VENDORED)
  for (const fn of ['classify', 'classifyBash', 'verdictForRisk', 'receiptTierFor']) {
    assert.equal(typeof m[fn], 'function', `missing export: ${fn}`)
  }
  for (const c of ['RISK', 'CATEGORY', 'BOUNDARY', 'VERDICT', 'RECEIPT_TIER']) {
    assert.equal(typeof m[c], 'object', `missing const: ${c}`)
  }
  assert.equal(m.classify({ tool: 'Bash', input: { command: 'rm -rf /' } }).verdictHint, 'deny')
  assert.equal(m.classify({ tool: 'Edit', input: { file_path: 'a.ts' } }).verdictHint, 'allow')
  assert.equal(m.classify({ tool: 'mcp__vaibot__status' }).verdictHint, 'allow')
})
