// Type declarations for classifier.mjs — stateless risk classifier for tool
// calls. Hand-written to pair with the plain-ESM source.

export type Risk = 'safe' | 'low' | 'medium' | 'high' | 'dangerous'
export type Category = 'read' | 'write' | 'exec' | 'network' | 'unknown'
export type Boundary = 'none' | 'ingress' | 'egress' | 'both'
export type Verdict = 'allow' | 'ask' | 'deny'
export type ReceiptTier = 'none' | 'ledger' | 'receipt'

export const RISK: {
  readonly SAFE: 'safe'
  readonly LOW: 'low'
  readonly MEDIUM: 'medium'
  readonly HIGH: 'high'
  readonly DANGEROUS: 'dangerous'
}
export const CATEGORY: {
  readonly READ: 'read'
  readonly WRITE: 'write'
  readonly EXEC: 'exec'
  readonly NETWORK: 'network'
  readonly UNKNOWN: 'unknown'
}
export const BOUNDARY: {
  readonly NONE: 'none'
  readonly INGRESS: 'ingress'
  readonly EGRESS: 'egress'
  readonly BOTH: 'both'
}
export const VERDICT: { readonly ALLOW: 'allow'; readonly ASK: 'ask'; readonly DENY: 'deny' }
export const RECEIPT_TIER: { readonly NONE: 'none'; readonly LEDGER: 'ledger'; readonly RECEIPT: 'receipt' }

export interface ClassifierTables {
  readTools: string[]
  writeTools: string[]
  networkTools: string[]
  searchTools: string[]
  execTools: string[]
  safeCmds: string[]
  networkCmds: string[]
  writeCmds: string[]
  readGitSub: string[]
}

export interface ToolCall {
  tool: string
  input?: unknown
}

export interface BashClassification {
  category: Category
  risk: Risk
  boundary: Boundary
  reversible: boolean
  reasons: string[]
}

export interface ClassifyResult {
  tool: string
  category: Category
  risk: Risk
  boundary: Boundary
  reversible: boolean
  verdictHint: Verdict
  receiptTier: ReceiptTier
  reasons: string[]
}

export function classifyBash(command: string, tables?: ClassifierTables): BashClassification
export function verdictForRisk(risk: Risk): Verdict
export function receiptTierFor(risk: Risk, boundary: Boundary): ReceiptTier
export function classify(call: ToolCall, cfg?: { tables?: ClassifierTables }): ClassifyResult
