export type RangeKey = "1h" | "24h" | "7d"

export type Bucket = {
  m: number
  req: number
  guarded?: number
  new_turns?: number
  cache_hits?: number
  would_block?: number
  enforced?: number
  status_5xx?: number
  cls_errors?: number
  lat?: number[]
  decisions?: Record<string, number>
  reasons?: Record<string, number>
  labels?: Record<string, number>
  categories?: Record<string, number>
  protocols?: Record<string, number>
}

export type KV = { key: string; count: number }

export type Stats = {
  from: string
  to: string
  step_seconds: number
  totals: Bucket
  series: Bucket[]
  peak_new_turns_per_minute: number
  latency_p50_ms: number
  latency_p95_ms: number
  latency_p99_ms: number
  latency_bounds_ms: number[]
  top_reasons: KV[]
  categories: KV[]
}

export type Health = {
  last_ok: string
  last_failure: string
  last_failure_status: string
  in_flight: number
  waiting: number
  spool_bytes: number
  spool_files: number
}

export type Summary = {
  mode: "shadow" | "enforce" | "disabled"
  policy_version: string
  model: string
  started_at: string
  health: Health | null
  audit_failures: number
  stats: Stats
}

export type AuditEvent = {
  timestamp: string
  trace_id: string
  phase: string
  route_class: string
  protocol?: string
  method: string
  path_template: string
  source_ip_hmac?: string
  credential_hmac?: string
  client?: string
  model?: string
  body_bytes: number
  decision: string
  reason_code?: string
  coverage?: string
  coverage_reason?: string
  inspected_chars?: number
  classifier?: string
  classifier_status?: string
  classifier_ms?: number
  label?: string
  categories?: string[]
  cache_hit?: boolean
  aux_model?: string
  aux_status?: string
  aux_ms?: number
  aux?: Record<string, number>
  policy_version?: string
  would_block?: boolean
  enforced?: boolean
  http_status: number
  latency_ms: number
  client_aborted?: boolean
}

export type Policy = {
  version: string
  labels: Record<string, string>
  unsafe_categories: Record<string, string>
  unsafe_default: string
  t0_only_protocols: string[] | null
  coverage_exceptions: string[] | null
  enforce: { review: string; no_inspectable_input: string; unparseable: string }
}

export type ConsoleConfig = {
  mode: Summary["mode"]
  model: string
  policy: Policy | null
  settings: Record<string, number | string>
  block_reply: { available: boolean; enabled: boolean; count: number }
  me: { actor: string; roles: string[] }
  samples: { enabled: boolean }
  /** Admin-set names for key fingerprints; empty for the shared metadata token. */
  aliases: Record<string, { name: string; by: string; at: string }>
}

export type Dim = "credential" | "client" | "model"

export type DimRow = {
  key: string
  alias?: string
  requests: number
  decisions: Record<string, number>
  would_block: number
  enforced: number
  cls_errors: number
  categories: KV[] | null
  last_seen: number
}

/** One sampled request: metadata only. */
export type Sample = {
  id: number
  trace_id: string
  content_id?: number
  content_status:
    "stored" | "excluded" | "oversize" | "none" | "deleted" | "expired"
  ts: number
  phase: string
  protocol: string
  path_template: string
  coverage: string
  coverage_reason?: string
  inspected_chars: number
  truncated: boolean
  base: boolean
  enriched: boolean
  sampling: string
  decision: string
  reason_code?: string
  label?: string
  categories: string[] | null
  classifier?: string
  classifier_status?: string
  classifier_ms: number
  cache_hit: boolean
  policy_version: string
  enforced: boolean
  would_block: boolean
  http_status: number
  client_aborted: boolean
  latency_ms: number
  expires_at: number
  seen: number
  cache_hits: number
  credential_hmac?: string
  client?: string
  model?: string
  review_status: string
  expected_action?: string
}

export type SampleReview = {
  id: number
  actor: string
  created_at: number
  policy_version: string
  status: string
  expected_action?: string
  category?: string
  reason?: string
  supersedes?: number
}

export type SampleDetail = Sample & {
  text?: string
  text_bytes?: number
  exclude_reason?: string
  redactions?: Record<string, number>
  reviews: SampleReview[]
}

export type SampleStatus = {
  enabled: boolean
  last_error?: string
  day?: string
  counts?: Record<string, number>
  queue_items?: number
  queue_max_items?: number
  db_bytes?: number
  max_db_bytes?: number
  free_bytes?: number
  min_free_bytes?: number
  base_probability?: number
  base_daily_cap?: number
  enriched_daily_cap?: number
  max_text_bytes?: number
  content_retention_hours?: number
  review_retention_hours?: number
}

export type ReviewInput = {
  status: string
  expected_action: string
  category: string
  reason: string
  supersedes: number
}
