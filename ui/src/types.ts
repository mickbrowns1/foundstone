export type RuleClass = 'simple' | 'volume' | 'correlation' | 'first_seen' | 'scheduled'
export type AppType = 'STAR' | 'Anomaly' | 'Identity'
export type RunStatus = 'ingested' | 'dry_run' | 'no_template' | 'error'

export interface RuleSummary {
  id: string
  name: string
  app: string
  file: string
  source: string | null
  rule_class: RuleClass
  copies: number
}

export interface PairItem {
  key: string
  op: string
  value: string
}

export interface QueryDetail {
  query: string
  pair_list: PairItem[]
  overlay: Record<string, unknown>
  data_source: string | null
}

export interface RuleDetail extends RuleSummary {
  description: string
  queries: QueryDetail[]
}

export interface RulesResponse {
  total: number
  offset: number
  limit: number
  items: RuleSummary[]
}

export interface Stats {
  total_rules: number
  total_in_library?: number
  synced: boolean
  by_class: Record<string, number>
  by_app: Record<string, number>
  by_source_top10: SourceItem[]
  template_sources: Record<string, number>
}

export interface RunResult {
  rule_id: string
  rule_name: string
  rule_class: RuleClass
  status: RunStatus
  alert_fired?: boolean | null
  modified_fields?: string[]
  error?: string
}

export interface Job {
  status: 'pending' | 'running' | 'done' | 'error'
  progress: number
  total: number
  results: RunResult[]
  error?: string
}

export interface ConfigState {
  configured: boolean
  base_url_set: boolean
  base_url: string
  account_id: string
  verify_delay: number
  dry_run: boolean
  read_token_set: boolean
  write_token_set: boolean
  s1_api_token_set: boolean
}

export interface Environment {
  id: number
  name: string
  sdl_base_url: string
  sdl_read_token: boolean   // masked — true = set
  sdl_write_token: boolean  // masked — true = set
  sdl_account_id: string
  s1_api_token: boolean     // masked — true = set
  verify_delay: number
  dry_run: boolean
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface LibraryStatus {
  synced: boolean
  deployed_count: number
  matched_in_extracted: number
}

export interface TemplateStore {
  sources: Record<string, number>
  total_sources: number
}

export interface TemplateUploadResult {
  filename: string
  total_events: number
  indexed_by_source: Record<string, number>
  skipped_no_source: number
}

export interface SourceItem {
  source: string
  count: number
  has_templates: boolean
  template_count: number
}
