import type {
  ConfigState,
  Environment,
  Job,
  LibraryStatus,
  RuleDetail,
  RulesResponse,
  SourceItem,
  Stats,
  TemplateStore,
  TemplateUploadResult,
} from '../types'

const BASE = '/api'

async function get<T>(path: string, params?: Record<string, string | number | boolean | undefined>): Promise<T> {
  const url = new URL(BASE + path, window.location.origin)
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') {
        url.searchParams.set(k, String(v))
      }
    }
  }
  const res = await fetch(url.toString())
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`HTTP ${res.status}: ${text}`)
  }
  return res.json() as Promise<T>
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`HTTP ${res.status}: ${text}`)
  }
  return res.json() as Promise<T>
}

async function del<T>(path: string): Promise<T> {
  const res = await fetch(BASE + path, { method: 'DELETE' })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`HTTP ${res.status}: ${text}`)
  }
  return res.json() as Promise<T>
}

export interface ListRulesParams {
  source?: string
  app?: string
  cls?: string
  q?: string
  limit?: number
  offset?: number
  deployed_only?: boolean
}

export const api = {
  // Rules
  listRules: (params: ListRulesParams) =>
    get<RulesResponse>('/rules', params as Record<string, string | number | boolean | undefined>),
  getRule: (id: string) => get<RuleDetail>(`/rules/${id}`),

  // Sources
  listSources: (deployed_only = true) =>
    get<SourceItem[]>('/sources', { deployed_only }),

  // Stats
  getStats: (deployed_only = true) =>
    get<Stats>('/stats', { deployed_only }),

  // Run / jobs
  startRun: (rule_ids: string[], dry_run: boolean, confirm_poc: boolean) =>
    post<{ job_id: string }>('/run', { rule_ids, dry_run, confirm_poc }),
  getJob: (job_id: string) => get<Job>(`/jobs/${job_id}`),

  // Environments
  listEnvironments: () => get<Environment[]>('/environments'),
  getActiveEnvironment: () => get<Environment & { active: boolean }>('/environments/active'),
  createEnvironment: (data: {
    name: string; sdl_base_url: string; sdl_read_token: string
    sdl_write_token: string; sdl_account_id: string; s1_api_token: string
    verify_delay: number; dry_run: boolean; make_active: boolean
  }) => post<Environment>('/environments', data),
  updateEnvironment: (id: number, data: Partial<{
    name: string; sdl_base_url: string; sdl_read_token: string
    sdl_write_token: string; sdl_account_id: string; s1_api_token: string
    verify_delay: number; dry_run: boolean
  }>) => fetch(`/api/environments/${id}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data)
  }).then(r => r.json() as Promise<Environment>),
  deleteEnvironment: (id: number) => del<{ deleted: boolean }>(`/environments/${id}`),
  activateEnvironment: (id: number) => post<Environment>(`/environments/${id}/activate`, {}),

  // Config (legacy shim)
  getConfig: () => get<ConfigState>('/config'),
  saveConfig: (data: {
    sdl_base_url: string
    sdl_read_token: string
    sdl_write_token: string
    sdl_account_id: string
    s1_api_token: string
    verify_delay: number
    dry_run: boolean
  }) => post<{ saved: boolean }>('/config', data),

  // Library sync
  syncLibrary: () => post<{ deployed_count: number; matched_in_extracted: number; total_in_extracted: number }>('/library/sync', {}),
  clearLibrarySync: () => del<{ cleared: boolean }>('/library/sync'),
  getLibraryStatus: () => get<LibraryStatus>('/library/status'),

  // Template upload
  uploadTemplates: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return fetch(BASE + '/templates/upload', { method: 'POST', body: form })
      .then(async (res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`)
        return res.json() as Promise<TemplateUploadResult>
      })
  },
  getTemplates: () => get<TemplateStore>('/templates'),
  clearTemplates: () => del<{ cleared: boolean }>('/templates'),
  clearTemplatesForSource: (source: string) =>
    del<{ source: string; removed: number }>(`/templates/${encodeURIComponent(source)}`),
}
