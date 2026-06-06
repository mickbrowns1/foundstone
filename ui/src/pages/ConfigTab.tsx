import { useEffect, useRef, useState, type ReactNode } from 'react'
import { api } from '../api/client'
import type { Environment, LibraryStatus, TemplateStore, TemplateUploadResult } from '../types'

// ── Blank form state ────────────────────────────────────────────────────────
const BLANK = {
  name: '', sdl_base_url: '', sdl_read_token: '', sdl_write_token: '',
  sdl_account_id: '', s1_api_token: '', verify_delay: 30, dry_run: true, make_active: false,
}

export function ConfigTab() {
  const [environments, setEnvironments] = useState<Environment[]>([])
  const [libraryStatus, setLibraryStatus] = useState<LibraryStatus | null>(null)
  const [templates, setTemplates] = useState<TemplateStore | null>(null)
  const [loading, setLoading] = useState(true)

  // Form
  const [showForm, setShowForm] = useState(false)
  const [editingId, setEditingId] = useState<number | null>(null)
  const [form, setForm] = useState({ ...BLANK })
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  // Token visibility
  const [showTokens, setShowTokens] = useState<Record<string, boolean>>({})

  // Library sync
  const [syncing, setSyncing] = useState(false)
  const [syncResult, setSyncResult] = useState<string | null>(null)
  const [syncError, setSyncError] = useState<string | null>(null)

  // Template upload
  const [uploadResult, setUploadResult] = useState<TemplateUploadResult | null>(null)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [uploading, setUploading] = useState(false)
  const [dragOver, setDragOver] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const refresh = async () => {
    const [envs, lib, tmpl] = await Promise.all([
      api.listEnvironments(),
      api.getLibraryStatus(),
      api.getTemplates(),
    ])
    setEnvironments(envs)
    setLibraryStatus(lib)
    setTemplates(tmpl)
  }

  useEffect(() => { refresh().finally(() => setLoading(false)) }, [])

  const handleEdit = (env: Environment) => {
    setEditingId(env.id)
    setForm({
      name: env.name,
      sdl_base_url: env.sdl_base_url,
      sdl_read_token: '',     // never pre-fill tokens
      sdl_write_token: '',
      sdl_account_id: env.sdl_account_id,
      s1_api_token: '',
      verify_delay: env.verify_delay,
      dry_run: env.dry_run,
      make_active: false,
    })
    setShowForm(true)
    setFormError(null)
  }

  const handleNew = () => {
    setEditingId(null)
    setForm({ ...BLANK })
    setShowForm(true)
    setFormError(null)
  }

  const handleCancel = () => { setShowForm(false); setEditingId(null); setFormError(null) }

  const handleSave = async () => {
    if (!form.name.trim()) { setFormError('Name is required'); return }
    setSaving(true); setFormError(null)
    try {
      if (editingId !== null) {
        // Only send token fields if they were filled in
        const updates: Record<string, unknown> = {
          name: form.name, sdl_base_url: form.sdl_base_url,
          sdl_account_id: form.sdl_account_id,
          verify_delay: form.verify_delay, dry_run: form.dry_run,
        }
        if (form.sdl_read_token)  updates.sdl_read_token  = form.sdl_read_token
        if (form.sdl_write_token) updates.sdl_write_token = form.sdl_write_token
        if (form.s1_api_token)    updates.s1_api_token    = form.s1_api_token
        await api.updateEnvironment(editingId, updates)
      } else {
        await api.createEnvironment({ ...form, sdl_base_url: form.sdl_base_url.replace(/\/+$/, '') })
      }
      setShowForm(false)
      setEditingId(null)
      await refresh()
    } catch (e) {
      setFormError(e instanceof Error ? e.message : String(e))
    } finally {
      setSaving(false)
    }
  }

  const handleActivate = async (id: number) => {
    await api.activateEnvironment(id)
    await refresh()
  }

  const handleDelete = async (id: number) => {
    if (!confirm('Delete this environment?')) return
    await api.deleteEnvironment(id)
    await refresh()
  }

  const handleSync = async () => {
    setSyncing(true); setSyncError(null); setSyncResult(null)
    try {
      const r = await api.syncLibrary()
      setSyncResult(`Synced ${r.deployed_count.toLocaleString()} deployed rules — ${r.matched_in_extracted.toLocaleString()} matched in library`)
      await refresh()
    } catch (e) {
      setSyncError(e instanceof Error ? e.message : String(e))
    } finally { setSyncing(false) }
  }

  const handleClearSync = async () => { await api.clearLibrarySync(); await refresh(); setSyncResult(null) }

  const handleUploadFile = async (file: File) => {
    setUploading(true); setUploadError(null); setUploadResult(null)
    try {
      const r = await api.uploadTemplates(file)
      setUploadResult(r)
      await refresh()
    } catch (e) {
      setUploadError(e instanceof Error ? e.message : String(e))
    } finally { setUploading(false) }
  }

  const toggleToken = (key: string) =>
    setShowTokens(prev => ({ ...prev, [key]: !prev[key] }))

  if (loading) return <div className="flex items-center justify-center h-64 text-gray-500 animate-pulse">Loading…</div>

  const activeEnv = environments.find(e => e.is_active)

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-6">

      {/* ── Environments ── */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold text-gray-200">Environments</h2>
          <button onClick={handleNew}
            className="text-sm px-4 py-2 bg-accent hover:bg-accent-hover text-white rounded-lg transition-colors font-medium">
            + New Environment
          </button>
        </div>

        {environments.length === 0 && !showForm && (
          <div className="bg-bg-card border border-border rounded-xl p-8 text-center text-gray-500 text-sm">
            No environments yet — add one to get started
          </div>
        )}

        {environments.map(env => (
          <div key={env.id} className={`bg-bg-card border rounded-xl p-4 transition-colors ${
            env.is_active ? 'border-violet-600' : 'border-border'
          }`}>
            <div className="flex items-center gap-3">
              {/* Active indicator */}
              <div className={`w-2 h-2 rounded-full flex-shrink-0 ${env.is_active ? 'bg-violet-500' : 'bg-gray-600'}`} />

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-gray-100 text-sm">{env.name}</span>
                  {env.is_active && (
                    <span className="text-xs bg-violet-900/50 text-violet-300 border border-violet-700 px-2 py-0.5 rounded-full">Active</span>
                  )}
                  {env.dry_run && (
                    <span className="text-xs bg-blue-900/40 text-blue-400 border border-blue-800 px-2 py-0.5 rounded-full">Dry Run</span>
                  )}
                </div>
                <p className="text-xs text-gray-500 mt-0.5 truncate">{env.sdl_base_url || '(no URL set)'}</p>
              </div>

              {/* Token status pills */}
              <div className="flex gap-1.5 flex-shrink-0">
                <Pill set={!!env.sdl_read_token} label="Read" />
                <Pill set={!!env.sdl_write_token} label="Write" />
                <Pill set={!!env.s1_api_token} label="API" />
              </div>

              {/* Actions */}
              <div className="flex gap-2 flex-shrink-0">
                {!env.is_active && (
                  <button onClick={() => handleActivate(env.id)}
                    className="text-xs px-3 py-1.5 bg-violet-900/40 hover:bg-violet-800/60 text-violet-300 border border-violet-700 rounded-lg transition-colors">
                    Activate
                  </button>
                )}
                <button onClick={() => handleEdit(env)}
                  className="text-xs px-3 py-1.5 bg-bg-surface hover:bg-border text-gray-300 border border-border rounded-lg transition-colors">
                  Edit
                </button>
                <button onClick={() => handleDelete(env.id)}
                  className="text-xs px-3 py-1.5 hover:bg-red-900/30 text-gray-500 hover:text-red-400 border border-transparent hover:border-red-800 rounded-lg transition-colors">
                  ✕
                </button>
              </div>
            </div>
          </div>
        ))}

        {/* Inline form */}
        {showForm && (
          <div className="bg-bg-card border border-accent/50 rounded-xl p-5 space-y-4">
            <h3 className="text-sm font-semibold text-gray-200">
              {editingId ? 'Edit Environment' : 'New Environment'}
            </h3>

            <FormField label="Name">
              <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                placeholder="e.g. POC - Acme Corp" className="form-input" autoFocus />
            </FormField>

            <FormField label="Console Base URL">
              <input value={form.sdl_base_url} onChange={e => setForm(f => ({ ...f, sdl_base_url: e.target.value }))}
                placeholder="https://your-tenant.sentinelone.net" className="form-input" type="url" />
            </FormField>

            <FormField label="SDL Account ID">
              <input value={form.sdl_account_id} onChange={e => setForm(f => ({ ...f, sdl_account_id: e.target.value }))}
                placeholder="Account ID" className="form-input" />
            </FormField>

            <div className="grid grid-cols-3 gap-3">
              <FormField label={`SDL Read Token${editingId ? ' (leave blank to keep)' : ''}`}>
                <TokenInput value={form.sdl_read_token}
                  onChange={v => setForm(f => ({ ...f, sdl_read_token: v }))}
                  show={!!showTokens['read']} onToggle={() => toggleToken('read')}
                  placeholder={editingId ? '••••••••' : 'Read token'} />
              </FormField>
              <FormField label={`SDL Write Token${editingId ? ' (leave blank to keep)' : ''}`}>
                <TokenInput value={form.sdl_write_token}
                  onChange={v => setForm(f => ({ ...f, sdl_write_token: v }))}
                  show={!!showTokens['write']} onToggle={() => toggleToken('write')}
                  placeholder={editingId ? '••••••••' : 'Write token'} />
              </FormField>
              <FormField label={`S1 API Token${editingId ? ' (leave blank to keep)' : ''}`}>
                <TokenInput value={form.s1_api_token}
                  onChange={v => setForm(f => ({ ...f, s1_api_token: v }))}
                  show={!!showTokens['api']} onToggle={() => toggleToken('api')}
                  placeholder={editingId ? '••••••••' : 'API token'} />
              </FormField>
            </div>

            <div className="flex items-center gap-6">
              <FormField label="Verify Delay (s)">
                <input type="number" value={form.verify_delay} min={5} max={300}
                  onChange={e => setForm(f => ({ ...f, verify_delay: Number(e.target.value) }))}
                  className="form-input w-24" />
              </FormField>
              <label className="flex items-center gap-2 cursor-pointer mt-5" onClick={() => setForm(f => ({ ...f, dry_run: !f.dry_run }))}>
                <Toggle on={form.dry_run} color="bg-blue-600" />
                <span className="text-sm text-gray-300">Dry Run</span>
              </label>
              {!editingId && (
                <label className="flex items-center gap-2 cursor-pointer mt-5" onClick={() => setForm(f => ({ ...f, make_active: !f.make_active }))}>
                  <Toggle on={form.make_active} color="bg-violet-600" />
                  <span className="text-sm text-gray-300">Set as active</span>
                </label>
              )}
            </div>

            {formError && <ErrorBox>{formError}</ErrorBox>}

            <div className="flex gap-3 pt-1">
              <button onClick={handleSave} disabled={saving}
                className="px-5 py-2 bg-accent hover:bg-accent-hover disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors">
                {saving ? 'Saving…' : editingId ? 'Update' : 'Create'}
              </button>
              <button onClick={handleCancel}
                className="px-5 py-2 border border-border text-gray-400 hover:text-gray-200 text-sm rounded-lg transition-colors">
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ── Detection Library Sync ── */}
      <div className="bg-bg-card border border-border rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-gray-300">Detection Library Sync</h2>
            <p className="text-xs text-gray-500 mt-0.5">
              Pulls deployed rules from <code className="text-violet-400">/detection-library/platform-rules</code> on the active environment. Only matched rules show in the Rules tab.
            </p>
          </div>
          {libraryStatus?.synced && (
            <span className="text-xs bg-emerald-900/40 text-emerald-400 border border-emerald-700 px-2 py-1 rounded-full">Synced</span>
          )}
        </div>

        {libraryStatus?.synced && (
          <div className="bg-bg-surface rounded-lg p-3 text-xs text-gray-300 space-y-1">
            <div className="flex justify-between"><span className="text-gray-500">Deployed on tenant</span><span className="font-mono">{libraryStatus.deployed_count.toLocaleString()}</span></div>
            <div className="flex justify-between"><span className="text-gray-500">Matched in library</span><span className="font-mono text-violet-400">{libraryStatus.matched_in_extracted.toLocaleString()}</span></div>
          </div>
        )}

        {syncResult && <SuccessBox>{syncResult}</SuccessBox>}
        {syncError && <ErrorBox>{syncError}</ErrorBox>}

        <div className="flex gap-3">
          <button onClick={handleSync} disabled={syncing || !activeEnv?.s1_api_token}
            className="flex-1 py-2.5 rounded-lg bg-violet-700 hover:bg-violet-600 disabled:opacity-40 text-white text-sm font-medium transition-colors">
            {syncing ? 'Syncing…' : '↓ Sync from Active Environment'}
          </button>
          {libraryStatus?.synced && (
            <button onClick={handleClearSync}
              className="px-4 py-2.5 rounded-lg border border-border hover:border-red-700 text-gray-400 hover:text-red-400 text-sm transition-colors">
              Clear
            </button>
          )}
        </div>
        {!activeEnv?.s1_api_token && (
          <p className="text-xs text-amber-500">Active environment needs an S1 API Token to sync.</p>
        )}
      </div>

      {/* ── Template Upload ── */}
      <div className="bg-bg-card border border-border rounded-xl p-5 space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-gray-300">Real Log Templates</h2>
          <p className="text-xs text-gray-500 mt-0.5">
            Upload a <code className="text-violet-400">.jsonl</code> or <code className="text-violet-400">.json</code> file of real log events. Used as base templates instead of pulling from SDL — keeps your data private.
          </p>
        </div>

        <div
          onDragOver={e => { e.preventDefault(); setDragOver(true) }}
          onDragLeave={() => setDragOver(false)}
          onDrop={e => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) handleUploadFile(f) }}
          onClick={() => fileInputRef.current?.click()}
          className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-colors ${
            dragOver ? 'border-violet-500 bg-violet-900/20' : 'border-border hover:border-violet-700 hover:bg-violet-900/10'
          }`}
        >
          <input ref={fileInputRef} type="file" accept=".json,.jsonl" className="hidden"
            onChange={e => { const f = e.target.files?.[0]; if (f) handleUploadFile(f) }} />
          <p className="text-2xl mb-2">{uploading ? '⏳' : '📂'}</p>
          <p className="text-sm text-gray-300 font-medium">{uploading ? 'Uploading…' : 'Drop log file here or click to browse'}</p>
          <p className="text-xs text-gray-500 mt-1">JSONL · JSON array · {"{"}"events": [...]{"}"}</p>
        </div>

        {uploadResult && (
          <div className="bg-bg-surface rounded-lg p-3 text-xs space-y-2">
            <p className="text-emerald-400 font-medium">✓ {uploadResult.filename} — {uploadResult.total_events.toLocaleString()} events loaded</p>
            {Object.entries(uploadResult.indexed_by_source).map(([src, count]) => (
              <div key={src} className="flex justify-between text-gray-300">
                <span className="text-violet-400">{src}</span>
                <span className="font-mono">{count.toLocaleString()} events</span>
              </div>
            ))}
            {uploadResult.skipped_no_source > 0 && (
              <p className="text-amber-500">{uploadResult.skipped_no_source} events skipped (no dataSource.name)</p>
            )}
          </div>
        )}
        {uploadError && <ErrorBox>{uploadError}</ErrorBox>}

        {templates && templates.total_sources > 0 && (
          <div className="bg-bg-surface rounded-lg p-3 text-xs space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-gray-400 font-medium">Loaded template sources</span>
              <button onClick={async () => { await api.clearTemplates(); await refresh() }}
                className="text-red-400 hover:text-red-300 transition-colors">Clear all</button>
            </div>
            {Object.entries(templates.sources).map(([src, count]) => (
              <div key={src} className="flex justify-between text-gray-300">
                <span className="text-violet-400">{src}</span>
                <span className="font-mono">{count.toLocaleString()} events</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Shared small components ─────────────────────────────────────────────────

function Pill({ set, label }: { set: boolean; label: string }) {
  return (
    <span className={`text-xs px-1.5 py-0.5 rounded border ${
      set ? 'bg-emerald-900/30 text-emerald-400 border-emerald-800' : 'bg-gray-800 text-gray-600 border-gray-700'
    }`}>{label}</span>
  )
}

interface FormFieldProps { label: string; children: ReactNode }
function FormField({ label, children }: FormFieldProps) {
  return (
    <div className="space-y-1.5">
      <label className="text-xs text-gray-400 font-medium">{label}</label>
      {children}
    </div>
  )
}

function TokenInput({ value, onChange, show, onToggle, placeholder }: {
  value: string; onChange: (v: string) => void; show: boolean; onToggle: () => void; placeholder: string
}) {
  return (
    <div className="relative">
      <input type={show ? 'text' : 'password'} value={value}
        onChange={e => onChange(e.target.value)} placeholder={placeholder} className="form-input pr-8" />
      <button type="button" onClick={onToggle}
        className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 text-xs">
        {show ? '🙈' : '👁'}
      </button>
    </div>
  )
}

function Toggle({ on, color }: { on: boolean; color: string }) {
  return (
    <div className={`relative w-9 h-5 rounded-full transition-colors flex-shrink-0 ${on ? color : 'bg-gray-600'}`}>
      <span className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${on ? 'translate-x-4' : ''}`} />
    </div>
  )
}

function ErrorBox({ children }: { children: ReactNode }) {
  return <div className="bg-red-900/30 border border-red-700 text-red-300 text-sm rounded-lg p-3">{children}</div>
}

function SuccessBox({ children }: { children: ReactNode }) {
  return <div className="bg-emerald-900/30 border border-emerald-700 text-emerald-300 text-sm rounded-lg p-3">{children}</div>
}
