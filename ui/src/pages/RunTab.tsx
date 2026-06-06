import { useCallback, useState } from 'react'
import { api } from '../api/client'
import { JobProgress } from '../components/JobProgress'
import { StatusBadge } from '../components/StatusBadge'
import { ClassBadge } from '../components/ClassBadge'
import type { Job, RunResult } from '../types'

interface Props {
  selectedIds: Set<string>
  onRemoveRule: (id: string) => void
  onClearSelection: () => void
  onJobResult: (results: RunResult[]) => void
}

export function RunTab({ selectedIds, onRemoveRule, onClearSelection, onJobResult }: Props) {
  const [dryRun, setDryRun] = useState(true)
  const [confirmPoc, setConfirmPoc] = useState(false)
  const [jobId, setJobId] = useState<string | null>(null)
  const [job, setJob] = useState<Job | null>(null)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleJobUpdate = useCallback(
    (updated: Job) => {
      setJob(updated)
      if (updated.status === 'done' || updated.status === 'error') {
        setRunning(false)
        if (updated.results.length > 0) {
          onJobResult(updated.results)
        }
      }
    },
    [onJobResult],
  )

  const handleRun = async () => {
    if (selectedIds.size === 0) return
    setError(null)
    setJob(null)
    setRunning(true)
    try {
      const res = await api.startRun([...selectedIds], dryRun, confirmPoc)
      setJobId(res.job_id)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      setRunning(false)
    }
  }

  const handleExport = () => {
    if (!job?.results) return
    const blob = new Blob([JSON.stringify(job.results, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `foundstone-results-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const progress = job ? Math.round((job.progress / Math.max(job.total, 1)) * 100) : 0
  const ids = [...selectedIds]

  return (
    <div className="p-5 space-y-5 max-w-5xl mx-auto">
      {/* Selected rules */}
      <section className="bg-bg-card border border-border rounded-xl p-5">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-gray-300">
            Selected Rules{' '}
            <span className="text-accent-light ml-1">({ids.length})</span>
          </h2>
          {ids.length > 0 && (
            <button
              onClick={onClearSelection}
              className="text-xs text-gray-500 hover:text-red-400 transition-colors"
            >
              Clear all
            </button>
          )}
        </div>

        {ids.length === 0 ? (
          <p className="text-sm text-gray-500 py-4 text-center">
            Select rules from the Rules tab to run them here.
          </p>
        ) : (
          <div className="max-h-48 overflow-y-auto space-y-1.5 pr-1">
            {ids.map((id) => (
              <div
                key={id}
                className="flex items-center justify-between gap-3 bg-bg-base rounded-lg px-3 py-2"
              >
                <span className="text-xs font-mono text-gray-400 truncate">{id}</span>
                <button
                  onClick={() => onRemoveRule(id)}
                  className="text-gray-500 hover:text-red-400 transition-colors text-xs shrink-0"
                >
                  ✕
                </button>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Run config */}
      <section className="bg-bg-card border border-border rounded-xl p-5">
        <h2 className="text-sm font-semibold text-gray-300 mb-4">Run Options</h2>
        <div className="flex flex-wrap gap-5">
          <label className="flex items-center gap-3 cursor-pointer">
            <div
              onClick={() => setDryRun(!dryRun)}
              className={`relative w-10 h-5 rounded-full transition-colors ${
                dryRun ? 'bg-blue-600' : 'bg-gray-600'
              }`}
            >
              <span
                className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${
                  dryRun ? 'translate-x-5' : ''
                }`}
              />
            </div>
            <span className="text-sm text-gray-300">
              Dry Run{' '}
              <span className="text-xs text-gray-500">(no ingestion)</span>
            </span>
          </label>

          <label className="flex items-center gap-3 cursor-pointer">
            <div
              onClick={() => setConfirmPoc(!confirmPoc)}
              className={`relative w-10 h-5 rounded-full transition-colors ${
                confirmPoc ? 'bg-amber-600' : 'bg-gray-600'
              }`}
            >
              <span
                className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${
                  confirmPoc ? 'translate-x-5' : ''
                }`}
              />
            </div>
            <span className="text-sm text-gray-300">
              Confirm POC{' '}
              <span className="text-xs text-gray-500">(bypass prod check)</span>
            </span>
          </label>
        </div>
      </section>

      {/* Run button */}
      <button
        onClick={handleRun}
        disabled={running || ids.length === 0}
        className="w-full py-3 rounded-xl bg-accent hover:bg-accent-hover disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold text-sm transition-colors"
      >
        {running ? '⏳ Running…' : `▶ Run ${ids.length} rule${ids.length !== 1 ? 's' : ''}`}
      </button>

      {error && (
        <div className="bg-red-900/30 border border-red-700 text-red-300 text-sm rounded-lg p-3">
          {error}
        </div>
      )}

      {/* Progress */}
      {jobId && running && <JobProgress jobId={jobId} onUpdate={handleJobUpdate} />}

      {job && (
        <section className="bg-bg-card border border-border rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-gray-300">
                Job Results{' '}
                <span
                  className={`ml-2 text-xs font-mono ${
                    job.status === 'done'
                      ? 'text-emerald-400'
                      : job.status === 'error'
                      ? 'text-red-400'
                      : 'text-amber-400'
                  }`}
                >
                  {job.status}
                </span>
              </h2>
              <p className="text-xs text-gray-500">
                {job.progress} / {job.total} completed
              </p>
            </div>
            {job.status === 'done' && job.results.length > 0 && (
              <button
                onClick={handleExport}
                className="text-xs px-3 py-1.5 border border-border rounded-lg text-gray-300 hover:bg-white/5 transition-colors"
              >
                ↓ Export JSON
              </button>
            )}
          </div>

          {/* Progress bar */}
          <div className="h-2 rounded-full bg-bg-base overflow-hidden">
            <div
              className="h-full rounded-full bg-accent transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>

          {/* Results table */}
          {job.results.length > 0 && (
            <div className="rounded-lg border border-border overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-bg-base border-b border-border">
                  <tr>
                    <th className="px-3 py-2 text-left text-gray-400 font-medium">Rule</th>
                    <th className="px-3 py-2 text-left text-gray-400 font-medium w-32">Class</th>
                    <th className="px-3 py-2 text-left text-gray-400 font-medium w-28">Status</th>
                    <th className="px-3 py-2 text-left text-gray-400 font-medium w-24">Alert</th>
                    <th className="px-3 py-2 text-left text-gray-400 font-medium">Modified Fields</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {job.results.map((r, i) => (
                    <ResultRow key={i} result={r} />
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {job.error && (
            <div className="text-sm text-red-400 bg-red-900/20 border border-red-800 rounded-lg p-3">
              {job.error}
            </div>
          )}
        </section>
      )}
    </div>
  )
}

function ResultRow({ result }: { result: RunResult }) {
  const alertCell =
    result.alert_fired === true ? (
      <span className="text-emerald-400 text-sm">✓</span>
    ) : result.alert_fired === false ? (
      <span className="text-red-400 text-sm">✗</span>
    ) : (
      <span className="text-gray-500 text-sm">—</span>
    )

  return (
    <tr className="hover:bg-white/3 transition-colors">
      <td className="px-3 py-2.5">
        <span className="text-gray-200 text-sm">{result.rule_name}</span>
      </td>
      <td className="px-3 py-2.5">
        <ClassBadge cls={result.rule_class} />
      </td>
      <td className="px-3 py-2.5">
        <StatusBadge status={result.status} />
      </td>
      <td className="px-3 py-2.5">{alertCell}</td>
      <td className="px-3 py-2.5">
        {result.modified_fields && result.modified_fields.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {result.modified_fields.map((f) => (
              <span key={f} className="text-xs font-mono bg-bg-base border border-border px-1.5 py-0.5 rounded text-gray-400">
                {f}
              </span>
            ))}
          </div>
        ) : result.error ? (
          <span className="text-xs text-red-400 truncate max-w-xs block" title={result.error}>
            {result.error}
          </span>
        ) : (
          <span className="text-gray-600 text-xs">—</span>
        )}
      </td>
    </tr>
  )
}
