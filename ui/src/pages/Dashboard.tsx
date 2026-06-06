import { useEffect, useState, type ReactNode } from 'react'
import { api } from '../api/client'
import { DonutChart } from '../components/DonutChart'
import { ClassBadge } from '../components/ClassBadge'
import { StatusBadge } from '../components/StatusBadge'
import type { RunResult, Stats } from '../types'

const CLASS_COLORS: Record<string, string> = {
  simple: '#7C3AED',
  volume: '#EA580C',
  correlation: '#0891B2',
  first_seen: '#DB2777',
  scheduled: '#0D9488',
}

const APP_COLORS = ['#7C3AED', '#0891B2', '#DB2777', '#F59E0B', '#10B981']

interface Props {
  recentResults: RunResult[]
  onQuickRun: () => void
}

export function Dashboard({ recentResults, onQuickRun }: Props) {
  const [stats, setStats] = useState<Stats | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getStats().then(setStats).finally(() => setLoading(false))
  }, [])

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-gray-500 animate-pulse">Loading…</div>
  }

  const needsSetup = !stats || stats.total_rules === 0 || !stats.synced

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">

      {/* ── Setup banner ── */}
      {needsSetup && (
        <div className="bg-violet-900/20 border border-violet-700 rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-3">
            <span className="text-3xl">🪨</span>
            <div>
              <h2 className="text-base font-semibold text-violet-200">Welcome to FoundStone</h2>
              <p className="text-sm text-violet-300/70 mt-0.5">Complete the steps below to start verifying detections</p>
            </div>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <Step n={1} title="Add an Environment"
              body="Go to the Environments tab and create a named tenant config with your SDL URL, tokens, and S1 API key."
              done={!!stats && stats.total_rules > 0} />
            <Step n={2} title="Sync Detection Library"
              body="Click Sync from Active Environment to pull the rules deployed on your tenant. Only those rules will be shown."
              done={!!stats?.synced} />
            <Step n={3} title="Upload Real Log Templates"
              body="Drop a .jsonl file of real events from your source. FoundStone overlays detection fields onto these to generate synthetic test logs."
              done={!!stats && Object.keys(stats.template_sources ?? {}).length > 0} />
          </div>
          <div className="border-t border-violet-800 pt-4 text-xs text-violet-400 space-y-1">
            <p><span className="font-semibold text-violet-300">How it works:</span> For each detection rule, FoundStone reads the filter logic, computes the minimal set of fields needed to fire it, overlays those onto a real event template, ingests to SDL, and verifies the alert fires.</p>
            <p>All synthetic events are tagged <code className="bg-violet-900/50 px-1 rounded">_foundstone_test: true</code> for easy cleanup.</p>
          </div>
        </div>
      )}

      {/* ── Stats row ── */}
      {stats && (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard label="Deployed Rules" value={stats.total_rules.toLocaleString()} icon="📋"
              sub={stats.synced ? `of ${stats.total_in_library?.toLocaleString() ?? '?'} in library` : 'sync to filter'} />
            <StatCard label="Rule Classes" value={Object.keys(stats.by_class).length.toString()} icon="🏷" />
            <StatCard label="Applications" value={Object.keys(stats.by_app).length.toString()} icon="📦" />
            <StatCard label="Data Sources" value={stats.by_source_top10.length.toString() + '+'} icon="🔌"
              sub={Object.keys(stats.template_sources ?? {}).length + ' have templates'} />
          </div>

          {/* ── Charts row ── */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card title="Rules by Class">
              <DonutChart slices={Object.entries(stats.by_class).map(([k, v]) => ({
                label: k.replace('_', ' '), value: v, color: CLASS_COLORS[k] ?? '#6B7280',
              }))} size={140} thickness={22} />
            </Card>
            <Card title="Rules by App">
              <DonutChart slices={Object.entries(stats.by_app).map(([k, v], i) => ({
                label: k, value: v, color: APP_COLORS[i % APP_COLORS.length],
              }))} size={140} thickness={22} />
            </Card>
          </div>

          {/* ── Top sources + recent results ── */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card title="Top Data Sources">
              <ul className="space-y-2">
                {stats.by_source_top10.map((s) => {
                  const pct = Math.round((s.count / stats.total_rules) * 100)
                  const hasTemplate = !!(stats.template_sources ?? {})[s.source]
                  return (
                    <li key={s.source}>
                      <div className="flex justify-between text-xs mb-0.5">
                        <span className="text-gray-300 font-mono truncate flex items-center gap-1.5">
                          {s.source}
                          {hasTemplate && <span className="text-emerald-500 text-xs">📂</span>}
                        </span>
                        <span className="text-gray-500 ml-2 shrink-0">{s.count}</span>
                      </div>
                      <div className="h-1.5 rounded-full bg-bg-base overflow-hidden">
                        <div className="h-full rounded-full bg-accent" style={{ width: `${pct}%` }} />
                      </div>
                    </li>
                  )
                })}
              </ul>
            </Card>

            <Card title="Recent Run Results">
              {recentResults.length === 0 ? (
                <div className="text-gray-500 text-sm py-4 text-center">
                  No runs yet.{' '}
                  <button onClick={onQuickRun} className="text-accent-light hover:underline">
                    Start a quick run →
                  </button>
                </div>
              ) : (
                <div className="space-y-2">
                  {recentResults.slice(0, 8).map((r, i) => (
                    <div key={i} className="flex items-center justify-between gap-3">
                      <div className="flex items-center gap-2 min-w-0">
                        <ClassBadge cls={r.rule_class} />
                        <span className="text-sm text-gray-300 truncate">{r.rule_name}</span>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        {r.alert_fired !== undefined && r.alert_fired !== null && (
                          <span className={`text-xs ${r.alert_fired ? 'text-emerald-400' : 'text-red-400'}`}>
                            {r.alert_fired ? '✓ fired' : '✗ no alert'}
                          </span>
                        )}
                        <StatusBadge status={r.status} />
                      </div>
                    </div>
                  ))}
                </div>
              )}
              <button onClick={onQuickRun}
                className="mt-4 w-full py-2 rounded-lg border border-accent/40 text-accent-light text-sm font-medium hover:bg-accent/10 transition-colors">
                ▶ Quick Run
              </button>
            </Card>
          </div>
        </>
      )}
    </div>
  )
}

function Step({ n, title, body, done }: { n: number; title: string; body: string; done: boolean }) {
  return (
    <div className={`rounded-lg border p-4 space-y-2 ${done ? 'border-emerald-700 bg-emerald-900/10' : 'border-violet-800 bg-violet-900/10'}`}>
      <div className="flex items-center gap-2">
        <span className={`w-6 h-6 rounded-full text-xs font-bold flex items-center justify-center flex-shrink-0 ${
          done ? 'bg-emerald-600 text-white' : 'bg-violet-700 text-white'
        }`}>{done ? '✓' : n}</span>
        <span className="text-sm font-semibold text-gray-200">{title}</span>
      </div>
      <p className="text-xs text-gray-400 leading-relaxed">{body}</p>
    </div>
  )
}

function StatCard({ label, value, icon, sub }: { label: string; value: string; icon: string; sub?: string }) {
  return (
    <div className="bg-bg-card border border-border rounded-xl p-5">
      <div className="flex items-center justify-between mb-3">
        <span className="text-gray-400 text-sm">{label}</span>
        <span className="text-2xl">{icon}</span>
      </div>
      <p className="text-3xl font-bold text-gray-100">{value}</p>
      {sub && <p className="text-xs text-gray-500 mt-1">{sub}</p>}
    </div>
  )
}

function Card({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="bg-bg-card border border-border rounded-xl p-5">
      <h3 className="text-sm font-semibold text-gray-300 mb-4">{title}</h3>
      {children}
    </div>
  )
}
