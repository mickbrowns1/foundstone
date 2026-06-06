import { useEffect, useRef, useState, useCallback } from 'react'
import { api } from '../api/client'
import { ClassBadge } from '../components/ClassBadge'
import { RuleDrawer } from '../components/RuleDrawer'
import type { RuleSummary, SourceItem } from '../types'

const CLASS_OPTIONS = ['simple', 'volume', 'correlation', 'first_seen', 'scheduled']
const APP_OPTIONS = ['STAR', 'Anomaly Detection', 'Identity']

interface Props {
  selected: Set<string>
  onSelectionChange: (selected: Set<string>) => void
  onRunRule: (id: string) => void
}

// ── grouped view types ──────────────────────────────────────────────────────
interface SourceGroup {
  source: string
  rules: RuleSummary[]
  hasTemplates: boolean
  templateCount: number
}

export function Rules({ selected, onSelectionChange, onRunRule }: Props) {
  const [allRules, setAllRules] = useState<RuleSummary[]>([])
  const [sources, setSources] = useState<SourceItem[]>([])
  const [loading, setLoading] = useState(false)

  const [q, setQ] = useState('')
  const [appFilter, setAppFilter] = useState('')
  const [classFilter, setClassFilter] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')

  // Which source groups are expanded (null = all expanded by default)
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())

  const [drawerRule, setDrawerRule] = useState<RuleSummary | null>(null)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Load sources (for filter dropdown + template info)
  useEffect(() => {
    api.listSources().then(setSources)
  }, [])

  // Fetch all matching rules (no pagination — grouped view handles it client-side)
  const fetchRules = useCallback(() => {
    setLoading(true)
    api
      .listRules({ q, app: appFilter, cls: classFilter, source: sourceFilter, limit: 5000, offset: 0 })
      .then((res) => setAllRules(res.items))
      .finally(() => setLoading(false))
  }, [q, appFilter, classFilter, sourceFilter])

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(fetchRules, 300)
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current) }
  }, [fetchRules])

  // Build source → rules groups
  const sourceMap = new Map<string, SourceItem>()
  sources.forEach(s => sourceMap.set(s.source, s))

  const grouped: SourceGroup[] = []
  const groupMap = new Map<string, RuleSummary[]>()
  allRules.forEach(r => {
    const src = r.source ?? '(no source)'
    if (!groupMap.has(src)) groupMap.set(src, [])
    groupMap.get(src)!.push(r)
  })
  groupMap.forEach((rules, source) => {
    const si = sourceMap.get(source)
    grouped.push({
      source,
      rules,
      hasTemplates: si?.has_templates ?? false,
      templateCount: si?.template_count ?? 0,
    })
  })
  grouped.sort((a, b) => b.rules.length - a.rules.length)

  const toggleCollapse = (source: string) => {
    setCollapsed(prev => {
      const next = new Set(prev)
      if (next.has(source)) next.delete(source)
      else next.add(source)
      return next
    })
  }

  const collapseAll = () => setCollapsed(new Set(grouped.map(g => g.source)))
  const expandAll = () => setCollapsed(new Set())

  const handleSelect = (id: string, checked: boolean) => {
    const next = new Set(selected)
    if (checked) next.add(id); else next.delete(id)
    onSelectionChange(next)
  }

  const handleSelectGroup = (group: SourceGroup, checked: boolean) => {
    const next = new Set(selected)
    group.rules.forEach(r => checked ? next.add(r.id) : next.delete(r.id))
    onSelectionChange(next)
  }

  const handleRunRule = (id: string) => {
    setDrawerRule(null)
    onRunRule(id)
  }

  const clearFilter = (which: string) => {
    if (which === 'q') setQ('')
    else if (which === 'app') setAppFilter('')
    else if (which === 'class') setClassFilter('')
    else if (which === 'source') setSourceFilter('')
  }

  const activeFilters = [
    q && { key: 'q', label: `"${q}"` },
    appFilter && { key: 'app', label: `App: ${appFilter}` },
    classFilter && { key: 'class', label: `Class: ${classFilter}` },
    sourceFilter && { key: 'source', label: `Source: ${sourceFilter}` },
  ].filter(Boolean) as { key: string; label: string }[]

  return (
    <div className="flex flex-col h-full">
      {/* ── Toolbar ── */}
      <div className="p-4 border-b border-border space-y-3 flex-shrink-0">
        <div className="flex flex-wrap items-center gap-3">
          {/* Search */}
          <div className="relative flex-1 min-w-52">
            <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500 text-sm">🔍</span>
            <input type="text" placeholder="Search rules…" value={q} onChange={e => setQ(e.target.value)}
              className="w-full pl-9 pr-3 py-2 bg-bg-card border border-border rounded-lg text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-accent/60 transition-colors" />
          </div>

          <select value={appFilter} onChange={e => setAppFilter(e.target.value)}
            className="bg-bg-card border border-border rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-accent/60">
            <option value="">All Apps</option>
            {APP_OPTIONS.map(a => <option key={a} value={a}>{a}</option>)}
          </select>

          <select value={classFilter} onChange={e => setClassFilter(e.target.value)}
            className="bg-bg-card border border-border rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-accent/60">
            <option value="">All Classes</option>
            {CLASS_OPTIONS.map(c => <option key={c} value={c}>{c.replace('_', ' ')}</option>)}
          </select>

          <select value={sourceFilter} onChange={e => setSourceFilter(e.target.value)}
            className="bg-bg-card border border-border rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-accent/60 max-w-48">
            <option value="">All Sources</option>
            {sources.map(s => <option key={s.source} value={s.source}>{s.source} ({s.count})</option>)}
          </select>

          <div className="flex items-center gap-2 ml-auto">
            <button onClick={expandAll} className="text-xs text-gray-500 hover:text-gray-300 transition-colors">Expand all</button>
            <span className="text-gray-700">|</span>
            <button onClick={collapseAll} className="text-xs text-gray-500 hover:text-gray-300 transition-colors">Collapse all</button>
          </div>
        </div>

        {/* Active filter chips */}
        {activeFilters.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {activeFilters.map(f => (
              <button key={f.key} onClick={() => clearFilter(f.key)}
                className="flex items-center gap-1.5 text-xs px-2.5 py-1 bg-accent/10 border border-accent/30 text-accent-light rounded-full hover:bg-accent/20 transition-colors">
                {f.label}<span className="text-accent-light/60">✕</span>
              </button>
            ))}
          </div>
        )}

        {/* Summary row */}
        <div className="flex items-center gap-4 text-xs text-gray-500">
          {loading ? <span className="animate-pulse">Loading…</span> : (
            <span>{allRules.length.toLocaleString()} rules across {grouped.length} sources</span>
          )}
          {selected.size > 0 && (
            <span className="text-accent-light bg-accent/10 border border-accent/30 px-2.5 py-0.5 rounded-full">
              {selected.size} selected
            </span>
          )}
        </div>
      </div>

      {/* ── Grouped rule list ── */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {grouped.map(group => {
          const isCollapsed = collapsed.has(group.source)
          const groupSelected = group.rules.filter(r => selected.has(r.id)).length
          const allGroupSelected = groupSelected === group.rules.length

          return (
            <div key={group.source} className="bg-bg-card border border-border rounded-xl overflow-hidden">
              {/* Source header */}
              <div
                className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-white/3 select-none"
                onClick={() => toggleCollapse(group.source)}
              >
                {/* Collapse chevron */}
                <span className={`text-gray-500 text-xs transition-transform ${isCollapsed ? '-rotate-90' : ''}`}>▼</span>

                {/* Select-all checkbox for group */}
                <input
                  type="checkbox"
                  checked={allGroupSelected && group.rules.length > 0}
                  ref={el => { if (el) el.indeterminate = groupSelected > 0 && !allGroupSelected }}
                  onChange={e => { e.stopPropagation(); handleSelectGroup(group, e.target.checked) }}
                  onClick={e => e.stopPropagation()}
                  className="w-4 h-4 rounded border-gray-600 bg-bg-base accent-violet-600 cursor-pointer"
                />

                {/* Source name */}
                <span className="font-semibold text-sm text-gray-100 flex-1">{group.source}</span>

                {/* Template indicator */}
                {group.hasTemplates && (
                  <span className="text-xs bg-emerald-900/40 text-emerald-400 border border-emerald-800 px-2 py-0.5 rounded-full">
                    📂 {group.templateCount.toLocaleString()} templates
                  </span>
                )}

                {/* Rule count */}
                <span className="text-xs text-gray-500 bg-bg-surface px-2.5 py-0.5 rounded-full border border-border">
                  {group.rules.length} rule{group.rules.length !== 1 ? 's' : ''}
                </span>

                {/* Selection count */}
                {groupSelected > 0 && (
                  <span className="text-xs text-accent-light bg-accent/10 border border-accent/30 px-2 py-0.5 rounded-full">
                    {groupSelected} selected
                  </span>
                )}
              </div>

              {/* Rules table — hidden when collapsed */}
              {!isCollapsed && (
                <div className="border-t border-border">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border bg-bg-surface/50">
                        <th className="w-10 px-4 py-2" />
                        <th className="text-left px-3 py-2 text-xs font-medium text-gray-500">Rule name</th>
                        <th className="text-left px-3 py-2 text-xs font-medium text-gray-500 w-32">Class</th>
                        <th className="text-left px-3 py-2 text-xs font-medium text-gray-500 w-28">App</th>
                        <th className="w-24 px-3 py-2" />
                      </tr>
                    </thead>
                    <tbody>
                      {group.rules.map((rule, i) => (
                        <tr
                          key={rule.id}
                          className={`border-b border-border/50 last:border-0 hover:bg-white/3 cursor-pointer transition-colors ${
                            selected.has(rule.id) ? 'bg-accent/5' : i % 2 === 0 ? '' : 'bg-bg-surface/20'
                          }`}
                          onClick={() => setDrawerRule(rule)}
                        >
                          <td className="px-4 py-2.5" onClick={e => e.stopPropagation()}>
                            <input
                              type="checkbox"
                              checked={selected.has(rule.id)}
                              onChange={e => handleSelect(rule.id, e.target.checked)}
                              className="w-4 h-4 rounded border-gray-600 bg-bg-base accent-violet-600 cursor-pointer"
                            />
                          </td>
                          <td className="px-3 py-2.5 text-gray-200 font-medium">{rule.name}</td>
                          <td className="px-3 py-2.5"><ClassBadge cls={rule.rule_class} /></td>
                          <td className="px-3 py-2.5 text-gray-400 text-xs">{rule.app}</td>
                          <td className="px-3 py-2.5 text-right" onClick={e => e.stopPropagation()}>
                            <button
                              onClick={() => handleRunRule(rule.id)}
                              className="text-xs px-3 py-1 bg-accent/20 hover:bg-accent/40 text-accent-light rounded-lg transition-colors border border-accent/30"
                            >
                              Run →
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )
        })}

        {!loading && grouped.length === 0 && (
          <div className="flex flex-col items-center justify-center h-64 text-gray-500 gap-2">
            <span className="text-4xl">🔍</span>
            <p className="text-sm">No rules match your filters</p>
          </div>
        )}
      </div>

      <RuleDrawer rule={drawerRule} onClose={() => setDrawerRule(null)} onRunRule={handleRunRule} />
    </div>
  )
}
