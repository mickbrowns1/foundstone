import { useEffect, useState } from 'react'
import { api } from '../api/client'
import type { RuleDetail, RuleSummary } from '../types'
import { ClassBadge } from './ClassBadge'

interface Props {
  rule: RuleSummary | null
  onClose: () => void
  onRunRule: (id: string) => void
}

export function RuleDrawer({ rule, onClose, onRunRule }: Props) {
  const [detail, setDetail] = useState<RuleDetail | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!rule) {
      setDetail(null)
      return
    }
    setLoading(true)
    api
      .getRule(rule.id)
      .then(setDetail)
      .finally(() => setLoading(false))
  }, [rule?.id])

  if (!rule) return null

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/50 z-40 transition-opacity"
        onClick={onClose}
      />

      {/* Drawer */}
      <div className="fixed right-0 top-0 h-full w-full max-w-2xl bg-bg-deep border-l border-border z-50 flex flex-col shadow-2xl">
        {/* Header */}
        <div className="flex items-start justify-between p-5 border-b border-border">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <ClassBadge cls={rule.rule_class} />
              <span className="text-xs text-gray-500">{rule.app}</span>
            </div>
            <h2 className="text-lg font-semibold text-gray-100 leading-tight">{rule.name}</h2>
            <p className="text-xs text-gray-500 font-mono mt-1 truncate">{rule.file}</p>
          </div>
          <button
            onClick={onClose}
            className="ml-4 p-1.5 rounded-lg text-gray-400 hover:text-gray-200 hover:bg-white/10 transition-colors shrink-0"
          >
            ✕
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {loading && (
            <div className="text-gray-400 text-sm animate-pulse">Loading details…</div>
          )}

          {detail && (
            <>
              {/* Description */}
              <section>
                <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
                  Description
                </h3>
                <p className="text-sm text-gray-300 leading-relaxed">{detail.description}</p>
              </section>

              {/* Source */}
              {detail.source && (
                <section>
                  <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
                    Data Source
                  </h3>
                  <span className="text-sm font-mono text-accent-light">{detail.source}</span>
                </section>
              )}

              {/* Queries */}
              {detail.queries.map((q, qi) => (
                <section key={qi} className="space-y-3">
                  <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
                    Query {detail.queries.length > 1 ? qi + 1 : ''}
                  </h3>

                  {/* Raw S1QL */}
                  <div>
                    <p className="text-xs text-gray-500 mb-1">S1QL</p>
                    <pre className="bg-bg-base text-emerald-300 text-xs p-3 rounded-lg overflow-x-auto border border-border whitespace-pre-wrap break-all font-mono">
                      {q.query}
                    </pre>
                  </div>

                  {/* Pair list table */}
                  {q.pair_list.length > 0 && (
                    <div>
                      <p className="text-xs text-gray-500 mb-1">Filter pairs</p>
                      <div className="rounded-lg border border-border overflow-hidden">
                        <table className="w-full text-xs">
                          <thead className="bg-bg-card">
                            <tr>
                              <th className="px-3 py-2 text-left text-gray-400 font-medium">Key</th>
                              <th className="px-3 py-2 text-left text-gray-400 font-medium w-12">Op</th>
                              <th className="px-3 py-2 text-left text-gray-400 font-medium">Value</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border">
                            {q.pair_list.map((p, pi) => (
                              <tr key={pi}>
                                <td className="px-3 py-1.5 font-mono text-cyan-300">{p.key}</td>
                                <td className="px-3 py-1.5 font-mono text-amber-400">{p.op}</td>
                                <td className="px-3 py-1.5 font-mono text-gray-300">{p.value}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {/* Overlay fields */}
                  {Object.keys(q.overlay).length > 0 && (
                    <div>
                      <p className="text-xs text-gray-500 mb-1">Overlay fields (would be modified)</p>
                      <div className="rounded-lg border border-border overflow-hidden">
                        <table className="w-full text-xs">
                          <tbody className="divide-y divide-border">
                            {Object.entries(q.overlay).map(([k, v]) => (
                              <tr key={k}>
                                <td className="px-3 py-1.5 font-mono text-violet-300 w-1/2">{k}</td>
                                <td className="px-3 py-1.5 font-mono text-gray-300">
                                  {JSON.stringify(v)}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </section>
              ))}
            </>
          )}
        </div>

        {/* Footer */}
        <div className="p-5 border-t border-border">
          <button
            onClick={() => onRunRule(rule.id)}
            className="w-full py-2.5 rounded-lg bg-accent hover:bg-accent-hover text-white font-medium text-sm transition-colors"
          >
            ▶ Run this rule
          </button>
        </div>
      </div>
    </>
  )
}
