import type { RuleSummary } from '../types'
import { ClassBadge } from './ClassBadge'

interface Props {
  rules: RuleSummary[]
  total: number
  offset: number
  limit: number
  selected: Set<string>
  onSelect: (id: string, checked: boolean) => void
  onSelectAll: (checked: boolean) => void
  onRowClick: (rule: RuleSummary) => void
  onPageChange: (offset: number) => void
}

export function RuleTable({
  rules,
  total,
  offset,
  limit,
  selected,
  onSelect,
  onSelectAll,
  onRowClick,
  onPageChange,
}: Props) {
  const totalPages = Math.ceil(total / limit)
  const currentPage = Math.floor(offset / limit) + 1
  const allChecked = rules.length > 0 && rules.every((r) => selected.has(r.id))
  const someChecked = rules.some((r) => selected.has(r.id)) && !allChecked

  return (
    <div className="flex flex-col h-full">
      <div className="overflow-auto flex-1 rounded-lg border border-border">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-bg-card border-b border-border z-10">
            <tr>
              <th className="w-10 px-3 py-3 text-left">
                <input
                  type="checkbox"
                  checked={allChecked}
                  ref={(el) => {
                    if (el) el.indeterminate = someChecked
                  }}
                  onChange={(e) => onSelectAll(e.target.checked)}
                  className="rounded border-gray-600 bg-bg-surface accent-accent"
                />
              </th>
              <th className="px-3 py-3 text-left text-gray-400 font-medium">Name</th>
              <th className="px-3 py-3 text-left text-gray-400 font-medium w-36">Source</th>
              <th className="px-3 py-3 text-left text-gray-400 font-medium w-24">App</th>
              <th className="px-3 py-3 text-left text-gray-400 font-medium w-32">Class</th>
              <th className="px-3 py-3 text-left text-gray-400 font-medium w-20">Copies</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {rules.map((rule) => (
              <tr
                key={rule.id}
                onClick={() => onRowClick(rule)}
                className={`cursor-pointer transition-colors ${
                  selected.has(rule.id) ? 'bg-accent/10' : 'hover:bg-white/3'
                }`}
              >
                <td className="px-3 py-2.5" onClick={(e) => e.stopPropagation()}>
                  <input
                    type="checkbox"
                    checked={selected.has(rule.id)}
                    onChange={(e) => onSelect(rule.id, e.target.checked)}
                    className="rounded border-gray-600 bg-bg-surface accent-accent"
                  />
                </td>
                <td className="px-3 py-2.5">
                  <span className="text-gray-200 font-medium line-clamp-1">{rule.name}</span>
                  <span className="text-xs text-gray-500 font-mono truncate block max-w-xs">
                    {rule.file.split('/').slice(-1)[0]}
                  </span>
                </td>
                <td className="px-3 py-2.5">
                  <span className="text-gray-300 text-xs font-mono truncate block">
                    {rule.source ?? '—'}
                  </span>
                </td>
                <td className="px-3 py-2.5">
                  <span
                    className={`text-xs font-medium ${
                      rule.app === 'STAR'
                        ? 'text-accent-light'
                        : rule.app === 'Anomaly'
                        ? 'text-cyan-400'
                        : 'text-pink-400'
                    }`}
                  >
                    {rule.app}
                  </span>
                </td>
                <td className="px-3 py-2.5">
                  <ClassBadge cls={rule.rule_class} />
                </td>
                <td className="px-3 py-2.5 text-gray-400 text-xs">{rule.copies}</td>
              </tr>
            ))}
            {rules.length === 0 && (
              <tr>
                <td colSpan={6} className="px-6 py-12 text-center text-gray-500">
                  No rules found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between px-1 pt-3 text-sm text-gray-400">
        <span>
          {total > 0
            ? `${offset + 1}–${Math.min(offset + limit, total)} of ${total.toLocaleString()} rules`
            : '0 rules'}
        </span>
        <div className="flex items-center gap-2">
          <button
            disabled={currentPage <= 1}
            onClick={() => onPageChange(offset - limit)}
            className="px-3 py-1.5 rounded border border-border text-gray-300 disabled:opacity-40 hover:enabled:bg-white/5 transition-colors"
          >
            ← Prev
          </button>
          <span className="px-2">
            {currentPage} / {totalPages}
          </span>
          <button
            disabled={currentPage >= totalPages}
            onClick={() => onPageChange(offset + limit)}
            className="px-3 py-1.5 rounded border border-border text-gray-300 disabled:opacity-40 hover:enabled:bg-white/5 transition-colors"
          >
            Next →
          </button>
        </div>
      </div>
    </div>
  )
}
