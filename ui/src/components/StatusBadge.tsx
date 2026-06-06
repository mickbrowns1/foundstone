import type { RunStatus } from '../types'

interface Props {
  status: RunStatus | string
}

const COLORS: Record<string, string> = {
  ingested: 'bg-emerald-900/50 text-emerald-300 border border-emerald-700',
  dry_run: 'bg-blue-900/50 text-blue-300 border border-blue-700',
  no_template: 'bg-amber-900/50 text-amber-300 border border-amber-700',
  error: 'bg-red-900/50 text-red-300 border border-red-700',
}

const LABELS: Record<string, string> = {
  ingested: 'Ingested',
  dry_run: 'Dry Run',
  no_template: 'No Template',
  error: 'Error',
}

export function StatusBadge({ status }: Props) {
  const cls = COLORS[status] ?? 'bg-gray-800 text-gray-400 border border-gray-600'
  const label = LABELS[status] ?? status
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${cls}`}>
      {label}
    </span>
  )
}
