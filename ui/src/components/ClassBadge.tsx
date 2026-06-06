import type { RuleClass } from '../types'

interface Props {
  cls: RuleClass | string
}

const COLORS: Record<string, string> = {
  simple: 'bg-violet-900/50 text-violet-300 border border-violet-700',
  volume: 'bg-orange-900/50 text-orange-300 border border-orange-700',
  correlation: 'bg-cyan-900/50 text-cyan-300 border border-cyan-700',
  first_seen: 'bg-pink-900/50 text-pink-300 border border-pink-700',
  scheduled: 'bg-teal-900/50 text-teal-300 border border-teal-700',
}

const LABELS: Record<string, string> = {
  simple: 'Simple',
  volume: 'Volume',
  correlation: 'Correlation',
  first_seen: 'First Seen',
  scheduled: 'Scheduled',
}

export function ClassBadge({ cls }: Props) {
  const color = COLORS[cls] ?? 'bg-gray-800 text-gray-400 border border-gray-600'
  const label = LABELS[cls] ?? cls
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${color}`}>
      {label}
    </span>
  )
}
