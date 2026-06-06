interface Slice {
  label: string
  value: number
  color: string
}

interface Props {
  slices: Slice[]
  size?: number
  thickness?: number
}

function polarToCartesian(cx: number, cy: number, r: number, angleDeg: number) {
  const rad = ((angleDeg - 90) * Math.PI) / 180
  return {
    x: cx + r * Math.cos(rad),
    y: cy + r * Math.sin(rad),
  }
}

function describeArc(cx: number, cy: number, r: number, startAngle: number, endAngle: number) {
  const start = polarToCartesian(cx, cy, r, endAngle)
  const end = polarToCartesian(cx, cy, r, startAngle)
  const largeArc = endAngle - startAngle <= 180 ? '0' : '1'
  return `M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArc} 0 ${end.x} ${end.y}`
}

export function DonutChart({ slices, size = 120, thickness = 20 }: Props) {
  const cx = size / 2
  const cy = size / 2
  const r = size / 2 - thickness / 2 - 2
  const total = slices.reduce((s, sl) => s + sl.value, 0)
  if (total === 0) return null

  let cumulative = 0
  const paths = slices.map((sl) => {
    const startAngle = (cumulative / total) * 360
    cumulative += sl.value
    const endAngle = (cumulative / total) * 360
    const gap = 1
    const path = describeArc(cx, cy, r, startAngle + gap, endAngle - gap)
    return { path, color: sl.color, label: sl.label, value: sl.value }
  })

  return (
    <div className="flex items-center gap-4">
      <svg width={size} height={size} className="shrink-0">
        {paths.map((p, i) => (
          <path
            key={i}
            d={p.path}
            fill="none"
            stroke={p.color}
            strokeWidth={thickness}
            strokeLinecap="butt"
          />
        ))}
      </svg>
      <ul className="space-y-1 text-xs">
        {paths.map((p, i) => (
          <li key={i} className="flex items-center gap-2">
            <span className="inline-block w-2.5 h-2.5 rounded-sm" style={{ background: p.color }} />
            <span className="text-gray-300">{p.label}</span>
            <span className="text-gray-500 ml-1">{p.value}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
