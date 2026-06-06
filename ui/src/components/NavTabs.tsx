export type TabId = 'dashboard' | 'rules' | 'run' | 'config'

interface Tab {
  id: TabId
  label: string
  icon: string
}

const TABS: Tab[] = [
  { id: 'dashboard', label: 'Dashboard', icon: '◉' },
  { id: 'rules', label: 'Rules', icon: '⚡' },
  { id: 'run', label: 'Run', icon: '▶' },
  { id: 'config', label: 'Environments', icon: '⚙' },
]

interface Props {
  active: TabId
  onChange: (id: TabId) => void
  runCount?: number
}

export function NavTabs({ active, onChange, runCount }: Props) {
  return (
    <nav className="flex items-center gap-1 px-4 py-2 border-b border-border bg-bg-deep">
      <div className="flex items-center gap-2 mr-6">
        <span className="text-accent text-xl font-bold tracking-tight">FoundStone</span>
        <span className="text-xs text-gray-500 font-mono">v0.1</span>
      </div>
      {TABS.map((tab) => {
        const isActive = tab.id === active
        return (
          <button
            key={tab.id}
            onClick={() => onChange(tab.id)}
            className={`relative flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              isActive
                ? 'bg-accent/20 text-accent-light border border-accent/30'
                : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
            }`}
          >
            <span>{tab.icon}</span>
            <span>{tab.label}</span>
            {tab.id === 'run' && runCount !== undefined && runCount > 0 && (
              <span className="ml-1 inline-flex items-center justify-center w-5 h-5 rounded-full bg-accent text-white text-xs">
                {runCount}
              </span>
            )}
          </button>
        )
      })}
    </nav>
  )
}
