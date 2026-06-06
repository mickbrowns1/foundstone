import { useState } from 'react'
import { NavTabs } from './components/NavTabs'
import type { TabId } from './components/NavTabs'
import { Dashboard } from './pages/Dashboard'
import { Rules } from './pages/Rules'
import { RunTab } from './pages/RunTab'
import { ConfigTab } from './pages/ConfigTab'
import type { RunResult } from './types'

export function App() {
  const [tab, setTab] = useState<TabId>('dashboard')
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [recentResults, setRecentResults] = useState<RunResult[]>([])

  const handleRunRule = (id: string) => {
    setSelected((prev) => new Set([...prev, id]))
    setTab('run')
  }

  const handleQuickRun = () => {
    setTab('run')
  }

  const handleRemoveRule = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev)
      next.delete(id)
      return next
    })
  }

  const handleJobResult = (results: RunResult[]) => {
    setRecentResults((prev) => [...results, ...prev].slice(0, 50))
  }

  return (
    <div className="flex flex-col h-screen bg-bg-base text-gray-100 overflow-hidden">
      <NavTabs active={tab} onChange={setTab} runCount={selected.size} />
      <main className="flex-1 overflow-y-auto">
        {tab === 'dashboard' && (
          <Dashboard recentResults={recentResults} onQuickRun={handleQuickRun} />
        )}
        {tab === 'rules' && (
          <Rules
            selected={selected}
            onSelectionChange={setSelected}
            onRunRule={handleRunRule}
          />
        )}
        {tab === 'run' && (
          <RunTab
            selectedIds={selected}
            onRemoveRule={handleRemoveRule}
            onClearSelection={() => setSelected(new Set())}
            onJobResult={handleJobResult}
          />
        )}
        {tab === 'config' && <ConfigTab />}
      </main>
    </div>
  )
}
