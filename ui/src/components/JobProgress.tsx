import { useEffect, useRef } from 'react'
import { api } from '../api/client'
import type { Job } from '../types'

interface Props {
  jobId: string
  onUpdate: (job: Job) => void
}

export function JobProgress({ jobId, onUpdate }: Props) {
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    const poll = async () => {
      try {
        const job = await api.getJob(jobId)
        onUpdate(job)
        if (job.status === 'done' || job.status === 'error') {
          if (intervalRef.current) clearInterval(intervalRef.current)
        }
      } catch {
        if (intervalRef.current) clearInterval(intervalRef.current)
      }
    }

    poll()
    intervalRef.current = setInterval(poll, 2000)
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [jobId, onUpdate])

  return null
}
