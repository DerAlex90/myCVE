/*! Copyright (c) 2026 Alexander Speka (DerAlex90)
 * SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0 */

import { useEffect, useState } from 'react'
import { api, dateTime } from './api'

type Report = {
  status: string
  checked_at: string
  checks: Record<
    string,
    {
      status: string
      last_seen_at?: string
      completed_at?: string
      queue_length?: number
      source_errors?: string[]
    }
  >
}
const names: Record<string, string> = {
  database: 'Datenbank',
  redis: 'Warteschlange',
  worker: 'Scan-Worker',
  scheduler: 'Zeitplanung',
  last_successful_scan: 'Letzter erfolgreicher Abgleich',
  latest_scan: 'Letzter Scan',
}
const states: Record<string, string> = {
  unknown: 'Nicht bestätigt',
  ok: 'Erreichbar / aktuell',
  stale: 'Überfällig oder noch nicht bestätigt',
  error: 'Prüfen',
  not_required: 'In diesem Betriebsmodus nicht benötigt',
}
export function Operations() {
  const [report, setReport] = useState<Report | null>(null)
  const [error, setError] = useState('')
  useEffect(() => {
    let mounted = true
    const load = async () => {
      if (document.visibilityState !== 'visible') return
      try {
        const data = await api<Report>('/operations')
        if (mounted) {
          setReport(data)
          setError('')
        }
      } catch (err) {
        if (mounted)
          setError(err instanceof Error ? err.message : 'Betriebsstatus nicht erreichbar')
      }
    }
    void load()
    const timer = setInterval(() => void load(), 15000)
    return () => {
      mounted = false
      clearInterval(timer)
    }
  }, [])
  return (
    <details className="operations">
      <summary>
        Betriebsstatus:{' '}
        {error
          ? 'Abruf prüfen'
          : report?.status === 'ok'
            ? 'Aktuell'
            : report
              ? 'Eingeschränkt'
              : 'Wird geprüft …'}
      </summary>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      <div className="operations-grid">
        {Object.entries(report?.checks || {}).map(([name, check]) => (
          <div key={name}>
            <strong>{names[name] || name}</strong>
            <span>{states[check.status] || check.status}</span>
            {check.queue_length != null && <small>{check.queue_length} wartende Aufgaben</small>}
            {(check.last_seen_at || check.completed_at) && (
              <small>{dateTime(check.last_seen_at || check.completed_at)}</small>
            )}
            {check.source_errors?.map((value) => (
              <small key={value}>{value}</small>
            ))}
          </div>
        ))}
      </div>
      {report && <small>Geprüft: {dateTime(report.checked_at)}</small>}
    </details>
  )
}
