export type Identification = {
  status?: 'identified' | 'pending' | 'unresolved' | 'ambiguous' | 'missing_version' | 'error'
  reason?: string
  cpe?: string
  ecosystem?: string
  url?: string
  checked_at?: string
  next_check_at?: string
  candidates?: { cpe: string; cpe_id?: string }[]
}
export type Coverage = {
  identified: number
  pending: number
  unresolved: number
  ambiguous: number
  missing_version: number
  error: number
}
export type Component = {
  name: string
  version: string | null
  ecosystem: string | null
  purl?: string
  cpe?: string
  ref?: string
  id?: string
  origin?: string
  identification?: Identification
  inventory?: {
    name: string
    version?: string
    architecture?: string
    source_name?: string
    source_version?: string
    version_source?: string
  }
}
export type Asset = {
  id: string
  name: string
  owner: string
  environment: string
  exposure: string
  criticality: string
  components: number
  open_findings: number
}
export type Evidence = {
  status: string
  reason: string
  source: string
  url?: string
  record_id?: string
  checksum?: string
}
export type Finding = {
  id: string
  alias: string
  aliases: string[]
  title: string
  description: string
  reason: string
  asset_id: string
  asset_name: string
  exposure: string
  criticality: string
  component: Component
  status: string
  priority: string
  priority_score: number
  priority_reasons: string[]
  fixed_versions: string[]
  workflow: string
  notes: string
  kev: boolean
  kev_due_date: string | null
  cvss: number | null
  updated_at: string
  evaluated_at: string
  evidence: Evidence[]
  installation_active: boolean
}
export type Source = {
  id: string
  source: string
  url: string
  checksum: string
  current: boolean
  fetched_at: string
  source_modified: string | null
  last_seen_at: string
}
export type FindingDetail = Finding & {
  sources: Source[]
  history: {
    id: string
    action: string
    created_at: string
    after: { status: string; workflow: string; priority: string }
  }[]
}
export type Scan = {
  id: string
  status: string
  created_at: string
  completed_at: string | null
  error: string | null
  result: {
    demo?: boolean
    sources?: Record<string, string>
    counts?: Record<string, number>
    errors?: string[]
  }
}
export type Overview = {
  identification: Coverage
  incomplete_components: number
  assets: number
  components: number
  open_findings: number
  affected: number
  unknown: number
  kev: number
  priorities: Record<string, number>
  last_scan: Scan | null
}
export type AppConfig = { authentication_required: boolean; demo: boolean; version: string }

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  const key = sessionStorage.getItem('mycve-key')
  if (key) headers.set('Authorization', `Bearer ${key}`)
  if (init.body && !(init.body instanceof FormData)) headers.set('Content-Type', 'application/json')
  const response = await fetch(`/api${path}`, { ...init, headers })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    if (response.status === 401) window.dispatchEvent(new Event('mycve-unauthorized'))
    throw new Error(
      typeof body.detail === 'string' ? body.detail : `Anfrage fehlgeschlagen (${response.status})`,
    )
  }
  return response.json() as Promise<T>
}

export async function downloadCsv() {
  return downloadFile('/findings/export.csv', 'mycve-findings.csv')
}

export async function downloadFile(path: string, filename: string) {
  const key = sessionStorage.getItem('mycve-key')
  const response = await fetch(`/api${path}`, {
    headers: key ? { Authorization: `Bearer ${key}` } : {},
  })
  if (!response.ok) throw new Error('Download fehlgeschlagen')
  const url = URL.createObjectURL(await response.blob())
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export const statusText: Record<string, string> = {
  affected: 'Betroffen',
  unknown: 'Ungeklärt',
  not_affected: 'Nicht betroffen',
}
export const workflowText: Record<string, string> = {
  open: 'Offen',
  in_progress: 'In Bearbeitung',
  accepted: 'Risiko akzeptiert',
  resolved: 'Erledigt',
}
export const scanText: Record<string, string> = {
  queued: 'Vorgemerkt',
  running: 'Läuft',
  succeeded: 'Abgeschlossen',
  partial: 'Teilweise abgeschlossen',
  failed: 'Fehlgeschlagen',
}
export function dateTime(value?: string | null) {
  if (!value) return 'Noch kein Abruf'
  const normalized = /^\d{4}-\d{2}-\d{2}$/.test(value)
    ? value + 'T00:00:00Z'
    : value.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(value)
      ? value
      : value + 'Z'
  const date = new Date(normalized)
  if (Number.isNaN(date.getTime())) return 'Zeitpunkt ungeklärt'
  return new Intl.DateTimeFormat('de-DE', {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: 'Europe/Berlin',
  }).format(date)
}
