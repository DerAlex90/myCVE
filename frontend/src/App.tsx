/*! Copyright (c) 2026 Alexander Speka (DerAlex90)
 * SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0 */

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import {
  api,
  componentTypeText,
  kernelText,
  patchText,
  phaseText,
  dateTime,
  downloadCsv,
  scanText,
  statusText,
  workflowText,
  type AppConfig,
  type Asset,
  type Component,
  type Finding,
  type FindingDetail,
  type Overview,
  type Scan,
} from './api'
import { Icon } from './Icon'
import { Modal } from './Modal'
import { Agents } from './Agents'
import { Operations } from './Operations'

type Page = 'findings' | 'assets' | 'agents' | 'sources' | 'activity' | 'library'
const nav: { id: Page; label: string; icon: string }[] = [
  { id: 'findings', label: 'Übersicht', icon: 'grid' },
  { id: 'assets', label: 'Systeme & Inventar', icon: 'server' },
  { id: 'agents', label: 'Inventar-Agenten', icon: 'globe' },
  { id: 'sources', label: 'Datenquellen', icon: 'database' },
  { id: 'activity', label: 'Aktivität', icon: 'activity' },
  { id: 'library', label: 'Python-Bibliothek', icon: 'code' },
]
const priorities: Record<string, string> = {
  P0: 'Sofort handeln',
  P1: 'Hohe Priorität',
  P2: 'Prüfen & planen',
  P3: 'Beobachten',
  none: 'Kein Handlungsbedarf',
}
const sourceInfo = [
  {
    name: 'OSV',
    short: 'OS',
    color: 'purple',
    purpose: 'Exakter Paketabgleich',
    detail:
      'Ökosystem, Paketname und Version. Paketnamen und Versionen werden für den Abgleich an OSV übertragen.',
    url: 'https://osv.dev',
  },
  {
    name: 'CVE Program',
    short: 'CV',
    color: 'blue',
    purpose: 'Die gemeinsame Datenbasis',
    detail:
      'Offizielle CVE-Datensätze aus cvelistV5. Originaltexte und Änderungen bleiben nachvollziehbar.',
    url: 'https://www.cve.org',
  },
  {
    name: 'NVD',
    short: 'NV',
    color: 'orange',
    purpose: 'Bewertungen & Produktkontext',
    detail:
      'CVSS-Metriken und CPE-Konfigurationen ergänzen bekannte CVEs. Komplexer Produktkontext bleibt zur Prüfung offen.',
    url: 'https://nvd.nist.gov',
  },
  {
    name: 'CISA KEV',
    short: 'KE',
    color: 'red',
    purpose: 'Bekannte aktive Ausnutzung',
    detail:
      'Ein bestätigtes Ausnutzungssignal erhöht die Dringlichkeit. KEV-Fristen werden als Quelleninformation angezeigt.',
    url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
  },
  {
    name: 'BSI CSAF',
    short: 'BS',
    color: 'green',
    purpose: 'Zusätzliche Sicherheitshinweise',
    detail:
      'Offizielle CERT-Bund-Metadaten, öffentliche WHITE/CLEAR-Feeds und Produktstatus. GREEN-Inhalte sind ausgeschlossen.',
    url: 'https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json',
  },
]
const message = (error: unknown) =>
  error instanceof Error ? error.message : 'Die Aktion konnte nicht abgeschlossen werden.'
const safeUrl = (url: string) => (/^https:\/\//i.test(url) ? url : undefined)

function Badge({ status }: { status: string }) {
  return (
    <span className={`badge status-${status}`}>
      <span className="tiny-dot" />
      {statusText[status] || status}
    </span>
  )
}
function Priority({ value }: { value: string }) {
  return (
    <span className={`priority priority-${value}`} title={priorities[value]}>
      <span className="priority-bars">▂▄▆</span>
      {value === 'none' ? '–' : value}
    </span>
  )
}
function Empty({
  icon = 'shield',
  title,
  children,
}: {
  icon?: string
  title: string
  children: React.ReactNode
}) {
  return (
    <div className="empty">
      <div className="empty-icon">
        <Icon name={icon} size={28} />
      </div>
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  )
}

export default function App() {
  const [config, setConfig] = useState<AppConfig | null>(null)
  const [authorized, setAuthorized] = useState(false)
  const [key, setKey] = useState('')
  const [page, setPage] = useState<Page>(() =>
    nav.some((item) => item.id === location.hash.slice(1))
      ? (location.hash.slice(1) as Page)
      : 'findings',
  )
  const [overview, setOverview] = useState<Overview | null>(null)
  const [assets, setAssets] = useState<Asset[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [scans, setScans] = useState<Scan[]>([])
  const [total, setTotal] = useState(0)
  const [search, setSearch] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [status, setStatus] = useState('')
  const [priority, setPriority] = useState('')
  const [workflow, setWorkflow] = useState('')
  const [assetFilter, setAssetFilter] = useState('')
  const [findingView, setFindingView] = useState<'risks' | 'packages'>('risks')
  const [componentType, setComponentType] = useState('')
  const [patchStatus, setPatchStatus] = useState('')
  const [exportMode, setExportMode] = useState('current')
  const [offset, setOffset] = useState(0)
  const [error, setError] = useState('')
  const [refreshError, setRefreshError] = useState('')
  const [toast, setToast] = useState('')
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [selected, setSelected] = useState<string | null>(null)
  const [assetForm, setAssetForm] = useState<Asset | 'new' | null>(null)
  const [importAsset, setImportAsset] = useState<string | null>(null)
  const [inventoryAsset, setInventoryAsset] = useState<Asset | null>(null)
  const [mobile, setMobile] = useState(false)
  const requestVersion = useRef(0)
  const refreshing = useRef(false)
  const lastLoad = useRef({ overview: 0, assets: 0 })

  useEffect(() => {
    api<AppConfig>('/config')
      .then((data) => {
        setConfig(data)
        setAuthorized(!data.authentication_required || !!sessionStorage.getItem('mycve-key'))
      })
      .catch((err) => {
        setError(message(err))
        setLoading(false)
      })
    const unauthorized = () => {
      setAuthorized(false)
      sessionStorage.removeItem('mycve-key')
    }
    const hash = () => {
      const found = nav.find((item) => item.id === location.hash.slice(1))
      if (found) setPage(found.id)
    }
    window.addEventListener('mycve-unauthorized', unauthorized)
    window.addEventListener('hashchange', hash)
    return () => {
      window.removeEventListener('mycve-unauthorized', unauthorized)
      window.removeEventListener('hashchange', hash)
    }
  }, [])
  useEffect(() => {
    const timer = setTimeout(() => {
      setSearchQuery(search)
      setOffset(0)
    }, 250)
    return () => clearTimeout(timer)
  }, [search])
  useEffect(() => {
    if (toast) {
      const timer = setTimeout(() => setToast(''), 5000)
      return () => clearTimeout(timer)
    }
  }, [toast])
  const findingParams = useCallback(
    (paging = false, view = findingView) => {
      const params = new URLSearchParams({ search: searchQuery, view })
      if (paging) {
        params.set('limit', '20')
        params.set('offset', String(offset))
      }
      for (const [name, value] of [
        ['status', status],
        ['priority', priority],
        ['workflow', workflow],
        ['asset_id', assetFilter],
        ['component_type', componentType],
        ['patch_status', patchStatus],
      ]) {
        if (value) params.set(name, value)
      }
      return params
    },
    [
      searchQuery,
      findingView,
      offset,
      status,
      priority,
      workflow,
      assetFilter,
      componentType,
      patchStatus,
    ],
  )
  const refresh = useCallback(
    async (force = false) => {
      if (!authorized) return
      const version = ++requestVersion.current
      refreshing.current = true
      try {
        const updates: Promise<() => void>[] = [
          api<Scan[]>('/scans').then((data) => () => setScans(data)),
        ]
        if (force || Date.now() - lastLoad.current.overview >= 15000) {
          updates.push(
            api<Overview>('/overview').then((data) => () => {
              setOverview(data)
              lastLoad.current.overview = Date.now()
            }),
          )
        }
        if (
          (force || Date.now() - lastLoad.current.assets >= 60000) &&
          ['findings', 'assets', 'agents'].includes(page)
        ) {
          updates.push(
            api<Asset[]>('/assets').then((data) => () => {
              setAssets(data)
              lastLoad.current.assets = Date.now()
            }),
          )
        }
        if (page === 'findings') {
          updates.push(
            api<{ items: Finding[]; total: number }>(`/findings?${findingParams(true)}`).then(
              (data) => () => {
                setFindings(data.items)
                setTotal(data.total)
              },
            ),
          )
        }
        const apply = await Promise.all(updates)
        if (version !== requestVersion.current) return
        apply.forEach((update) => update())
        setRefreshError('')
      } catch (err) {
        if (version === requestVersion.current) setRefreshError(message(err))
      } finally {
        if (version === requestVersion.current) {
          refreshing.current = false
          setLoading(false)
        }
      }
    },
    [authorized, page, findingParams],
  )
  useEffect(() => {
    void refresh()
  }, [refresh])
  const running = scans.some((scan) => ['queued', 'running'].includes(scan.status))
  useEffect(() => {
    if (!authorized) return
    const update = () => {
      if (document.visibilityState === 'visible' && !refreshing.current) void refresh()
    }
    const timer = setInterval(update, running ? 4000 : 15000)
    window.addEventListener('focus', update)
    document.addEventListener('visibilitychange', update)
    return () => {
      clearInterval(timer)
      window.removeEventListener('focus', update)
      document.removeEventListener('visibilitychange', update)
    }
  }, [authorized, running, refresh])
  const action = async (fn: () => Promise<void>) => {
    setBusy(true)
    setError('')
    try {
      await fn()
    } catch (err) {
      setError(message(err))
    } finally {
      setBusy(false)
    }
  }
  const go = (next: Page) => {
    setPage(next)
    location.hash = next
    setMobile(false)
  }
  const resetFilters = () => {
    setSearch('')
    setStatus('')
    setPriority('')
    setWorkflow('')
    setAssetFilter('')
    setComponentType('')
    setPatchStatus('')
    setOffset(0)
  }
  const hasFilters = !!(
    search ||
    status ||
    priority ||
    workflow ||
    assetFilter ||
    componentType ||
    patchStatus
  )
  const startScan = (forceFull = false) =>
    action(async () => {
      await api('/scans', { method: 'POST', body: JSON.stringify({ force_full: forceFull }) })
      setToast('Scan vorgemerkt. Der Fortschritt erscheint unter Aktivität.')
      await refresh(true)
    })
  const login = (event: FormEvent) => {
    event.preventDefault()
    void action(async () => {
      sessionStorage.setItem('mycve-key', key.trim())
      await api('/overview')
      setKey('')
      setAuthorized(true)
      setError('')
    })
  }

  if (!config)
    return (
      <div className="boot">
        <div className="brand">
          <Icon name="shield" size={32} />
          <span>
            my<span>CVE</span>
          </span>
        </div>
        <p>{error || 'Deine Sicherheitsübersicht wird geladen …'}</p>
        {error && (
          <button className="button" onClick={() => location.reload()}>
            Erneut versuchen
          </button>
        )}
      </div>
    )
  if (!authorized)
    return (
      <div className="login-screen">
        <div className="login-story">
          <div className="brand">
            <Icon name="shield" size={36} />
            <span>
              my<span>CVE</span>
              <small>VULNERABILITY INTELLIGENCE</small>
            </span>
          </div>
          <div>
            <span className="eyebrow light">WISSEN, WAS ZU TUN IST.</span>
            <h1>
              Dein Inventar.
              <br />
              Klare Prioritäten.
            </h1>
            <p>
              Schwachstellen verstehen, Betroffenheit belegen und die nächsten Schritte im Blick
              behalten.
            </p>
          </div>
          <span className="login-footer">
            <Icon name="lock" size={16} />
            <a href="/license" target="_blank" rel="noreferrer">
              © 2026 Alexander Speka (DerAlex90) · Lizenz
            </a>
          </span>
        </div>
        <form className="login-form" onSubmit={login}>
          <span className="eyebrow">WILLKOMMEN ZURÜCK</span>
          <h2>Workspace öffnen</h2>
          <p>Melde dich mit dem API-Schlüssel deiner Installation an.</p>
          <label>
            API-Schlüssel
            <input
              type="password"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              required
              autoComplete="current-password"
              placeholder="Deinen Schlüssel eingeben"
            />
          </label>
          {error && (
            <div className="form-error" role="alert">
              {error}
            </div>
          )}
          <button className="button primary" disabled={busy}>
            {busy ? 'Wird geprüft …' : 'Sicher anmelden'}
            <Icon name="arrow" size={17} />
          </button>
          <small>
            Der Schlüssel wird für diese Sitzung im Browser gespeichert. Du findest ihn in der
            Konfiguration deiner Installation.
          </small>
        </form>
      </div>
    )

  return (
    <div className="app-shell">
      {mobile && (
        <button
          className="sidebar-scrim"
          aria-label="Navigation schließen"
          onClick={() => setMobile(false)}
        />
      )}
      <aside className={`sidebar ${mobile ? 'mobile-open' : ''}`}>
        <a className="brand" href="#findings" onClick={() => go('findings')}>
          <div className="brand-icon">
            <Icon name="shield" size={26} />
          </div>
          <span>
            my<span>CVE</span>
            <small>VULNERABILITY INTELLIGENCE</small>
          </span>
        </a>
        <div className="workspace-switch">
          <span className="workspace-letter">M</span>
          <div>
            Mein Workspace<small>Self-hosted · Quellcode einsehbar</small>
          </div>
          <Icon name="lock" size={14} />
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav aria-label="Hauptnavigation">
          {nav.map((item) => (
            <button
              key={item.id}
              onClick={() => go(item.id)}
              className={`nav-item ${page === item.id ? 'active' : ''}`}
              aria-current={page === item.id ? 'page' : undefined}
            >
              <Icon name={item.icon} size={19} />
              <span>{item.label}</span>
              {item.id === 'findings' && overview && overview.open_findings > 0 && (
                <span className="nav-count">{overview.open_findings}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-note">
          <div className="note-symbol">
            <Icon name="shield" size={24} />
          </div>
          <h3>Sicherheit braucht Kontext.</h3>
          <p>Betroffenheit und Dringlichkeit. Zusammen, aber klar getrennt.</p>
          <button onClick={() => go('library')}>
            So funktioniert myCVE <Icon name="arrow" size={14} />
          </button>
        </div>
        <div className="sidebar-bottom">
          <div>
            <span className="connection-dot" /> Eigene Installation
            <span className="version">v{config.version}</span>
          </div>
          <a href="https://github.com/DerAlex90/myCVE" target="_blank" rel="noreferrer">
            <Icon name="code" size={15} />
            Quellcode ansehen
            <Icon name="arrowUp" size={13} />
          </a>
          {config.authentication_required && (
            <button
              onClick={() => {
                sessionStorage.removeItem('mycve-key')
                setAuthorized(false)
              }}
            >
              <Icon name="logout" size={15} /> Abmelden
            </button>
          )}
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            <button
              className="icon-button mobile-menu"
              aria-label="Navigation öffnen"
              onClick={() => setMobile(true)}
            >
              <Icon name="menu" />
            </button>
            <Icon name="grid" size={16} />
            <span>Workspace</span>
            <span className="slash">/</span>
            <strong>{nav.find((item) => item.id === page)?.label}</strong>
          </div>
          <div className="topbar-right">
            <span className="private-label">
              <Icon name="lock" size={13} />
              Privater Workspace
            </span>
            <span className="avatar">M</span>
          </div>
        </header>
        <main>
          {config.demo && (
            <div className="demo-banner">
              <Icon name="info" size={16} />
              <span>
                <strong>Demo-Workspace</strong> · Alle Systeme, Meldungen und Ausnutzungssignale
                sind fiktive Beispieldaten.
              </span>
              <span className="demo-pill">DEMO</span>
            </div>
          )}
          {(error || refreshError) && (
            <div className="error-banner" role="alert">
              <Icon name="warning" size={18} />
              <span>{error || refreshError}</span>
              <button
                className="icon-button"
                onClick={() => {
                  setError('')
                  setRefreshError('')
                }}
                aria-label="Fehlermeldung schließen"
              >
                <Icon name="close" size={16} />
              </button>
            </div>
          )}
          <div className="page-heading">
            <div>
              <div className="eyebrow">
                {page === 'findings' ? 'DEIN SICHERHEITSKOMPASS' : 'VULNERABILITY INTELLIGENCE'}
              </div>
              <h1>
                {
                  {
                    findings: 'Sicherheitsübersicht',
                    assets: 'Systeme & Inventar',
                    agents: 'Automatisch auf dem aktuellen Stand.',
                    sources: 'Verlässliche Daten. Klare Herkunft.',
                    activity: 'Jede Änderung im Blick.',
                    library: 'Ein Kern. Viele Möglichkeiten.',
                  }[page]
                }
              </h1>
              <p>
                {
                  {
                    findings: 'Erkenne, was dich betrifft. Handle dort, wo es zählt.',
                    assets: 'Die Grundlage für jeden belastbaren Schwachstellenabgleich.',
                    agents:
                      'Windows und Linux erfassen ihre installierten Pakete und melden sie an deinen Server.',
                    sources:
                      'Fünf Quellen verbinden Schwachstellen mit dem Kontext deiner Systeme.',
                    activity: 'Datenabrufe, Scan-Ergebnisse und nachvollziehbare Veränderungen.',
                    library: 'Nutze das Matching unabhängig von API, Datenbank und Oberfläche.',
                  }[page]
                }
              </p>
            </div>
            <div className="heading-actions">
              {page === 'assets' ? (
                <button className="button primary" onClick={() => setAssetForm('new')}>
                  <Icon name="plus" size={17} />
                  System hinzufügen
                </button>
              ) : (
                page !== 'library' && (
                  <button
                    className="button primary"
                    disabled={busy || running || config.demo}
                    title={
                      config.demo
                        ? 'Echte Scans stehen in deiner eigenen Installation zur Verfügung'
                        : undefined
                    }
                    onClick={() => void startScan()}
                  >
                    <Icon name="refresh" className={running ? 'spinning' : ''} size={16} />
                    {running ? 'Scan läuft …' : 'Jetzt abgleichen'}
                  </button>
                )
              )}
            </div>
          </div>

          {loading ? (
            <div className="loading-state">
              <span className="loader" />
              <p>Inventar und Findings werden geladen …</p>
            </div>
          ) : (
            <>
              {page === 'findings' && (
                <>
                  {(overview?.incomplete_components || 0) > 0 && (
                    <div className="inventory-coverage">
                      <Icon name="info" size={18} />
                      <p>
                        <strong>
                          Automatische Produktzuordnung für {overview?.incomplete_components}{' '}
                          Komponenten noch offen.
                        </strong>{' '}
                        Der Server ermittelt Kennungen selbstständig und wiederholt ungeklärte
                        Abfragen. Fehlende Versionen werden mit neuen Agentenberichten erneut
                        geprüft. Diese Einträge gelten noch nicht als vollständig abgeglichen.
                      </p>
                      <button className="text-button" onClick={() => go('assets')}>
                        Status ansehen
                        <Icon name="arrow" size={14} />
                      </button>
                    </div>
                  )}
                  <div className="risk-kind-summary">
                    Risiken je Typ (Mehrfachzuordnung möglich):{' '}
                    {['runtime', 'development', 'unknown'].map((kind) => (
                      <button
                        key={kind}
                        className="text-button"
                        onClick={() => {
                          setComponentType(kind)
                          setOffset(0)
                        }}
                      >
                        {componentTypeText[kind]}: {overview?.component_types?.[kind] || 0}
                      </button>
                    ))}
                  </div>
                  <div className="metrics-grid">
                    <Metric
                      label="Offene Risiken"
                      value={overview?.open_findings || 0}
                      icon="shield"
                      color="orange"
                      note={`${overview?.package_findings || 0} Pakettreffer · ${overview?.affected || 0} Risiken bestätigt`}
                    />
                    <Metric
                      label="Sofort handeln"
                      value={overview?.priorities.P0 || 0}
                      icon="bolt"
                      color="red"
                      note="Bestätigt betroffen · hohe Dringlichkeit"
                    />
                    <Metric
                      label="Bekannte Ausnutzung"
                      value={overview?.kev || 0}
                      icon="globe"
                      color="purple"
                      note="CISA KEV · offene Findings"
                    />
                    <Metric
                      label="Überwachte Systeme"
                      value={overview?.assets || 0}
                      icon="server"
                      color="green"
                      note={`${overview?.components || 0} aktive Komponenten`}
                    />
                  </div>
                  <div className="insight-row">
                    <div className="priority-overview">
                      <div className="section-top">
                        <span>Prioritäten im Überblick</span>
                        <span className="muted">{overview?.open_findings || 0} offen</span>
                      </div>
                      <div
                        className="priority-track"
                        aria-label="Verteilung offener Findings nach Priorität"
                      >
                        {['P0', 'P1', 'P2', 'P3'].map((value) => (
                          <button
                            key={value}
                            className={`track-${value}`}
                            disabled={!overview?.priorities[value]}
                            style={{ flex: overview?.priorities[value] || 0.12 }}
                            title={`${value}: ${overview?.priorities[value] || 0} Findings`}
                            onClick={() => {
                              setPriority(value)
                              setOffset(0)
                            }}
                          />
                        ))}
                      </div>
                      <div className="priority-legend">
                        {['P0', 'P1', 'P2', 'P3'].map((value) => (
                          <button
                            key={value}
                            onClick={() => {
                              setPriority(priority === value ? '' : value)
                              setOffset(0)
                            }}
                          >
                            <span className={`legend-dot dot-${value}`} />
                            {value}
                            <strong>{overview?.priorities[value] || 0}</strong>
                          </button>
                        ))}
                      </div>
                    </div>
                    <div className="sync-overview">
                      <div className="sync-icon">
                        <Icon name="refresh" size={22} />
                      </div>
                      <div>
                        <span className="section-top">
                          {config.demo ? 'Beispiel eines Datenabgleichs' : 'Letzter Datenabgleich'}
                        </span>
                        <strong>
                          {overview?.last_scan
                            ? dateTime(
                                overview.last_scan.completed_at || overview.last_scan.created_at,
                              )
                            : 'Noch kein Scan gestartet'}
                        </strong>
                        <span className="muted">
                          {overview?.last_scan
                            ? scanText[overview.last_scan.status]
                            : 'Inventar hinzufügen und ersten Abgleich starten'}
                        </span>
                      </div>
                      <button
                        className="icon-button"
                        aria-label="Scan-Aktivität ansehen"
                        onClick={() => go('activity')}
                      >
                        <Icon name="arrowUp" size={18} />
                      </button>
                    </div>
                  </div>
                  <section className="panel findings-panel">
                    <div className="panel-heading">
                      <div className="panel-title">
                        <h2>{findingView === 'risks' ? 'Risiken' : 'Pakettreffer'}</h2>
                        <span className="count-pill">{total}</span>
                      </div>
                      <button
                        className="button subtle small"
                        disabled={busy}
                        onClick={() =>
                          void action(async () => {
                            await downloadCsv(
                              exportMode === 'all'
                                ? new URLSearchParams({ view: 'packages' })
                                : findingParams(
                                    false,
                                    exportMode === 'current'
                                      ? findingView
                                      : (exportMode as 'risks' | 'packages'),
                                  ),
                            )
                            setToast('CSV für den gewählten Umfang exportiert.')
                          })
                        }
                      >
                        <Icon name="download" size={15} />
                        Exportieren
                      </button>
                    </div>
                    <div className="filters risk-controls">
                      <label>
                        Ansicht
                        <select
                          aria-label="Trefferansicht"
                          value={findingView}
                          onChange={(e) => {
                            setFindingView(e.target.value as 'risks' | 'packages')
                            setOffset(0)
                          }}
                        >
                          <option value="risks">Gruppierte Risiken</option>
                          <option value="packages">Einzelne Pakettreffer</option>
                        </select>
                      </label>
                      <label>
                        Komponententyp
                        <select
                          aria-label="Komponententyp filtern"
                          value={componentType}
                          onChange={(e) => {
                            setComponentType(e.target.value)
                            setOffset(0)
                          }}
                        >
                          <option value="">Alle Komponententypen</option>
                          {Object.entries(componentTypeText)
                            .filter(([value]) => value !== 'mixed')
                            .map(([value, label]) => (
                              <option key={value} value={value}>
                                {label}
                              </option>
                            ))}
                        </select>
                      </label>
                      <label>
                        Fixstatus
                        <select
                          aria-label="Fixstatus filtern"
                          value={patchStatus}
                          onChange={(e) => {
                            setPatchStatus(e.target.value)
                            setOffset(0)
                          }}
                        >
                          <option value="">Jeder Fixstatus</option>
                          {Object.entries(patchText).map(([value, label]) => (
                            <option key={value} value={value}>
                              {label}
                            </option>
                          ))}
                        </select>
                      </label>
                      <label>
                        CSV-Umfang
                        <select
                          aria-label="CSV-Umfang"
                          value={exportMode}
                          onChange={(e) => setExportMode(e.target.value)}
                        >
                          <option value="current">Aktuelle gefilterte Ansicht</option>
                          <option value="risks">Gefilterte Risiken</option>
                          <option value="packages">Gefilterte Paketdetails</option>
                          <option value="all">Alle Paketdetails ohne Filter</option>
                        </select>
                      </label>
                    </div>
                    <div className="filters">
                      <div className="search-field">
                        <Icon name="search" size={17} />
                        <input
                          aria-label="Findings durchsuchen"
                          value={search}
                          onChange={(e) => setSearch(e.target.value)}
                          placeholder="ID, Meldung oder System suchen …"
                        />
                      </div>
                      <select
                        aria-label="Priorität filtern"
                        value={priority}
                        onChange={(e) => {
                          setPriority(e.target.value)
                          setOffset(0)
                        }}
                      >
                        <option value="">Alle Prioritäten</option>
                        {['P0', 'P1', 'P2', 'P3', 'none'].map((value) => (
                          <option key={value} value={value}>
                            {value === 'none' ? 'Keine Priorität' : value}
                          </option>
                        ))}
                      </select>
                      <select
                        aria-label="Betroffenheit filtern"
                        value={status}
                        onChange={(e) => {
                          setStatus(e.target.value)
                          setOffset(0)
                        }}
                      >
                        <option value="">Jede Betroffenheit</option>
                        {Object.entries(statusText).map(([value, label]) => (
                          <option key={value} value={value}>
                            {label}
                          </option>
                        ))}
                      </select>
                      <select
                        aria-label="Bearbeitungsstatus filtern"
                        value={workflow}
                        onChange={(e) => {
                          setWorkflow(e.target.value)
                          setOffset(0)
                        }}
                      >
                        <option value="">Jeder Status</option>
                        {Object.entries(workflowText).map(([value, label]) => (
                          <option key={value} value={value}>
                            {label}
                          </option>
                        ))}
                      </select>
                      <select
                        aria-label="System filtern"
                        value={assetFilter}
                        onChange={(e) => {
                          setAssetFilter(e.target.value)
                          setOffset(0)
                        }}
                      >
                        <option value="">Alle Systeme</option>
                        {assets.map((asset) => (
                          <option key={asset.id} value={asset.id}>
                            {asset.name}
                          </option>
                        ))}
                      </select>
                      {hasFilters && (
                        <button className="text-button" onClick={resetFilters}>
                          Zurücksetzen
                        </button>
                      )}
                    </div>
                    {findings.length ? (
                      <div className="table-scroll">
                        <table className="findings-table">
                          <thead>
                            <tr>
                              <th>Priorität</th>
                              <th>Schwachstelle</th>
                              <th>System / Komponente</th>
                              <th>Betroffenheit</th>
                              <th>CVSS</th>
                              <th>Bearbeitung</th>
                              <th>
                                <span className="sr-only">Öffnen</span>
                              </th>
                            </tr>
                          </thead>
                          <tbody>
                            {findings.map((finding) => (
                              <tr key={finding.id}>
                                <td>
                                  <Priority value={finding.priority} />
                                </td>
                                <td>
                                  <button
                                    className="finding-link"
                                    onClick={() => setSelected(finding.id)}
                                  >
                                    <span className="mono alias">
                                      {finding.alias}
                                      {finding.kev && (
                                        <span className="kev-tag">
                                          <Icon name="bolt" size={11} />
                                          KEV
                                        </span>
                                      )}
                                    </span>
                                    <span className="finding-title">{finding.title}</span>
                                  </button>
                                </td>
                                <td>
                                  <span className="system-name">{finding.asset_name}</span>
                                  <span className="component-name mono">
                                    {finding.component.name}{' '}
                                    <span>{finding.component.version || 'Version fehlt'}</span>
                                  </span>
                                  <small className="risk-meta">
                                    {componentTypeText[finding.component_type] || 'Ungeklärt'} ·{' '}
                                    {patchText[finding.patch_status] || patchText.unknown}
                                  </small>
                                  {finding.context.kernel_status !== 'not_kernel' && (
                                    <small className="risk-meta">
                                      {kernelText[finding.context.kernel_status]}
                                      {finding.context.running_kernel &&
                                        ` · läuft: ${finding.context.running_kernel}`}
                                    </small>
                                  )}
                                  {!!finding.packages?.length && (
                                    <details className="risk-members">
                                      <summary>{finding.package_count} Pakettreffer</summary>
                                      <ul>
                                        {finding.packages.map((member) => (
                                          <li key={member.finding_id}>
                                            <strong>{member.name}</strong> {member.version}{' '}
                                            {member.architecture}
                                            <br />
                                            {componentTypeText[member.component_type]} ·{' '}
                                            {kernelText[member.kernel_status] ||
                                              statusText[member.status]}
                                          </li>
                                        ))}
                                      </ul>
                                    </details>
                                  )}
                                </td>
                                <td>
                                  <Badge status={finding.status} />
                                </td>
                                <td>
                                  <span
                                    className={`cvss-score ${(finding.cvss || 0) >= 9 ? 'critical' : ''}`}
                                  >
                                    {finding.cvss?.toFixed(1) || '–'}
                                  </span>
                                </td>
                                <td>
                                  <span className={`workflow workflow-${finding.workflow}`}>
                                    <span className="tiny-dot" />
                                    {finding.workflow === 'mixed'
                                      ? 'Gemischt'
                                      : workflowText[finding.workflow]}
                                  </span>
                                </td>
                                <td>
                                  <button
                                    className="icon-button row-open"
                                    onClick={() => setSelected(finding.id)}
                                    aria-label={`${finding.alias} öffnen`}
                                  >
                                    <Icon name="chevron" size={17} />
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <Empty
                        title={
                          hasFilters ? 'Keine passenden Findings' : 'Bereit für den ersten Abgleich'
                        }
                      >
                        {hasFilters
                          ? 'Passe die Suche oder die Filter an.'
                          : 'Lege ein System an, importiere sein Inventar und starte den Datenabgleich.'}
                        {!hasFilters && (
                          <button
                            className="button primary"
                            onClick={() => {
                              go('assets')
                              setAssetForm('new')
                            }}
                          >
                            System hinzufügen
                            <Icon name="plus" size={16} />
                          </button>
                        )}
                      </Empty>
                    )}
                    <div className="table-footer">
                      <span>
                        {total
                          ? `${offset + 1}–${Math.min(offset + 20, total)} von ${total} Findings`
                          : '0 Findings'}
                        <span className="footer-dot">·</span>
                        {hasFilters ? 'Gefilterte Ansicht' : 'Alle Betroffenheiten'}
                      </span>
                      <div className="pagination">
                        <button
                          className="icon-button"
                          disabled={offset === 0}
                          onClick={() => setOffset(Math.max(0, offset - 20))}
                          aria-label="Vorherige Seite"
                        >
                          <Icon name="chevron" style={{ transform: 'rotate(180deg)' }} size={16} />
                        </button>
                        <span>{Math.floor(offset / 20) + 1}</span>
                        <button
                          className="icon-button"
                          disabled={offset + 20 >= total}
                          onClick={() => setOffset(offset + 20)}
                          aria-label="Nächste Seite"
                        >
                          <Icon name="chevron" size={16} />
                        </button>
                      </div>
                    </div>
                  </section>
                  <div className="bottom-note">
                    <Icon name="info" size={15} />
                    <span>
                      Ein Finding ist ein Hinweis mit Belegen. Öffne die Details, um Matching,
                      Quellen und Handlungskontext zu prüfen.
                    </span>
                    <span className="source-count">5 Datenquellen · 1 Überblick</span>
                  </div>
                </>
              )}
              {page === 'assets' && (
                <>
                  <div className="inventory-summary">
                    <span>
                      <Icon name="server" /> <strong>{assets.length}</strong> Systeme
                    </span>
                    <span>
                      <Icon name="package" /> <strong>{overview?.components || 0}</strong>{' '}
                      Komponenten
                    </span>
                    <p>CycloneDX JSON oder CSV · bis zu 10.000 Komponenten pro Import</p>
                  </div>
                  {assets.length ? (
                    <div className="asset-grid">
                      {assets.map((asset) => (
                        <article className="asset-card" key={asset.id}>
                          <div className="asset-top">
                            <span className="asset-icon">
                              <Icon name="server" size={22} />
                            </span>
                            <span className={`environment env-${asset.environment}`}>
                              {asset.environment}
                            </span>
                            <button
                              className="icon-button"
                              aria-label={`${asset.name} bearbeiten`}
                              onClick={() => setAssetForm(asset)}
                            >
                              <Icon name="code" size={16} />
                            </button>
                          </div>
                          <h2>{asset.name}</h2>
                          <p>{asset.owner || 'Noch kein Verantwortlicher'}</p>
                          <div className="asset-tags">
                            <span>
                              <Icon
                                name={asset.exposure === 'internet' ? 'globe' : 'lock'}
                                size={13}
                              />
                              {
                                { internet: 'Internet', internal: 'Intern', isolated: 'Isoliert' }[
                                  asset.exposure
                                ]
                              }
                            </span>
                            <span>
                              Kritikalität:{' '}
                              {
                                { high: 'Hoch', medium: 'Mittel', low: 'Niedrig' }[
                                  asset.criticality
                                ]
                              }
                            </span>
                          </div>
                          <div className="asset-numbers">
                            <button onClick={() => setInventoryAsset(asset)}>
                              <strong>{asset.components}</strong>
                              <span>
                                Komponenten <Icon name="arrowUp" size={11} />
                              </span>
                            </button>
                            <button
                              onClick={() => {
                                setAssetFilter(asset.id)
                                setOffset(0)
                                go('findings')
                              }}
                            >
                              <strong className={asset.open_findings ? 'orange-text' : ''}>
                                {asset.open_findings}
                              </strong>
                              <span>
                                Offene Findings <Icon name="arrowUp" size={11} />
                              </span>
                            </button>
                          </div>
                          <button
                            className="button asset-import"
                            onClick={() => setImportAsset(asset.id)}
                          >
                            <Icon name="upload" size={15} />
                            Inventar importieren
                          </button>
                        </article>
                      ))}
                    </div>
                  ) : (
                    <section className="panel">
                      <Empty icon="server" title="Dein Inventar beginnt hier">
                        Füge dein erstes System hinzu. Erreichbarkeit und Kritikalität helfen später
                        bei der Priorisierung.
                      </Empty>
                    </section>
                  )}
                </>
              )}
              {page === 'agents' && (
                <Agents
                  assets={assets}
                  onRefresh={() => void refresh(true)}
                  onNavigateAssets={() => go('assets')}
                />
              )}
              {page === 'sources' && (
                <>
                  <div className="source-principle">
                    <div>
                      <Icon name="database" size={28} />
                    </div>
                    <p>
                      <strong>Jede Aussage hat eine Herkunft.</strong> Originaldaten, Abrufzeit,
                      Änderungsstand und SHA-256-Prüfsumme bleiben gespeichert. Widersprüche werden
                      zur Prüfung sichtbar.
                    </p>
                    <span className="badge status-not_affected">
                      <Icon name="check" size={13} />
                      Nachvollziehbar
                    </span>
                  </div>
                  <div className="source-grid">
                    {sourceInfo.map((source) => {
                      const state = overview?.last_scan?.result.sources?.[source.name]
                      return (
                        <article className="source-card" key={source.name}>
                          <div className="source-top">
                            <span className={`source-logo ${source.color}`}>{source.short}</span>
                            <a
                              href={source.url}
                              target="_blank"
                              rel="noreferrer"
                              aria-label={`${source.name} Website öffnen`}
                            >
                              <Icon name="arrowUp" size={18} />
                            </a>
                          </div>
                          <h2>{source.name}</h2>
                          <h3>{source.purpose}</h3>
                          <p>{source.detail}</p>
                          <div className="source-status">
                            <span className={`tiny-dot source-state-${state}`} />
                            {config.demo
                              ? 'Beispielquelle · keine Live-Daten'
                              : state === 'ok'
                                ? 'Letzter Abruf erfolgreich'
                                : state === 'skipped'
                                  ? 'Kein passender Abgleich nötig'
                                  : state === 'error' || state === 'partial'
                                    ? 'Abruf prüfen'
                                    : 'Noch nicht abgeglichen'}
                          </div>
                        </article>
                      )
                    })}
                  </div>
                  <div className="source-disclosure">
                    <Icon name="clock" size={18} />
                    <div>
                      <strong>Bekannte Meldungen werden erneut geprüft.</strong>
                      <p>
                        Der Worker gleicht das Inventar regelmäßig ab. Die Aktualität pro Quelle
                        findest du im Scan-Protokoll und in den Finding-Details.
                      </p>
                    </div>
                    <button className="text-button" onClick={() => go('activity')}>
                      Protokoll öffnen
                      <Icon name="arrow" size={15} />
                    </button>
                  </div>
                </>
              )}
              {page === 'activity' && (
                <section className="panel">
                  <div className="panel-heading">
                    <div className="panel-title">
                      <h2>Abgleich-Protokoll</h2>
                      <span className="count-pill">{scans.length}</span>
                    </div>
                    <button
                      className="button subtle small"
                      disabled={busy || running || config.demo}
                      onClick={() => void startScan(true)}
                      title="Quellen erneut abrufen und gespeicherte Retry-Ergebnisse verwerfen"
                    >
                      Vollständig neu abgleichen
                    </button>
                    <button className="button subtle small" onClick={() => void refresh(true)}>
                      <Icon name="refresh" size={15} />
                      Aktualisieren
                    </button>
                  </div>
                  <Operations />
                  {scans.length ? (
                    <div className="scan-list">
                      {scans.map((scan) => (
                        <details className="scan-item" key={scan.id}>
                          <summary>
                            <span className={`scan-icon scan-${scan.status}`}>
                              <Icon
                                name={
                                  scan.status === 'succeeded'
                                    ? 'check'
                                    : scan.status === 'failed' || scan.status === 'partial'
                                      ? 'warning'
                                      : 'refresh'
                                }
                                size={19}
                              />
                            </span>
                            <div>
                              <strong>
                                {scan.result.demo
                                  ? 'Demo-Datenabgleich'
                                  : 'Inventar & Schwachstellen abgleichen'}
                              </strong>
                              <span>
                                {dateTime(scan.created_at)} ·{' '}
                                {['queued', 'running'].includes(scan.status)
                                  ? `${phaseText[scan.progress?.phase || 'prepare'] || scan.progress?.phase}: ${scan.progress?.completed || 0}${scan.progress?.total != null ? ` / ${scan.progress.total}` : ''}`
                                  : `${scan.result.counts?.findings || 0} Pakettreffer geprüft`}
                              </span>
                            </div>
                            <span className={`scan-state scan-${scan.status}`}>
                              {scanText[scan.status]}
                            </span>
                            <Icon name="down" size={17} />
                          </summary>
                          <div className="scan-body">
                            <dl>
                              <dt>Letzte Aktivität</dt>
                              <dd>{dateTime(scan.progress?.updated_at || scan.heartbeat_at)}</dd>
                              <dt>Abrufe / wiederverwendet</dt>
                              <dd>
                                {scan.result.counts?.feed_requests || 0} /{' '}
                                {scan.result.counts?.cache_hits || 0}
                              </dd>
                              <dt>Scan-ID</dt>
                              <dd className="mono">{scan.id}</dd>
                              <dt>Abgeschlossen</dt>
                              <dd>{dateTime(scan.completed_at)}</dd>
                            </dl>
                            {!config.demo && (
                              <div className="scan-actions">
                                {['queued', 'running'].includes(scan.status) ? (
                                  <button
                                    className="button subtle small"
                                    disabled={busy || scan.cancel_requested}
                                    onClick={() =>
                                      void action(async () => {
                                        await api(`/scans/${scan.id}/cancel`, { method: 'POST' })
                                        await refresh(true)
                                      })
                                    }
                                  >
                                    {scan.cancel_requested ? 'Abbruch angefragt' : 'Scan abbrechen'}
                                  </button>
                                ) : (
                                  ['partial', 'failed', 'cancelled'].includes(scan.status) && (
                                    <button
                                      className="button subtle small"
                                      disabled={busy || running}
                                      onClick={() =>
                                        void action(async () => {
                                          await api(`/scans/${scan.id}/resume`, { method: 'POST' })
                                          await refresh(true)
                                        })
                                      }
                                    >
                                      Fortsetzen
                                    </button>
                                  )
                                )}
                              </div>
                            )}
                            <div className="source-state-list">
                              {Object.entries(scan.result.sources || {}).map(([name, state]) => (
                                <span key={name}>
                                  {name}
                                  <strong>
                                    {state === 'ok'
                                      ? 'Erfolgreich'
                                      : state === 'skipped'
                                        ? 'Nicht benötigt'
                                        : state === 'demo'
                                          ? 'Beispiel'
                                          : 'Prüfen'}
                                  </strong>
                                </span>
                              ))}
                            </div>
                            {scan.error && <p className="form-error">{scan.error}</p>}
                            {scan.result.errors?.map((value, index) => (
                              <p key={index} className="form-error">
                                {value}
                              </p>
                            ))}
                            {!scan.error && !scan.result.errors?.length && (
                              <p className="muted">
                                {scan.result.demo
                                  ? 'Dieses Protokoll gehört zum fiktiven Beispieldatensatz.'
                                  : 'Keine Fehler für diesen Scan gemeldet.'}
                              </p>
                            )}
                          </div>
                        </details>
                      ))}
                    </div>
                  ) : (
                    <Empty icon="activity" title="Noch keine Scans">
                      Starte einen Abgleich, sobald dein Inventar importiert ist. Hier erscheint das
                      Ergebnis jeder Quelle.
                    </Empty>
                  )}
                </section>
              )}
              {page === 'library' && <Library onToast={setToast} />}
            </>
          )}
          <footer className="main-footer">
            <span>
              myCVE<span> · </span>
              <a href="/license" target="_blank" rel="noreferrer">
                © 2026 Alexander Speka (DerAlex90) · Lizenz
              </a>
            </span>
            <span>
              <Icon name="lock" size={12} />
              Dein Workspace. Deine Kontrolle.
            </span>
          </footer>
        </main>
      </div>
      {toast && (
        <div className="toast" role="status">
          <Icon name="check" size={18} />
          {toast}
        </div>
      )}
      {selected && (
        <FindingPanel
          id={selected}
          grouped={findingView === 'risks'}
          onClose={() => setSelected(null)}
          onSaved={() => {
            void refresh(true)
            setToast('Finding aktualisiert.')
          }}
          onError={setError}
        />
      )}
      {assetForm && (
        <AssetForm
          asset={assetForm}
          onClose={() => setAssetForm(null)}
          onSaved={(id) => {
            setAssetForm(null)
            void refresh(true)
            setToast('System gespeichert.')
            if (assetForm === 'new') setImportAsset(id)
          }}
        />
      )}
      {importAsset && (
        <ImportForm
          assets={assets}
          assetId={importAsset}
          onClose={() => setImportAsset(null)}
          onSaved={(count) => {
            setImportAsset(null)
            void refresh(true)
            setToast(
              `${count} Komponenten importiert. Starte einen Abgleich für aktuelle Findings.`,
            )
          }}
        />
      )}
      {inventoryAsset && (
        <Inventory
          asset={inventoryAsset}
          onClose={() => setInventoryAsset(null)}
          onWatch={() => {
            void refresh(true)
            setToast('CVE wird beobachtet. Starte den Abgleich für aktuelle Quelldaten.')
          }}
        />
      )}
    </div>
  )
}

function Metric({
  label,
  value,
  icon,
  color,
  note,
}: {
  label: string
  value: number
  icon: string
  color: string
  note: string
}) {
  return (
    <article className={`metric metric-${color}`}>
      <div className="metric-top">
        <span>{label}</span>
        <span className={`metric-icon ${color}`}>
          <Icon name={icon} size={18} />
        </span>
      </div>
      <strong className="metric-value">{value.toLocaleString('de-DE')}</strong>
      <div className="metric-note">
        <span className={`tiny-dot ${color}`} />
        {note}
      </div>
    </article>
  )
}

function AssetForm({
  asset,
  onClose,
  onSaved,
}: {
  asset: Asset | 'new'
  onClose: () => void
  onSaved: (id: string) => void
}) {
  const [form, setForm] = useState(
    asset === 'new'
      ? {
          name: '',
          owner: '',
          environment: 'production',
          exposure: 'internal',
          criticality: 'medium',
        }
      : asset,
  )
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setBusy(true)
    try {
      const result = await api<Asset>(asset === 'new' ? '/assets' : `/assets/${asset.id}`, {
        method: asset === 'new' ? 'POST' : 'PUT',
        body: JSON.stringify({
          name: form.name,
          owner: form.owner,
          environment: form.environment,
          exposure: form.exposure,
          criticality: form.criticality,
        }),
      })
      onSaved(result.id)
    } catch (err) {
      setError(message(err))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal
      title={asset === 'new' ? 'System hinzufügen' : 'System bearbeiten'}
      subtitle="Kontext macht Prioritäten belastbar."
      onClose={onClose}
    >
      <form className="form-body" onSubmit={(event) => void submit(event)}>
        <label>
          Systemname
          <input
            value={form.name}
            required
            maxLength={200}
            placeholder="z. B. customer-api"
            onChange={(e) => setForm({ ...form, name: e.target.value })}
          />
        </label>
        <label>
          Verantwortlich
          <input
            value={form.owner}
            maxLength={200}
            placeholder="Team oder Verantwortlicher"
            onChange={(e) => setForm({ ...form, owner: e.target.value })}
          />
        </label>
        <div className="form-row">
          <label>
            Umgebung
            <select
              value={form.environment}
              onChange={(e) => setForm({ ...form, environment: e.target.value })}
            >
              <option value="production">Production</option>
              <option value="staging">Staging</option>
              <option value="development">Development</option>
            </select>
          </label>
          <label>
            Erreichbarkeit
            <select
              value={form.exposure}
              onChange={(e) => setForm({ ...form, exposure: e.target.value })}
            >
              <option value="internal">Intern</option>
              <option value="internet">Internet</option>
              <option value="isolated">Isoliert</option>
            </select>
          </label>
        </div>
        <label>
          Kritikalität
          <select
            value={form.criticality}
            onChange={(e) => setForm({ ...form, criticality: e.target.value })}
          >
            <option value="high">Hoch</option>
            <option value="medium">Mittel</option>
            <option value="low">Niedrig</option>
          </select>
        </label>
        <div className="form-hint">
          <Icon name="info" size={17} />
          Änderungen an Erreichbarkeit und Kritikalität bewerten bestehende Findings erneut.
        </div>
        {error && (
          <div className="form-error" role="alert">
            {error}
          </div>
        )}
        <div className="form-actions">
          <button type="button" className="button" onClick={onClose}>
            Abbrechen
          </button>
          <button className="button primary" disabled={busy}>
            {busy ? 'Speichert …' : 'System speichern'}
            <Icon name="check" size={16} />
          </button>
        </div>
      </form>
    </Modal>
  )
}

function ImportForm({
  assets,
  assetId,
  onClose,
  onSaved,
}: {
  assets: Asset[]
  assetId: string
  onClose: () => void
  onSaved: (count: number) => void
}) {
  const [file, setFile] = useState<File | null>(null)
  const [replace, setReplace] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const submit = async (event: FormEvent) => {
    event.preventDefault()
    if (!file) return
    setBusy(true)
    try {
      const data = new FormData()
      data.append('file', file)
      const result = await api<{ imported: number }>(
        `/assets/${assetId}/import?replace=${replace}`,
        { method: 'POST', body: data },
      )
      onSaved(result.imported)
    } catch (err) {
      setError(message(err))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal
      title="Inventar importieren"
      subtitle={assets.find((asset) => asset.id === assetId)?.name || 'Neues System'}
      onClose={onClose}
    >
      <form className="form-body" onSubmit={(event) => void submit(event)}>
        <label className="upload-area">
          <Icon name="upload" size={30} />
          <strong>{file ? file.name : 'SBOM oder CSV auswählen'}</strong>
          <span>CycloneDX JSON 1.4–1.7 oder CSV · max. 10 MB</span>
          <input
            aria-label="Inventardatei auswählen"
            type="file"
            accept=".json,.csv"
            required
            onChange={(e) => setFile(e.target.files?.[0] || null)}
          />
        </label>
        <div className="csv-example">
          <span>CSV-Spalten</span>
          <code>name,version,ecosystem,purl,cpe,vendor,platform,ref</code>
          <small>name ist erforderlich. Eine fehlende Version bleibt ungeklärt.</small>
        </div>
        <label className="checkbox-label">
          <input type="checkbox" checked={replace} onChange={(e) => setReplace(e.target.checked)} />
          <span>
            <strong>Aktuelles Inventar ersetzen</strong>
            <small>
              Fehlende Komponenten werden inaktiv. Ihre Findings bleiben in der Historie.
            </small>
          </span>
        </label>
        {error && (
          <div className="form-error" role="alert">
            {error}
          </div>
        )}
        <div className="form-actions">
          <button type="button" className="button" onClick={onClose}>
            Abbrechen
          </button>
          <button className="button primary" disabled={busy || !file}>
            {busy ? 'Importiert …' : 'Inventar importieren'}
            <Icon name="upload" size={16} />
          </button>
        </div>
      </form>
    </Modal>
  )
}

function Inventory({
  asset,
  onClose,
  onWatch,
}: {
  asset: Asset
  onClose: () => void
  onWatch: () => void
}) {
  const [items, setItems] = useState<Component[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [error, setError] = useState('')
  const [selected, setSelected] = useState('')
  const [cve, setCve] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    api<{ items: Component[]; total: number }>(
      `/assets/${asset.id}/components?limit=100&offset=${offset}`,
    )
      .then((result) => {
        setItems(result.items)
        setTotal(result.total)
        setSelected(result.items[0]?.id || '')
      })
      .catch((err) => setError(message(err)))
  }, [asset.id, offset])
  const watch = async (event: FormEvent) => {
    event.preventDefault()
    setBusy(true)
    try {
      await api('/watches', {
        method: 'POST',
        body: JSON.stringify({ installation_id: selected, cve_id: cve.trim().toUpperCase() }),
      })
      setCve('')
      onWatch()
      setError('')
    } catch (err) {
      setError(message(err))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal title="Installierte Komponenten" subtitle={asset.name} onClose={onClose}>
      <div className="form-body">
        <div className="component-list">
          {items.map((item, index) => (
            <div key={item.id || index}>
              <span>
                <strong>{item.inventory?.name || item.name}</strong>
                <small>
                  {item.inventory
                    ? `${item.inventory.architecture || ''} · ${item.origin?.split(':').at(-1) || ''}`
                    : item.ecosystem || 'Ökosystem ungeklärt'}
                </small>
                {item.inventory?.source_name && (
                  <small>
                    Abgleich: {item.name} {item.version}
                  </small>
                )}
                {item.context && (
                  <small>
                    {componentTypeText[item.context.component_type]}
                    {item.context.kernel_status !== 'not_kernel' &&
                      ` · ${kernelText[item.context.kernel_status]}`}
                    {item.context.running_kernel &&
                      ` · laufender Kernel: ${item.context.running_kernel}`}
                  </small>
                )}
                {item.identification?.status && (
                  <small>
                    Automatische Zuordnung: {item.identification.reason}
                    {item.identification.checked_at &&
                      ` · ${dateTime(item.identification.checked_at)}`}
                  </small>
                )}
                {(item.cpe || item.identification?.ecosystem) && (
                  <small>{item.cpe || item.identification?.ecosystem}</small>
                )}
                {item.identification?.url && (
                  <small>
                    <a href={item.identification.url} target="_blank" rel="noreferrer">
                      Produktquelle ansehen
                    </a>
                  </small>
                )}
                {item.inventory?.version_source && (
                  <small>Versionsquelle: {item.inventory.version_source}</small>
                )}
              </span>
              <code>{item.inventory?.version || item.version || 'Version fehlt'}</code>
            </div>
          ))}
        </div>
        {!items.length && <p className="muted">Noch keine Komponenten importiert.</p>}
        <div className="pagination">
          <button
            className="button small"
            disabled={!offset}
            onClick={() => setOffset(Math.max(0, offset - 100))}
          >
            Zurück
          </button>
          <span>{total} Komponenten</span>
          <button
            className="button small"
            disabled={offset + 100 >= total}
            onClick={() => setOffset(offset + 100)}
          >
            Weiter
          </button>
        </div>
        {items.length > 0 && (
          <form className="watch-form" onSubmit={(event) => void watch(event)}>
            <h3>CVE gezielt beobachten</h3>
            <p>
              Eine Beobachtung startet ungeklärt, bis belastbare Produkt- und Versionsdaten
              vorliegen.
            </p>
            <label>
              Komponente
              <select value={selected} onChange={(e) => setSelected(e.target.value)}>
                {items.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name} {item.version}
                  </option>
                ))}
              </select>
            </label>
            <label>
              CVE-ID
              <input
                placeholder="CVE-2024-12345"
                pattern="CVE-[0-9]{4}-[0-9]{4,}"
                value={cve}
                required
                onChange={(e) => setCve(e.target.value.toUpperCase())}
              />
            </label>
            <button className="button primary" disabled={busy}>
              CVE beobachten
              <Icon name="plus" size={16} />
            </button>
          </form>
        )}
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
      </div>
    </Modal>
  )
}

function FindingPanel({
  id,
  grouped,
  onClose,
  onSaved,
  onError,
}: {
  id: string
  grouped: boolean
  onClose: () => void
  onSaved: () => void
  onError: (error: string) => void
}) {
  const [detail, setDetail] = useState<FindingDetail | null>(null)
  const [tab, setTab] = useState('context')
  const [notes, setNotes] = useState('')
  const [workflow, setWorkflow] = useState('open')
  const [busy, setBusy] = useState(false)
  const [raw, setRaw] = useState('')
  const [error, setError] = useState('')
  const load = useCallback(async () => {
    try {
      const data = await api<FindingDetail>(`/findings/${id}`)
      setDetail(data)
      setNotes(data.notes)
      setWorkflow(data.workflow)
      setError('')
    } catch (err) {
      setError(message(err))
    }
  }, [id])
  useEffect(() => {
    void load()
  }, [load])
  const save = async () => {
    setBusy(true)
    try {
      await api(`/findings/${id}?grouped=${grouped}`, {
        method: 'PATCH',
        body: JSON.stringify({ workflow, notes }),
      })
      await load()
      onSaved()
    } catch (err) {
      onError(message(err))
      setError(message(err))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal
      title={detail?.alias || 'Finding wird geladen …'}
      subtitle="Nachvollziehbar entscheiden."
      onClose={onClose}
    >
      {error && (
        <p className="form-error detail-error" role="alert">
          {error}
        </p>
      )}
      {detail && (
        <div className="finding-detail">
          <div className="detail-summary">
            <div className="detail-badges">
              <Priority value={detail.priority} />
              <Badge status={detail.status} />
              {detail.kev && (
                <span className="kev-tag">
                  <Icon name="bolt" size={12} />
                  Bekannte Ausnutzung
                </span>
              )}
            </div>
            <h2>{detail.title}</h2>
            <p>
              {patchText[detail.patch_status]} · {componentTypeText[detail.component_type]}
            </p>
            {grouped && (detail.package_count || 0) > 1 && (
              <p>
                Bearbeitungsstatus und Notizen gelten beim Speichern für alle {detail.package_count}{' '}
                Pakettreffer dieses Risikos.
              </p>
            )}
            <p className="detail-system">
              <Icon name="server" size={16} />
              {detail.asset_name}
              <span> / </span>
              <code>
                {detail.component.name} {detail.component.version || '(Version fehlt)'}
              </code>
            </p>
          </div>
          <div className="detail-tabs" role="tablist">
            {[
              ['context', 'Bewertung'],
              ['sources', `Quellen (${detail.sources.length})`],
              ['history', 'Verlauf'],
            ].map(([value, label]) => (
              <button
                role="tab"
                aria-selected={tab === value}
                className={tab === value ? 'active' : ''}
                key={value}
                onClick={() => setTab(value)}
              >
                {label}
              </button>
            ))}
          </div>
          {tab === 'context' && (
            <div className="detail-body">
              <div className={`match-explanation match-${detail.status}`}>
                <Icon
                  name={
                    detail.status === 'unknown'
                      ? 'info'
                      : detail.status === 'affected'
                        ? 'warning'
                        : 'check'
                  }
                  size={20}
                />
                <div>
                  <strong>{statusText[detail.status]}</strong>
                  <p>{detail.reason}</p>
                </div>
              </div>
              <h3>Warum diese Priorität?</h3>
              <div className="reason-list">
                {detail.priority_reasons.map((reason) => (
                  <span key={reason}>
                    <Icon name="check" size={14} />
                    {reason}
                  </span>
                ))}
              </div>
              <div className="detail-numbers">
                <div>
                  <span>Technische Schwere</span>
                  <strong>
                    {detail.cvss?.toFixed(1) || '–'}
                    <small>CVSS</small>
                  </strong>
                </div>
                <div>
                  <span>Kontextbasierte Bewertung</span>
                  <strong>
                    {detail.priority_score}
                    <small>/ 100</small>
                  </strong>
                </div>
              </div>
              {detail.description && (
                <>
                  <h3>Beschreibung</h3>
                  <p className="description-text">{detail.description}</p>
                </>
              )}
              {detail.fixed_versions.length > 0 && (
                <>
                  <h3>Veröffentlichte Fix-Versionen</h3>
                  <div className="fix-versions">
                    {detail.fixed_versions.map((value) => (
                      <code key={value}>{value}</code>
                    ))}
                  </div>
                  <p className="muted">Den passenden Versionszweig vor dem Update prüfen.</p>
                </>
              )}
              {detail.kev_due_date && (
                <p className="form-hint">
                  KEV-Quellenfrist: {detail.kev_due_date}. Die Frist gilt im jeweiligen
                  CISA-Regelungskontext.
                </p>
              )}
              <div className="workflow-edit">
                <h3>Bearbeitung</h3>
                <label>
                  Status
                  <select value={workflow} onChange={(e) => setWorkflow(e.target.value)}>
                    {Object.entries(workflowText).map(([value, label]) => (
                      <option key={value} value={value}>
                        {label}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Notizen
                  <textarea
                    rows={3}
                    maxLength={10000}
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    placeholder="Nächster Schritt, Verantwortliche oder Entscheidungsgrundlage …"
                  />
                </label>
                <p className="muted">
                  Der Bearbeitungsstatus dokumentiert deine Entscheidung. Die ermittelte
                  Betroffenheit bleibt separat sichtbar.
                </p>
                <button className="button primary" disabled={busy} onClick={() => void save()}>
                  {busy ? 'Speichert …' : 'Änderungen speichern'}
                  <Icon name="check" size={16} />
                </button>
              </div>
              <div className="detail-timestamp">
                <Icon name="clock" size={14} />
                Zuletzt bewertet: {dateTime(detail.evaluated_at)}
              </div>
            </div>
          )}
          {tab === 'sources' && (
            <div className="detail-body">
              <h3>Matching-Belege</h3>
              {detail.evidence.map((item, index) => (
                <div className="evidence-item" key={index}>
                  <div>
                    <strong>{item.source}</strong>
                    <Badge status={item.status} />
                  </div>
                  <p>{item.reason}</p>
                </div>
              ))}
              {!detail.evidence.length && (
                <p className="muted">Noch keine belastbaren Matching-Belege vorhanden.</p>
              )}
              <h3>Gespeicherte Quelldokumente</h3>
              {detail.sources.map((source) => (
                <div className="source-record" key={source.id}>
                  <div>
                    <strong>{source.source}</strong>
                    <span className={`revision-label ${source.current ? 'current' : ''}`}>
                      {source.current ? 'Aktuell' : 'Frühere Fassung'}
                    </span>
                  </div>
                  <dl>
                    <dt>Abruf</dt>
                    <dd>{dateTime(source.last_seen_at)}</dd>
                    <dt>Quelländerung</dt>
                    <dd>{dateTime(source.source_modified)}</dd>
                    <dt>SHA-256</dt>
                    <dd className="checksum mono">{source.checksum}</dd>
                  </dl>
                  <div className="source-record-actions">
                    <a href={safeUrl(source.url)} target="_blank" rel="noreferrer">
                      Original öffnen
                      <Icon name="arrowUp" size={13} />
                    </a>
                    <button
                      className="text-button"
                      onClick={() => {
                        void api<{ payload: unknown }>(`/sources/${source.id}`)
                          .then((result) => setRaw(JSON.stringify(result.payload, null, 2)))
                          .catch((err) => setError(message(err)))
                      }}
                    >
                      Rohdaten anzeigen
                      <Icon name="code" size={14} />
                    </button>
                  </div>
                </div>
              ))}
              {raw && (
                <div className="raw-data">
                  <div>
                    <strong>Originaldaten</strong>
                    <button
                      className="icon-button"
                      onClick={() => setRaw('')}
                      aria-label="Rohdaten schließen"
                    >
                      <Icon name="close" size={15} />
                    </button>
                  </div>
                  <pre>{raw}</pre>
                </div>
              )}
            </div>
          )}
          {tab === 'history' && (
            <div className="detail-body">
              <div className="timeline">
                {detail.history.map((event) => (
                  <div className="timeline-item" key={event.id}>
                    <span className="timeline-dot" />
                    <div>
                      <strong>
                        {{
                          created: 'Finding erstellt',
                          reevaluated: 'Erneut bewertet',
                          workflow_updated: 'Bearbeitung aktualisiert',
                        }[event.action] || event.action}
                      </strong>
                      <span>{dateTime(event.created_at)}</span>
                      <p>
                        {statusText[event.after.status]} · {event.after.priority} ·{' '}
                        {workflowText[event.after.workflow]}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </Modal>
  )
}

function Library({ onToast }: { onToast: (text: string) => void }) {
  const example = `from mycve import Component, match_osv, prioritize\n\ncomponent = Component(\n    name="example-http",\n    ecosystem="PyPI",\n    version="2.4.1",\n)\n\n# advisory: ein vollständiges OSV-JSON-Dokument\nresult = match_osv(component, advisory)\npriority = prioritize(\n    result.status, kev=True, cvss=9.8,\n    exposure="internet", criticality="high",\n)\n\nprint(result.status, result.reason)\nprint(priority.level, priority.reasons)`
  return (
    <>
      <div className="library-hero">
        <div>
          <span className="library-chip">
            <Icon name="code" size={14} />
            PYTHON · NAMENSNENNUNGSPFLICHT
          </span>
          <h2>
            Nachvollziehbares Matching.
            <br />
            Überall einsetzbar.
          </h2>
          <p>
            Eine kleine, eigenständige Bibliothek für deine CI-Pipeline, eigene Werkzeuge oder den
            vollständigen myCVE-Tracker.
          </p>
          <a
            className="button primary"
            href="https://github.com/DerAlex90/myCVE"
            target="_blank"
            rel="noreferrer"
          >
            Repository öffnen
            <Icon name="arrowUp" size={16} />
          </a>
        </div>
        <div className="library-emblem">
          <Icon name="shield" size={110} />
          <span>myCVE</span>
          <small>EXPLAINABLE BY DESIGN</small>
        </div>
      </div>
      <div className="library-columns">
        <section className="panel code-panel">
          <div className="panel-heading">
            <h2>Einfach integrieren</h2>
            <button
              className="text-button"
              onClick={() => {
                void navigator.clipboard
                  .writeText(example)
                  .then(() => onToast('Python-Beispiel kopiert.'))
                  .catch(() => onToast('Kopieren nicht verfügbar. Markiere das Beispiel direkt.'))
              }}
            >
              Kopieren
              <Icon name="code" size={14} />
            </button>
          </div>
          <pre className="code-example">
            <code>{example}</code>
          </pre>
        </section>
        <div className="library-features">
          {[
            [
              'package',
              'Identität vor Namensähnlichkeit',
              'Paketökosystem, PURL und Version bestimmen den Abgleich. Ein ähnlicher Name bestätigt keine Betroffenheit.',
            ],
            [
              'activity',
              'Versionen im richtigen Kontext',
              'Eigene Vergleiche für Python, SemVer, Go, Maven, NuGet, RubyGems, Debian und RPM. Unbekannte Formate bleiben ungeklärt.',
            ],
            [
              'shield',
              'Entscheidungen mit Begründung',
              'Betroffenheit, Priorität, Gründe und veröffentlichte Fix-Versionen als strukturierte Ergebnisse.',
            ],
          ].map(([icon, title, text]) => (
            <article key={title}>
              <span>
                <Icon name={icon} size={21} />
              </span>
              <div>
                <h3>{title}</h3>
                <p>{text}</p>
              </div>
            </article>
          ))}
          <div className="install-command">
            <span>Aus dem geklonten Repository installieren</span>
            <code>pip install .</code>
            <span>Mit API und Hintergrundjobs</span>
            <code>pip install '.[server]'</code>
          </div>
        </div>
      </div>
    </>
  )
}
