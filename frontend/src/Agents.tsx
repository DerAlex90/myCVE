import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { api, dateTime, downloadFile, type Asset } from './api'
import { Icon } from './Icon'
import { Modal } from './Modal'
import './agents.css'

type Agent = {
  id: string
  asset_id: string
  asset_name: string
  status: string
  token_suffix: string
  device_id: string | null
  agent_version: string
  last_seen_at: string | null
  last_inventory_at: string | null
  last_collected_at: string | null
  last_error: string | null
  host: Record<string, string>
  packages: number
  scan_pending: boolean
  incomplete_packages: number
  collectors: { id: string; complete: boolean; error: string | null; packages: number }[]
}
type AgentConfig = {
  server_url: string
  agent_id: string
  token: string
  interval_seconds: number
  allow_insecure_localhost: boolean
}
type Provision = { agent: Agent; configuration: AgentConfig }
type Snapshot = {
  id: string
  report_id: string
  collected_at: string
  received_at: string
  checksum: string
  partial: boolean
  changes: Record<string, number>
}
type SnapshotDetail = {
  payload: { host: Record<string, string>; collectors: unknown[] }
  changes: {
    kind: string
    before: { name: string; version?: string } | null
    after: { name: string; version?: string } | null
  }[]
}
const statusText: Record<string, string> = {
  online: 'Meldet sich',
  stale: 'Kontakt überfällig',
  never_seen: 'Noch nicht verbunden',
  revoked: 'Widerrufen',
}
const errorText = (error: unknown) =>
  error instanceof Error ? error.message : 'Aktion fehlgeschlagen'

function saveConfig(config: AgentConfig, name: string) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(config, null, 2) + '\n'], { type: 'application/json' }),
  )
  const link = document.createElement('a')
  link.href = url
  link.download = name
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export function Agents({
  assets,
  onRefresh,
  onNavigateAssets,
}: {
  assets: Asset[]
  onRefresh: () => void
  onNavigateAssets: () => void
}) {
  const [agents, setAgents] = useState<Agent[]>([])
  const [downloads, setDownloads] = useState<{ name: string; bytes: number }[]>([])
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [create, setCreate] = useState(false)
  const [assetId, setAssetId] = useState('')
  const [provision, setProvision] = useState<Provision | null>(null)
  const [serverURL, setServerURL] = useState(location.origin)
  const [localHTTP, setLocalHTTP] = useState(false)
  const [selected, setSelected] = useState<Agent | null>(null)
  const [revoke, setRevoke] = useState<Agent | null>(null)
  const [renew, setRenew] = useState<Agent | null>(null)
  const [resetDevice, setResetDevice] = useState(false)
  const load = useCallback(async () => {
    try {
      const [data, files] = await Promise.all([
        api<Agent[]>('/agents'),
        api<{ name: string; bytes: number }[]>('/agents/downloads'),
      ])
      setAgents(data)
      setDownloads(files)
    } catch (error) {
      setError(errorText(error))
    }
  }, [])
  useEffect(() => {
    void load()
    const timer = setInterval(() => void load(), 15000)
    return () => clearInterval(timer)
  }, [load])
  const act = async (fn: () => Promise<void>) => {
    setBusy(true)
    setError('')
    try {
      await fn()
    } catch (error) {
      setError(errorText(error))
    } finally {
      setBusy(false)
    }
  }
  const available = assets.filter((asset) => !agents.some((agent) => agent.asset_id === asset.id))
  const issue = async (event: FormEvent) => {
    event.preventDefault()
    await act(async () => {
      const result = await api<Provision>('/agents', {
        method: 'POST',
        body: JSON.stringify({ asset_id: assetId }),
      })
      setProvision(result)
      setCreate(false)
      setLocalHTTP(false)
      await load()
      onRefresh()
    })
  }
  const downloadConfiguration = () => {
    if (!provision) return
    let parsed: URL
    try {
      parsed = new URL(serverURL)
    } catch {
      setError('Gültige HTTPS-Serveradresse eingeben.')
      return
    }
    const local = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname)
    if (parsed.protocol !== 'https:' && !(local && parsed.protocol === 'http:' && localHTTP)) {
      setError(
        'HTTPS verwenden oder HTTP für einen lokalen Loopback-Server ausdrücklich freigeben.',
      )
      return
    }
    if (parsed.username || parsed.password || parsed.search || parsed.hash) {
      setError('Serveradresse ohne Zugangsdaten, Suchparameter und Fragment verwenden.')
      return
    }
    saveConfig(
      {
        ...provision.configuration,
        server_url: serverURL.replace(/\/$/, ''),
        allow_insecure_localhost: localHTTP,
      },
      'mycve-agent-config.json',
    )
    setMessage('Gerätekonfiguration heruntergeladen. Diese Datei enthält den einmaligen Schlüssel.')
  }
  return (
    <>
      {error && (
        <div className="error-banner" role="alert">
          <Icon name="warning" size={17} />
          <span>{error}</span>
          <button
            className="icon-button"
            aria-label="Fehlermeldung schließen"
            onClick={() => setError('')}
          >
            <Icon name="close" size={16} />
          </button>
        </div>
      )}
      {message && (
        <div className="agent-message" role="status">
          <Icon name="check" size={16} />
          {message}
        </div>
      )}
      <section className="agent-intro">
        <div className="agent-intro-icon">
          <Icon name="globe" size={26} />
        </div>
        <div>
          <h2>Ein Dienst pro Gerät. Ein aktuelles Inventar.</h2>
          <p>
            Der Go-Agent erfasst Betriebssystem und Pakete. Jeder Schlüssel darf ausschließlich das
            Inventar seines Systems übermitteln. Unvollständige Berichte entfernen keine bisherigen
            Einträge.
          </p>
        </div>
        <button
          className="button primary"
          onClick={() => {
            setAssetId(available[0]?.id || '')
            setCreate(true)
          }}
          disabled={busy}
        >
          <Icon name="plus" size={16} />
          Agent registrieren
        </button>
      </section>
      <section className="panel agent-panel">
        <div className="panel-heading">
          <div className="panel-title">
            <h2>Verbundene Geräte</h2>
            <span className="count-pill">{agents.length}</span>
          </div>
          <button
            className="button subtle small"
            onClick={() => {
              void load()
              onRefresh()
            }}
          >
            <Icon name="refresh" size={15} />
            Aktualisieren
          </button>
        </div>
        {agents.length ? (
          <div className="agent-list">
            {agents.map((agent) => (
              <article className="agent-row" key={agent.id}>
                <div className="agent-row-heading">
                  <span className="asset-icon">
                    <Icon name="server" size={20} />
                  </span>
                  <div>
                    <h3>{agent.asset_name}</h3>
                    <p>
                      {agent.host.hostname || 'Wartet auf den ersten Bericht'}
                      {agent.host.os && ` · ${agent.host.os} ${agent.host.architecture}`}
                    </p>
                  </div>
                  <span className={`agent-state agent-${agent.status}`}>
                    {statusText[agent.status]}
                  </span>
                </div>
                <div className="agent-facts">
                  <span>
                    <strong>{agent.packages}</strong> Pakete
                  </span>
                  <span>
                    Letzter Kontakt<strong>{dateTime(agent.last_seen_at)}</strong>
                  </span>
                  <span>
                    Inventar erfasst<strong>{dateTime(agent.last_collected_at)}</strong>
                  </span>
                  <span>
                    Version<strong>{agent.agent_version || '–'}</strong>
                  </span>
                </div>
                {agent.host.name && (
                  <p className="agent-os">
                    {agent.host.name} {agent.host.build || agent.host.version} · {agent.host.kernel}
                  </p>
                )}
                {agent.last_error && <p className="form-error">{agent.last_error}</p>}
                {agent.incomplete_packages > 0 && (
                  <p className="agent-pending">
                    <Icon name="info" size={14} />
                    {agent.incomplete_packages} Pakete benötigen für den CVE-Abgleich eine
                    eindeutige Kennung oder Version.
                  </p>
                )}
                {agent.scan_pending && (
                  <p className="agent-pending">
                    <Icon name="clock" size={13} />
                    Neues Inventar wartet auf den nächsten CVE-Abgleich.
                  </p>
                )}
                <div className="agent-row-actions">
                  <button className="text-button" onClick={() => setSelected(agent)}>
                    Berichte & Änderungen
                    <Icon name="arrow" size={14} />
                  </button>
                  <button
                    className="text-button"
                    onClick={() => {
                      setRenew(agent)
                      setResetDevice(false)
                    }}
                  >
                    Schlüssel erneuern
                  </button>
                  {agent.status !== 'revoked' && (
                    <button className="text-button revoke-button" onClick={() => setRevoke(agent)}>
                      Zugriff widerrufen
                    </button>
                  )}
                </div>
              </article>
            ))}
          </div>
        ) : (
          <div className="empty">
            <div className="empty-icon">
              <Icon name="globe" size={28} />
            </div>
            <h3>Bereit für automatische Erfassung</h3>
            <p>
              Lege ein System an und registriere seinen Agenten. Lade dann Programm und
              Gerätekonfiguration auf den zugehörigen Rechner.
            </p>
            <button className="button" onClick={onNavigateAssets}>
              Systeme öffnen
              <Icon name="arrow" size={16} />
            </button>
          </div>
        )}
      </section>
      <section className="panel agent-downloads">
        <div className="panel-heading">
          <h2>Agent herunterladen</h2>
          <span className="muted">Linux · Windows · amd64 / arm64</span>
        </div>
        {downloads.length ? (
          <div className="agent-download-grid">
            {downloads.map((file) => (
              <button
                key={file.name}
                className="agent-download"
                disabled={busy}
                onClick={() =>
                  void act(async () => {
                    await downloadFile(`/agents/downloads/${file.name}`, file.name)
                  })
                }
              >
                <Icon name="download" size={18} />
                <span>
                  <strong>{file.name}</strong>
                  <small>{(file.bytes / 1024 / 1024).toFixed(1)} MB</small>
                </span>
              </button>
            ))}
          </div>
        ) : (
          <p className="agent-build-hint">
            Agent-Pakete sind in diesem Entwicklungsserver noch nicht gebaut. Der
            Docker-Produktionsbuild erstellt die Downloads automatisch.
          </p>
        )}
        <div className="agent-install-note">
          <Icon name="info" size={17} />
          <p>
            Linux: Paket entpacken, dann{' '}
            <code>sudo ./install.sh /pfad/mycve-agent-config.json</code>. Windows:{' '}
            <code>.\Install.ps1 -ConfigPath C:\Pfad\mycve-agent-config.json</code> als Administrator
            ausführen. Zunächst kann <code>mycve-agent once --config …</code> die Verbindung prüfen.
          </p>
        </div>
      </section>
      {create && (
        <Modal
          title="Agent registrieren"
          subtitle="Ein Schlüssel für genau ein System."
          onClose={() => setCreate(false)}
        >
          <form className="form-body" onSubmit={(event) => void issue(event)}>
            {available.length ? (
              <>
                <label>
                  System
                  <select
                    value={assetId}
                    required
                    onChange={(event) => setAssetId(event.target.value)}
                  >
                    {available.map((asset) => (
                      <option key={asset.id} value={asset.id}>
                        {asset.name}
                      </option>
                    ))}
                  </select>
                </label>
                <p className="form-hint">
                  Die Konfiguration enthält einen einmalig ausgegebenen Geräteschlüssel. Den
                  Workspace-API-Schlüssel benötigt der Agent nicht.
                </p>
                <div className="form-actions">
                  <button type="button" className="button" onClick={() => setCreate(false)}>
                    Abbrechen
                  </button>
                  <button className="button primary" disabled={busy}>
                    Agent anlegen
                    <Icon name="check" size={16} />
                  </button>
                </div>
              </>
            ) : (
              <>
                <p className="muted">
                  Alle vorhandenen Systeme besitzen bereits einen Agenten oder es wurde noch kein
                  System angelegt. Bestehende Schlüssel lassen sich direkt beim Agenten erneuern.
                </p>
                <button
                  className="button primary"
                  type="button"
                  onClick={() => {
                    setCreate(false)
                    onNavigateAssets()
                  }}
                >
                  Systeme öffnen
                </button>
              </>
            )}
          </form>
        </Modal>
      )}
      {provision && (
        <Modal
          title="Gerätekonfiguration sichern"
          subtitle={provision.agent.asset_name}
          onClose={() => setProvision(null)}
        >
          <div className="form-body">
            <p className="form-hint">
              Der Schlüssel wird nur jetzt ausgegeben. Sichere die Konfigurationsdatei für dieses
              Gerät. Bei Verlust lässt sich ein neuer Schlüssel ausstellen.
            </p>
            <label>
              Serveradresse
              <input
                type="url"
                value={serverURL}
                onChange={(event) => setServerURL(event.target.value)}
                required
              />
            </label>
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={localHTTP}
                onChange={(event) => setLocalHTTP(event.target.checked)}
              />
              <span>
                <strong>HTTP ausschließlich für einen Loopback-Server zulassen</strong>
                <small>Für entfernte Geräte ist HTTPS erforderlich.</small>
              </span>
            </label>
            {error && (
              <p className="form-error" role="alert">
                {error}
              </p>
            )}
            <button className="button primary" onClick={downloadConfiguration}>
              <Icon name="download" size={16} />
              Konfiguration herunterladen
            </button>
            <p className="muted">
              Der Agent legt seine Geräte-ID beim ersten Lauf im geschützten Zustandsverzeichnis an.
              Konfiguration und Zustandsverzeichnis nicht auf weitere Geräte klonen.
            </p>
          </div>
        </Modal>
      )}
      {revoke && (
        <Modal
          title="Agent-Zugriff widerrufen"
          subtitle={revoke.asset_name}
          onClose={() => setRevoke(null)}
        >
          <div className="form-body">
            <p>
              Der bisherige Schlüssel wird sofort ungültig. Gespeicherte Pakete und Berichte bleiben
              erhalten.
            </p>
            <div className="form-actions">
              <button className="button" onClick={() => setRevoke(null)}>
                Abbrechen
              </button>
              <button
                className="button primary"
                disabled={busy}
                onClick={() =>
                  void act(async () => {
                    await api(`/agents/${revoke.id}`, { method: 'DELETE' })
                    setRevoke(null)
                    setMessage('Agent-Schlüssel widerrufen.')
                    await load()
                  })
                }
              >
                Zugriff widerrufen
              </button>
            </div>
          </div>
        </Modal>
      )}
      {renew && (
        <Modal
          title="Schlüssel erneuern"
          subtitle={renew.asset_name}
          onClose={() => setRenew(null)}
        >
          <div className="form-body">
            <p>
              Der bisherige Schlüssel wird sofort ungültig. Die neue Konfiguration muss auf dem
              Gerät hinterlegt werden.
            </p>
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={resetDevice}
                onChange={(event) => setResetDevice(event.target.checked)}
              />
              <span>
                <strong>Gerätebindung zurücksetzen</strong>
                <small>
                  Für eine Neuinstallation mit neuer lokaler Geräte-ID. Der nächste Bericht bindet
                  den Schlüssel erneut.
                </small>
              </span>
            </label>
            <div className="form-actions">
              <button className="button" onClick={() => setRenew(null)}>
                Abbrechen
              </button>
              <button
                className="button primary"
                disabled={busy}
                onClick={() =>
                  void act(async () => {
                    const result = await api<Provision>(
                      `/agents/${renew.id}/rotate-token?reset_device=${resetDevice}`,
                      { method: 'POST' },
                    )
                    setRenew(null)
                    setProvision(result)
                    setLocalHTTP(false)
                    await load()
                  })
                }
              >
                Neuen Schlüssel erzeugen
              </button>
            </div>
          </div>
        </Modal>
      )}
      {selected && <Reports agent={selected} onClose={() => setSelected(null)} />}
    </>
  )
}

function Reports({ agent, onClose }: { agent: Agent; onClose: () => void }) {
  const [snapshots, setSnapshots] = useState<Snapshot[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [detail, setDetail] = useState<SnapshotDetail | null>(null)
  const [error, setError] = useState('')
  useEffect(() => {
    api<{ items: Snapshot[]; total: number }>(`/agents/${agent.id}/snapshots?offset=${offset}`)
      .then((data) => {
        setSnapshots(data.items)
        setTotal(data.total)
      })
      .catch((error) => setError(errorText(error)))
  }, [agent.id, offset])
  return (
    <Modal title="Inventarberichte & Änderungen" subtitle={agent.asset_name} onClose={onClose}>
      <div className="form-body">
        {agent.host.os && (
          <div className="agent-host-details">
            <strong>{agent.host.hostname}</strong>
            <span>
              {agent.host.name} {agent.host.version} {agent.host.build}
            </span>
            <span>
              {agent.host.architecture} · {agent.host.kernel}
            </span>
          </div>
        )}
        <div className="source-state-list">
          {agent.collectors.map((source) => (
            <span key={source.id}>
              {source.id}
              <strong>{source.complete ? `${source.packages} Pakete` : 'Unvollständig'}</strong>
            </span>
          ))}
        </div>
        {snapshots.map((snapshot) => (
          <button
            key={snapshot.id}
            className="snapshot-row"
            onClick={() => {
              void api<SnapshotDetail>(`/agents/${agent.id}/snapshots/${snapshot.id}`)
                .then(setDetail)
                .catch((error) => setError(errorText(error)))
            }}
          >
            <span>
              <strong>{dateTime(snapshot.collected_at)}</strong>
              <small>{snapshot.partial ? 'Teilweise erfasst' : 'Vollständig erfasst'}</small>
            </span>
            <span className="snapshot-counts">
              +{snapshot.changes.added} · ↻{snapshot.changes.updated} · −{snapshot.changes.removed}
            </span>
            <Icon name="chevron" size={16} />
          </button>
        ))}
        {!snapshots.length && <p className="muted">Noch keine Inventarberichte eingegangen.</p>}
        <div className="pagination">
          <button
            className="button small"
            disabled={!offset}
            onClick={() => setOffset(Math.max(0, offset - 20))}
          >
            Zurück
          </button>
          <span>{total} Berichte</span>
          <button
            className="button small"
            disabled={offset + 20 >= total}
            onClick={() => setOffset(offset + 20)}
          >
            Weiter
          </button>
        </div>
        {detail && (
          <section className="snapshot-detail">
            <h3>Paketänderungen</h3>
            {detail.changes.slice(0, 100).map((change, index) => (
              <div key={index}>
                <span className={`change-${change.kind}`}>
                  {
                    { added: 'Hinzugefügt', updated: 'Aktualisiert', removed: 'Entfernt' }[
                      change.kind
                    ]
                  }
                </span>
                <strong>{change.after?.name || change.before?.name}</strong>
                <code>
                  {change.before?.version || '–'} → {change.after?.version || '–'}
                </code>
              </div>
            ))}
            {!detail.changes.length && (
              <p className="muted">Keine Paketänderungen in diesem Bericht.</p>
            )}
            {detail.changes.length > 100 && (
              <p className="muted">Die ersten 100 Änderungen werden angezeigt.</p>
            )}
          </section>
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
