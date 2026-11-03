import { expect, test } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'

test('filter, inspect evidence, update workflow and export', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', (error) => errors.push(error.message))
  await page.goto('/')
  await expect(
    page.getByRole('heading', { name: 'Sicherheitsübersicht', exact: true }),
  ).toBeVisible()
  await expect(
    page.getByText('Alle Systeme, Meldungen und Ausnutzungssignale sind fiktive Beispieldaten.', {
      exact: false,
    }),
  ).toBeVisible()
  await page.getByRole('combobox', { name: 'Priorität filtern' }).selectOption('P0')
  await expect(page.getByRole('table').getByRole('row')).toHaveCount(2)
  await page.getByRole('button', { name: 'DEMO-2026-0001 KEV', exact: false }).first().click()
  const dialog = page.getByRole('dialog')
  await expect(dialog.getByRole('heading', { name: 'Warum diese Priorität?' })).toBeVisible()
  await dialog.getByRole('tab', { name: 'Quellen (1)' }).click()
  await expect(dialog.getByText('SHA-256', { exact: true })).toBeVisible()
  await dialog.getByRole('button', { name: 'Rohdaten anzeigen' }).click()
  await expect(dialog.locator('pre')).toContainText('mycve_demo')
  await dialog.getByRole('tab', { name: 'Bewertung', exact: true }).click()
  await dialog.getByRole('combobox', { name: 'Status', exact: true }).selectOption('in_progress')
  await dialog.getByLabel('Notizen').fill('Browser test: Wartungsfenster geplant')
  await dialog.getByRole('button', { name: 'Änderungen speichern' }).click()
  await expect(page.getByRole('status')).toContainText('Finding aktualisiert')
  await dialog.getByRole('tab', { name: 'Verlauf' }).click()
  await expect(dialog.getByText('Bearbeitung aktualisiert').first()).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(dialog).not.toBeVisible()
  const download = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Exportieren' }).click()
  expect((await download).suggestedFilename()).toBe('mycve-findings.csv')
  expect(errors).toEqual([])
})

test('create system, import inventory and create a CVE watch', async ({ page }) => {
  await page.goto('/#assets')
  await page.getByRole('button', { name: 'System hinzufügen', exact: true }).click()
  let dialog = page.getByRole('dialog')
  await dialog.getByLabel('Systemname').fill(`browser-test-${Date.now()}`)
  await dialog.getByLabel('Verantwortlich').fill('Test team')
  await dialog.getByRole('button', { name: 'System speichern' }).click()
  dialog = page.getByRole('dialog')
  await expect(dialog.getByRole('heading', { name: 'Inventar importieren' })).toBeVisible()
  await dialog.getByLabel('Inventardatei auswählen').setInputFiles({
    name: 'inventory.csv',
    mimeType: 'text/csv',
    buffer: Buffer.from('name,version,ecosystem,ref\nexample-package,1.0.0,PyPI,test-ref\n'),
  })
  await dialog.getByRole('button', { name: 'Inventar importieren', exact: true }).click()
  await expect(page.getByRole('status')).toContainText('1 Komponenten importiert')
  const card = page
    .locator('.asset-card')
    .filter({ has: page.getByRole('heading', { name: /^browser-test-/ }) })
    .last()
  await card.getByRole('button', { name: '1 Komponenten' }).click()
  dialog = page.getByRole('dialog')
  await expect(dialog.getByText('example-package', { exact: true })).toBeVisible()
  await dialog.getByLabel('CVE-ID').fill('CVE-2024-12345')
  await dialog.getByRole('button', { name: 'CVE beobachten' }).click()
  await expect(page.getByRole('status')).toContainText('CVE wird beobachtet')
})

test('mobile navigation, layout and keyboard close', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('/')
  await expect(page.getByRole('table')).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  )
  await page.getByRole('button', { name: 'Navigation öffnen' }).click()
  await page.getByRole('button', { name: 'Datenquellen', exact: true }).click()
  await expect(
    page.getByRole('heading', { name: 'Verlässliche Daten. Klare Herkunft.' }),
  ).toBeVisible()
  await expect(page.getByRole('heading', { name: 'BSI CSAF', exact: true })).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  )
})

test('workspace pages meet automated WCAG AA checks', async ({ page }) => {
  await page.route('**/api/agents/downloads', (route) =>
    route.fulfill({
      json: [
        { name: 'mycve-agent-linux-amd64.tar.gz', bytes: 3_000_000 },
        { name: 'mycve-agent-linux-arm64.tar.gz', bytes: 2_800_000 },
        { name: 'mycve-agent-windows-amd64.zip', bytes: 3_200_000 },
        { name: 'mycve-agent-windows-arm64.zip', bytes: 2_900_000 },
        { name: 'SHA256SUMS', bytes: 400 },
      ],
    }),
  )
  await page.goto('/')
  await expect(page.getByRole('table')).toBeVisible()
  for (const name of [
    'Übersicht',
    'Systeme & Inventar',
    'Inventar-Agenten',
    'Datenquellen',
    'Aktivität',
    'Python-Bibliothek',
  ]) {
    await page
      .getByRole('navigation', { name: 'Hauptnavigation' })
      .getByRole('button', { name })
      .click()
    if (name === 'Inventar-Agenten')
      await expect(page.locator('.agent-download').first()).toBeVisible()
    const result = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
      .analyze()
    expect(result.violations, name).toEqual([])
  }
})

test('login meets automated WCAG AA checks', async ({ page }) => {
  await page.route('**/api/config', (route) =>
    route.fulfill({ json: { authentication_required: true, demo: false, version: '0.4.0' } }),
  )
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Workspace öffnen' })).toBeVisible()
  const result = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
    .analyze()
  expect(result.violations).toEqual([])
})

test('background updates appear automatically and a connection error clears on recovery', async ({
  page,
}) => {
  await page.clock.install()
  let phase: 'initial' | 'offline' | 'updated' = 'initial'
  await page.route('**/api/overview', async (route) => {
    if (phase === 'offline') {
      await route.fulfill({
        status: 503,
        json: { detail: 'Verbindung vorübergehend unterbrochen' },
      })
      return
    }
    const response = await route.fetch()
    const overview = await response.json()
    if (phase === 'updated') overview.assets = 37
    await route.fulfill({ response, json: overview })
  })
  await page.goto('/')
  await expect(page.getByRole('table')).toBeVisible()
  phase = 'offline'
  await page.clock.fastForward(16000)
  await expect(page.getByRole('alert')).toContainText('Verbindung vorübergehend unterbrochen')
  phase = 'updated'
  await page.clock.fastForward(16000)
  const systems = page.locator('.metric').filter({ hasText: 'Überwachte Systeme' })
  await expect(systems.locator('.metric-value')).toHaveText('37')
  await expect(page.getByRole('alert')).toHaveCount(0)
})

test('author credit links to the governing public license', async ({ page }) => {
  await page.goto('/')
  const credit = page.getByRole('link', { name: '© 2026 Alexander Speka (DerAlex90) · Lizenz' })
  await expect(credit).toBeVisible()
  await expect(credit).toHaveAttribute('href', '/license')
  const response = await page.request.get('/license')
  expect(response.ok()).toBe(true)
  expect(await response.text()).toContain('LicenseRef-myCVE-Attribution-1.0')
})

test('register data sender, receive inventory, inspect changes and revoke access', async ({
  page,
}) => {
  await page.goto('/#assets')
  await page.getByRole('button', { name: 'System hinzufügen', exact: true }).click()
  let dialog = page.getByRole('dialog')
  const name = `agent-browser-${Date.now()}`
  await dialog.getByLabel('Systemname').fill(name)
  await dialog.getByRole('button', { name: 'System speichern' }).click()
  await expect(page.getByRole('heading', { name: 'Inventar importieren' })).toBeVisible()
  await page.getByRole('button', { name: 'Schließen', exact: true }).click()
  await page.getByRole('button', { name: 'Inventar-Agenten', exact: true }).click()
  await page.getByRole('button', { name: 'Agent registrieren' }).click()
  dialog = page.getByRole('dialog')
  await dialog.getByRole('combobox', { name: 'System', exact: true }).selectOption({ label: name })
  const created = page.waitForResponse(
    (response) => response.url().endsWith('/api/agents') && response.request().method() === 'POST',
  )
  await dialog.getByRole('button', { name: 'Agent anlegen' }).click()
  const registration = await (await created).json()
  dialog = page.getByRole('dialog')
  await expect(dialog.getByRole('heading', { name: 'Gerätekonfiguration sichern' })).toBeVisible()
  await dialog.getByRole('checkbox').check()
  const download = page.waitForEvent('download')
  await dialog.getByRole('button', { name: 'Konfiguration herunterladen' }).click()
  expect((await download).suggestedFilename()).toBe('mycve-agent-config.json')
  await page.getByRole('button', { name: 'Schließen', exact: true }).click()
  const response = await page.request.post('/api/agent/inventory', {
    headers: { Authorization: `Bearer ${registration.configuration.token}` },
    data: {
      schema_version: 1,
      snapshot_id: '11111111-1111-4111-8111-111111111111',
      device_id: '22222222-2222-4222-8222-222222222222',
      collected_at: new Date().toISOString(),
      agent_version: '0.2.0',
      host: { hostname: 'example-linux', os: 'linux', architecture: 'amd64' },
      collectors: [
        {
          id: 'dpkg',
          complete: true,
          packages: [{ id: 'example', name: 'example-agent-package', version: '1.0' }],
        },
      ],
    },
  })
  expect(response.status()).toBe(200)
  await page.getByRole('button', { name: 'Aktualisieren', exact: true }).click()
  const card = page
    .locator('.agent-row')
    .filter({ has: page.getByRole('heading', { name, exact: true }) })
  await expect(card.getByText('Meldet sich', { exact: true })).toBeVisible()
  await expect(card.getByText('example-linux', { exact: false })).toBeVisible()
  await card.getByRole('button', { name: 'Berichte & Änderungen' }).click()
  dialog = page.getByRole('dialog')
  await dialog.locator('.snapshot-row').first().click()
  await expect(dialog.getByText('example-agent-package', { exact: true })).toBeVisible()
  await page.keyboard.press('Escape')
  await card.getByRole('button', { name: 'Zugriff widerrufen' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Zugriff widerrufen' }).click()
  await expect(card.getByText('Widerrufen', { exact: true })).toBeVisible()
})
