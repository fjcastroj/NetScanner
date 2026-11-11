/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Francisco Javier Castro Jiménez
 * Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
 * Computer Engineering, Universidad Internacional de La Rioja (UNIR).
 */

// Component tests of task 7.3 (web-ui spec). The API is a fetch stub with lab
// values only.
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { I18nextProvider } from 'react-i18next'
import { MemoryRouter } from 'react-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { Value } from './api'
import { AppRoutes } from './App'
import { createI18n } from './i18n'
import en from './locales/en.json'
import es from './locales/es.json'
import { uptimeParts } from './pages/DevicePage'
import { Provenance } from './Provenance'

type Reply = { status?: number; body: unknown } | ((init?: RequestInit) => { status?: number; body: unknown })
type Calls = { url: string; init?: RequestInit }[]

// Logged in: the session check answers, as do health and status.
const DEFAULTS: Record<string, Reply> = {
  'GET /api/health': { body: { status: 'ok' } },
  'GET /api/auth/session': { body: { username: 'lab-admin', expires_at: '2026-11-11T10:00:00+00:00' } },
  'GET /api/status': { body: { authentication: true, admin_exists: true } },
}

function stubApi(routes: Record<string, Reply>): Calls {
  const calls: Calls = []
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string, init?: RequestInit) => {
      calls.push({ url, init })
      const key = `${init?.method ?? 'GET'} ${url.split('?')[0]}`
      const route = routes[key] ?? DEFAULTS[key]
      if (route === undefined) return Promise.resolve(new Response('{}', { status: 404 }))
      const { status = 200, body } = typeof route === 'function' ? route(init) : route
      return Promise.resolve(new Response(JSON.stringify(body), { status }))
    }),
  )
  return calls
}

async function renderAt(path: string, language = 'es') {
  localStorage.setItem('netscanner.language', language)
  render(
    <I18nextProvider i18n={createI18n()}>
      <MemoryRouter initialEntries={[path]}>
        <AppRoutes />
      </MemoryRouter>
    </I18nextProvider>,
  )
  await act(async () => {})
}

const SETTINGS = {
  seeds: ['10.99.0.13'],
  allowed_ranges: ['10.99.0.0/24'],
  exclusions: [],
  max_depth: 1,
  follow_ip_mac: false,
  max_candidates: 4096,
  max_devices: 256,
  max_datagrams: 50000,
  updated_at: '2026-11-08T10:00:00+00:00',
  ceilings: { max_depth: 5, max_candidates: 4096, max_devices: 256, max_datagrams: 50000 },
  lab_ranges: ['10.99.0.0/24'],
}
const CREDENTIAL = {
  configured: true,
  version: 'v2c',
  user: null,
  level: null,
  auth_protocol: null,
  priv_protocol: null,
  updated_at: '2026-11-08T10:00:00+00:00',
  usable: true,
}
const EMPTY_PAGE = { total: 0, limit: 100, offset: 0, items: [] }

function value(v: unknown, extra: Partial<Value> = {}): Value {
  return {
    value: v,
    state: 'value',
    origin: 'observed',
    method: null,
    source: 'SNMPv2-MIB::system',
    query_id: 1,
    run_id: 1,
    seen_at: '2026-11-08T10:00:00+00:00',
    age_seconds: 120,
    stale: false,
    ...extra,
  }
}

const INFERRED_MODEL = value('srx1500', {
  origin: 'inferred',
  method: 'juniper-sysdescr-pattern',
  evidence: {
    inputs: [
      { kind: 'query', id: 1 },
      {
        table: 'devices',
        snapshot: {
          model_fragment: 'Juniper Networks, Inc. srx1500 internet router',
          version_fragment: 'kernel JUNOS 19.4R3.11',
        },
      },
    ],
  },
})

beforeEach(() => localStorage.clear())
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

describe('header with the session', () => {
  const routes = {
    'GET /api/settings/discovery': { body: SETTINGS },
    'GET /api/settings/credential': { body: CREDENTIAL },
    'GET /api/runs': { body: EMPTY_PAGE },
    'GET /api/devices': { body: EMPTY_PAGE },
    'GET /api/devices/1': { status: 404, body: { detail: 'device not found' } },
  }

  for (const [language, texts] of [
    ['es', es],
    ['en', en],
  ] as const) {
    for (const path of ['/settings', '/discovery', '/devices', '/devices/1']) {
      it(`shows the user and logout on ${path} in ${language}, and no lab banner`, async () => {
        stubApi(routes)
        await renderAt(path, language)
        expect(screen.getByLabelText(texts.session.user).textContent).toBe('lab-admin')
        expect(screen.getByRole('button', { name: texts.session.logout })).toBeTruthy()
        expect(screen.queryByRole('note')).toBeNull()
        expect(document.body.textContent).not.toMatch(/laboratorio sin autenticación|lab mode/i)
      })
    }
  }
})

describe('settings screen', () => {
  it('shows the stored credential without filling any secret field', async () => {
    stubApi({
      'GET /api/settings/discovery': { body: SETTINGS },
      'GET /api/settings/credential': { body: CREDENTIAL },
    })
    await renderAt('/settings', 'en')
    expect(screen.getByText(/A credential is configured: version v2c/)).toBeTruthy()
    const community = screen.getByLabelText(en.credential.community) as HTMLInputElement
    expect(community.type).toBe('password')
    expect(community.value).toBe('')
    fireEvent.change(screen.getByLabelText(en.credential.version), { target: { value: '3' } })
    for (const label of [en.credential.auth_key, en.credential.priv_key]) {
      const input = screen.getByLabelText(label) as HTMLInputElement
      expect(input.type).toBe('password')
      expect(input.value).toBe('')
    }
  })

  it('clears the secret field after sending it', async () => {
    const calls = stubApi({
      'GET /api/settings/discovery': { body: SETTINGS },
      'GET /api/settings/credential': { body: { ...CREDENTIAL, configured: false } },
      'PUT /api/settings/credential': { body: CREDENTIAL },
    })
    await renderAt('/settings', 'en')
    const community = screen.getByLabelText(en.credential.community) as HTMLInputElement
    fireEvent.change(community, { target: { value: 'lab-community-x1' } })
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: en.credential.save }))
    })
    const put = calls.find((c) => c.init?.method === 'PUT')
    expect(JSON.parse(String(put?.init?.body))).toEqual({ version: '2c', community: 'lab-community-x1' })
    expect(community.value).toBe('')
    expect(document.body.textContent).not.toContain('lab-community-x1')
  })

  it('shows each validation reason next to its field', async () => {
    stubApi({
      'GET /api/settings/discovery': { body: SETTINGS },
      'GET /api/settings/credential': { body: CREDENTIAL },
      'PUT /api/settings/discovery': {
        status: 422,
        body: {
          detail: [
            { field: 'seeds.0', reason: 'seed is out of scope' },
            { field: 'max_depth', reason: "above the server's ceiling of 5" },
          ],
        },
      },
    })
    await renderAt('/settings', 'en')
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: en.settings.save }))
    })
    const seeds = screen.getByLabelText(en.settings.seeds)
    expect(seeds.getAttribute('aria-invalid')).toBe('true')
    const seedError = document.getElementById(seeds.getAttribute('aria-describedby') ?? '')
    expect(seedError?.textContent).toBe('line 1: seed is out of scope')
    expect(seeds.parentElement?.contains(seedError)).toBe(true)
    const depth = screen.getByLabelText(en.settings.max_depth)
    const depthError = document.getElementById(depth.getAttribute('aria-describedby') ?? '')
    expect(depthError?.textContent).toBe("above the server's ceiling of 5")
    expect(depth.parentElement?.contains(depthError)).toBe(true)
  })
})

describe('discovery screen', () => {
  const running = {
    id: 7,
    kind: 'discovery',
    status: 'running',
    requested_at: '2026-11-08T10:00:00+00:00',
    started_at: '2026-11-08T10:00:01+00:00',
    finished_at: null,
    error_category: null,
    summary: null,
    progress: {
      candidates: 3, reached_by: { seed: 3 }, devices: 1, new_devices: 1, without_answer: 0,
      reasons: { no_response: 1 }, queries: 12,
    },
  }

  it('disables the start button and refreshes every 2 s while a run is active', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: false })
    let detailCalls = 0
    stubApi({
      'GET /api/runs': { body: { total: 1, limit: 20, offset: 0, items: [running] } },
      'GET /api/runs/7': () => {
        detailCalls += 1
        return { body: { ...running, progress: { ...running.progress, queries: 12 * detailCalls } } }
      },
    })
    await renderAt('/discovery', 'en')
    await act(async () => {})
    const button = screen.getByRole('button', { name: en.discovery.start }) as HTMLButtonElement
    expect(button.disabled).toBe(true)
    expect(screen.getByTestId('count-queries').textContent).toBe('12')
    expect(screen.getByText('No response: 1')).toBeTruthy()
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2_000)
    })
    expect(screen.getByTestId('count-queries').textContent).toBe('24')
    expect(button.disabled).toBe(true)
  })

  it('enables the start button when no run is active', async () => {
    stubApi({
      'GET /api/runs': {
        body: { total: 1, limit: 20, offset: 0, items: [{ ...running, status: 'completed' }] },
      },
      'GET /api/runs/7': { body: { ...running, status: 'completed', finished_at: '2026-11-08T10:01:00+00:00' } },
    })
    await renderAt('/discovery', 'en')
    await act(async () => {})
    const button = screen.getByRole('button', { name: en.discovery.start }) as HTMLButtonElement
    expect(button.disabled).toBe(false)
  })
})

describe('provenance', () => {
  function renderValue(v: Value) {
    render(
      <I18nextProvider i18n={createI18n()}>
        <Provenance value={v} />
      </I18nextProvider>,
    )
  }

  it('marks an inferred value and shows method and evidence fragments on demand', () => {
    localStorage.setItem('netscanner.language', 'en')
    renderValue(INFERRED_MODEL)
    expect(screen.getByText(en.provenance.inferred)).toBeTruthy()
    const details = screen.getByText(en.provenance.details).closest('details') as HTMLDetailsElement
    expect(details.open).toBe(false) // on demand
    fireEvent.click(screen.getByText(en.provenance.details))
    expect(within(details).getByText('juniper-sysdescr-pattern')).toBeTruthy()
    expect(within(details).getByText('Juniper Networks, Inc. srx1500 internet router')).toBeTruthy()
    expect(within(details).getByText('kernel JUNOS 19.4R3.11')).toBeTruthy()
    expect(screen.getByText('2 minutes ago')).toBeTruthy()
  })

  it('marks a stale value with its last seen time', () => {
    localStorage.setItem('netscanner.language', 'es')
    renderValue(value('ge-0/0/1', { stale: true, age_seconds: 10 * 86_400, seen_at: '2026-10-29T10:00:00+00:00' }))
    expect(screen.getByText(es.provenance.observed)).toBeTruthy()
    const stale = screen.getByText(/^obsoleto, visto por última vez/)
    expect(stale.textContent).toContain(new Date('2026-10-29T10:00:00+00:00').toLocaleString('es'))
    expect(screen.getByText('hace 10 días')).toBeTruthy()
  })

  it('shows an inferred model in the device detail', async () => {
    stubApi({
      'GET /api/devices/1': {
        body: {
          id: 1,
          groups: {
            system: { first_seen_at: '', last_seen_at: '', stale: false, presence: 'present', source: 'SNMPv2-MIB::system', fields: { sys_name: value('srx-01') } },
            chassis: null,
            vendor: null,
            model: { first_seen_at: '', last_seen_at: '', stale: false, presence: 'present', source: 'SNMPv2-MIB::system', fields: { model: INFERRED_MODEL } },
          },
          addresses: [],
          interfaces: [],
        },
      },
    })
    await renderAt('/devices/1', 'en')
    const cell = document.querySelector('[data-field="model"]') as HTMLElement
    expect(cell.textContent).toContain('srx1500')
    expect(within(cell).getByText(en.provenance.inferred)).toBeTruthy()
  })
})

describe('fixes on the settings and device screens', () => {
  it('says that seeds are single IP addresses, and ranges keep their own help', async () => {
    for (const [language, texts] of [
      ['es', es],
      ['en', en],
    ] as const) {
      stubApi({
        'GET /api/settings/discovery': { body: SETTINGS },
        'GET /api/settings/credential': { body: CREDENTIAL },
      })
      await renderAt('/settings', language)
      const seeds = screen.getByLabelText(texts.settings.seeds)
      expect(seeds.parentElement?.textContent).toContain(texts.settings.seeds_help)
      expect(seeds.parentElement?.textContent).not.toContain(texts.settings.one_per_line)
      const ranges = screen.getByLabelText(texts.settings.allowed_ranges)
      expect(ranges.parentElement?.textContent).toContain(texts.settings.one_per_line)
      cleanup()
      vi.unstubAllGlobals()
    }
  })

  it('splits sysUpTime hundredths of a second into days, hours and minutes', () => {
    expect(uptimeParts(3818839757)).toEqual({ days: 441, hours: 23, minutes: 53 })
    expect(uptimeParts(0)).toEqual({ days: 0, hours: 0, minutes: 0 })
    expect(uptimeParts(8_640_000 + 360_000 + 6_000 - 1)).toEqual({ days: 1, hours: 1, minutes: 0 })
  })

  function deviceWith(status: string) {
    const group = (source: string, fields: Record<string, Value>) => ({
      first_seen_at: '', last_seen_at: '', stale: false, presence: 'present', source, fields,
    })
    return {
      id: 1,
      groups: {
        system: group('SNMPv2-MIB::system', { sys_name: value('srx-01'), sys_uptime: value(3818839757) }),
        chassis: null,
        vendor: group('SNMPv2-MIB::system', {
          vendor_name: value('Juniper', { origin: 'inferred', method: 'enterprise-registry' }),
          vendor_status: value(status, { origin: 'inferred', method: 'enterprise-registry' }),
        }),
        model: null,
      },
      addresses: [],
      interfaces: [],
    }
  }

  for (const [language, texts] of [
    ['es', es],
    ['en', en],
  ] as const) {
    for (const status of ['known', 'generic_agent', 'not_in_registry'] as const) {
      it(`translates vendor status ${status} in ${language} and keeps the raw value in the details`, async () => {
        stubApi({ 'GET /api/devices/1': { body: deviceWith(status) } })
        await renderAt('/devices/1', language)
        const cell = document.querySelector('[data-field="vendor_status"]') as HTMLElement
        const details = cell.querySelector('details') as HTMLDetailsElement
        const shown = cell.textContent!.replace(details.textContent!, '')
        expect(shown).toContain(texts.vendor_status[status])
        expect(shown).not.toContain(status)
        expect(within(details).getByText(texts.provenance.raw)).toBeTruthy()
        expect(within(details).getByText(status)).toBeTruthy()
      })
    }

    it(`shows sysUpTime as days, hours and minutes in ${language}, raw value in the details`, async () => {
      stubApi({ 'GET /api/devices/1': { body: deviceWith('known') } })
      await renderAt('/devices/1', language)
      const cell = document.querySelector('[data-field="sys_uptime"]') as HTMLElement
      const details = cell.querySelector('details') as HTMLDetailsElement
      const shown = cell.textContent!.replace(details.textContent!, '')
      expect(shown).toContain('441 d 23 h 53 min')
      expect(shown).not.toContain('3818839757')
      expect(within(details).getByText('3818839757')).toBeTruthy()
      expect(screen.getByText(texts.fields.sys_uptime)).toBeTruthy()
    })
  }
})
