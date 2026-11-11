/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Francisco Javier Castro Jiménez
 * Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
 * Computer Engineering, Universidad Internacional de La Rioja (UNIR).
 */

// Component tests of task 6.3 of add-admin-authentication (web-ui spec): login,
// session expiry and logout. The API is a fetch stub with lab values only.
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { useEffect } from 'react'
import { I18nextProvider } from 'react-i18next'
import { MemoryRouter, useNavigate } from 'react-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { AppRoutes } from './App'
import { createI18n } from './i18n'
import en from './locales/en.json'
import es from './locales/es.json'

type Answer = { status?: number; body: unknown; headers?: Record<string, string> }
type Handler = (init?: RequestInit) => Answer
type Call = { url: string; init?: RequestInit }

const SESSION = { username: 'lab-admin', expires_at: '2026-11-11T10:00:00+00:00' }
const NO_SESSION: Answer = { status: 401, body: { detail: 'authentication required' } }
const PAGE = { total: 0, limit: 100, offset: 0, items: [] }
const DEVICE = {
  id: 1,
  groups: {
    system: {
      first_seen_at: '', last_seen_at: '', stale: false, presence: 'present', source: 'SNMPv2-MIB::system',
      fields: { sys_name: { value: 'lab-sw-01', state: 'value', origin: 'observed', age_seconds: 5 } },
    },
    chassis: null,
    vendor: null,
    model: null,
  },
  addresses: [],
  interfaces: [],
}

function stub(routes: Record<string, Handler>): Call[] {
  const calls: Call[] = []
  const defaults: Record<string, Handler> = {
    'GET /api/health': () => ({ body: { status: 'ok' } }),
    'GET /api/status': () => ({ body: { authentication: true, admin_exists: true } }),
  }
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string, init?: RequestInit) => {
      calls.push({ url, init })
      const handler = routes[`${init?.method ?? 'GET'} ${url.split('?')[0]}`] ?? defaults[`GET ${url}`]
      if (!handler) return Promise.resolve(new Response('{}', { status: 404 }))
      const { status = 200, body, headers } = handler(init)
      return Promise.resolve(new Response(JSON.stringify(body), { status, headers }))
    }),
  )
  return calls
}

let goBack: () => void = () => {}

function History() {
  const navigate = useNavigate()
  useEffect(() => {
    goBack = () => void navigate(-1)
  }, [navigate])
  return null
}

async function renderAt(entries: string[], language: string) {
  localStorage.setItem('netscanner.language', language)
  render(
    <I18nextProvider i18n={createI18n()}>
      <MemoryRouter initialEntries={entries} initialIndex={entries.length - 1}>
        <History />
        <AppRoutes />
      </MemoryRouter>
    </I18nextProvider>,
  )
  await act(async () => {})
}

async function submitLogin(texts: typeof en, password = 'lab-password-12') {
  fireEvent.change(screen.getByLabelText(texts.login.username), { target: { value: 'lab-admin' } })
  fireEvent.change(screen.getByLabelText(texts.login.password), { target: { value: password } })
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: texts.login.submit }))
  })
}

beforeEach(() => localStorage.clear())
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

describe('login screen', () => {
  for (const [language, texts] of [
    ['es', es],
    ['en', en],
  ] as const) {
    it(`shows a generic failure message and empties the password field (${language})`, async () => {
      const calls = stub({
        'GET /api/auth/session': () => NO_SESSION,
        'POST /api/auth/login': () => ({ status: 401, body: { detail: 'invalid user name or password' } }),
      })
      await renderAt(['/devices'], language)
      const user = screen.getByLabelText(texts.login.username) as HTMLInputElement
      const password = screen.getByLabelText(texts.login.password) as HTMLInputElement
      expect(user.autocomplete).toBe('username')
      expect(password.autocomplete).toBe('current-password')
      expect(password.type).toBe('password')
      await submitLogin(texts, 'wrong-lab-password')
      expect(screen.getByRole('alert').textContent).toBe(texts.login.failed)
      expect(password.value).toBe('')
      expect(user.value).toBe('lab-admin')
      expect(document.body.textContent).not.toContain('wrong-lab-password')
      const login = calls.find((c) => c.url === '/api/auth/login')
      expect(new Headers(login?.init?.headers).get('X-NetScanner-Request')).toBe('1')
      expect(JSON.parse(String(login?.init?.body))).toEqual({
        username: 'lab-admin',
        password: 'wrong-lab-password',
      })
    })
  }

  it('says when the next attempt is possible after a 429', async () => {
    vi.useFakeTimers({ now: new Date('2026-11-10T10:00:00Z'), toFake: ['Date'] })
    stub({
      'GET /api/auth/session': () => NO_SESSION,
      'POST /api/auth/login': () => ({
        status: 429,
        body: { detail: 'too many failed logins; try again later' },
        headers: { 'Retry-After': '600' },
      }),
    })
    await renderAt(['/devices'], 'en')
    await submitLogin(en)
    const time = new Date('2026-11-10T10:10:00Z').toLocaleTimeString('en')
    expect(screen.getByRole('alert').textContent).toBe(en.login.limited.replace('{{time}}', time))
    expect((screen.getByLabelText(en.login.password) as HTMLInputElement).value).toBe('')
  })

  for (const [language, texts] of [
    ['es', es],
    ['en', en],
  ] as const) {
    it(`explains that the account is created from the server console (${language})`, async () => {
      stub({
        'GET /api/auth/session': () => NO_SESSION,
        'GET /api/status': () => ({ body: { authentication: true, admin_exists: false } }),
      })
      await renderAt(['/settings'], language)
      const note = screen.getByRole('note')
      expect(note.textContent).toContain(texts.login.no_account)
      expect(note.textContent).toContain('docker compose run --rm api python -m netscanner.admin create')
    })
  }

  it('shows no account message when the administrator exists', async () => {
    stub({ 'GET /api/auth/session': () => NO_SESSION })
    await renderAt(['/settings'], 'en')
    expect(screen.queryByRole('note')).toBeNull()
  })
})

describe('session expiry', () => {
  it('returns to the login screen on a 401, then shows the page that was open', async () => {
    let expired = false
    let loggedIn = true
    stub({
      'GET /api/auth/session': () => ({ body: SESSION }),
      'GET /api/devices': () => ({ body: PAGE }),
      'GET /api/devices/1': () => (loggedIn && !expired ? { body: DEVICE } : NO_SESSION),
      'POST /api/auth/login': () => {
        loggedIn = true
        expired = false
        return { body: SESSION }
      },
    })
    expired = true // the session expired on the server while the list was open
    loggedIn = false
    await renderAt(['/devices', '/devices/1'], 'en')
    // Opening the device answered 401: the login screen, and nothing of the page.
    expect(screen.getByRole('heading', { name: en.login.title })).toBeTruthy()
    expect(document.body.textContent).not.toContain('lab-sw-01')
    expect(screen.queryByRole('navigation', { name: en.nav.label })?.textContent).toBe('')
    await submitLogin(en)
    // After logging in, the device page that was open is shown.
    expect(screen.getByRole('heading', { name: 'lab-sw-01' })).toBeTruthy()
    expect(screen.queryByRole('heading', { name: en.login.title })).toBeNull()
  })
})

describe('logout', () => {
  it('shows the login screen, and back does not reopen the page without a session', async () => {
    let loggedIn = true
    const calls = stub({
      'GET /api/auth/session': () => (loggedIn ? { body: SESSION } : NO_SESSION),
      'GET /api/devices': () => (loggedIn ? { body: PAGE } : NO_SESSION),
      'GET /api/settings/discovery': () => NO_SESSION,
      'POST /api/auth/logout': () => {
        loggedIn = false
        return { body: { detail: 'logged out' } }
      },
    })
    await renderAt(['/settings', '/devices'], 'es')
    expect(screen.getByLabelText(es.session.user).textContent).toBe('lab-admin')
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: es.session.logout }))
    })
    const logout = calls.find((c) => c.url === '/api/auth/logout')
    expect(logout?.init?.method).toBe('POST')
    expect(new Headers(logout?.init?.headers).get('X-NetScanner-Request')).toBe('1')
    expect(screen.getByRole('heading', { name: es.login.title })).toBeTruthy()
    expect(screen.queryByRole('button', { name: es.session.logout })).toBeNull()
    await act(async () => goBack())
    expect(screen.getByRole('heading', { name: es.login.title })).toBeTruthy()
    expect(screen.queryByRole('heading', { name: es.nav.settings })).toBeNull()
  })
})
