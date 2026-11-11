/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Francisco Javier Castro Jiménez
 * Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
 * Computer Engineering, Universidad Internacional de La Rioja (UNIR).
 */

import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { I18nextProvider } from 'react-i18next'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import App from './App'
import { createI18n, STORAGE_KEY } from './i18n'
import en from './locales/en.json'
import es from './locales/es.json'
import { HEALTH_URL } from './useApiStatus'

// Health answers with ``result``; there is no session (401), so the login
// screen is shown; status says the administrator exists. A new Response per
// call (a body can be read only once).
function mockHealth(result: Response | Error) {
  const fetchMock = vi.fn((url: string) => {
    if (url === HEALTH_URL) {
      return result instanceof Error ? Promise.reject(result) : Promise.resolve(result.clone())
    }
    if (url === '/api/auth/session') {
      return Promise.resolve(new Response('{"detail":"authentication required"}', { status: 401 }))
    }
    if (url === '/api/status') {
      return Promise.resolve(new Response('{"authentication":true,"admin_exists":true}', { status: 200 }))
    }
    return Promise.resolve(new Response('{"total":0,"limit":20,"offset":0,"items":[]}', { status: 200 }))
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

function setBrowserLanguages(languages: string[]) {
  vi.spyOn(navigator, 'languages', 'get').mockReturnValue(languages)
  vi.spyOn(navigator, 'language', 'get').mockReturnValue(languages[0])
}

async function renderApp() {
  const i18n = createI18n()
  render(
    <I18nextProvider i18n={i18n}>
      <App />
    </I18nextProvider>,
  )
  await act(async () => {}) // let the health request settle
  return i18n
}

beforeEach(() => {
  localStorage.clear()
  setBrowserLanguages(['es-ES'])
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('application shell', () => {
  it('shows the name, the navigation area, the login screen and the language selector', async () => {
    mockHealth(new Response('{}', { status: 200 }))
    await renderApp()
    expect(screen.getByRole('heading', { name: es.app.name })).toBeTruthy()
    expect(screen.getByRole('navigation', { name: es.nav.label })).toBeTruthy()
    expect(screen.getByRole('combobox')).toBeTruthy()
    expect(screen.getByRole('heading', { name: es.login.title })).toBeTruthy()
    expect(screen.queryByRole('link', { name: es.nav.devices })).toBeNull() // no pages without a session
    expect(document.body.textContent).not.toMatch(/laboratorio|lab mode/i) // the lab banner is gone
  })
})

describe('API status indicator', () => {
  it('shows available when health answers 200', async () => {
    const fetchMock = mockHealth(new Response('{"status":"ok"}', { status: 200 }))
    await renderApp()
    expect(fetchMock).toHaveBeenCalledWith(HEALTH_URL, expect.anything())
    expect(screen.getByRole('status').textContent).toBe(es.status.available)
  })

  it('shows unavailable when health answers 503', async () => {
    mockHealth(new Response('{"status":"degraded"}', { status: 503 }))
    await renderApp()
    expect(screen.getByRole('status').textContent).toBe(es.status.unavailable)
  })

  it('shows unavailable without technical details when the request fails', async () => {
    mockHealth(new TypeError('Failed to fetch: connection refused'))
    await renderApp()
    const status = screen.getByRole('status').textContent
    expect(status).toBe(es.status.unavailable)
    expect(document.body.textContent).not.toContain('refused')
  })
})

describe('languages', () => {
  it('switches all visible text without reloading and remembers the choice', async () => {
    mockHealth(new Response('{}', { status: 200 }))
    await renderApp()
    expect(screen.getByRole('heading', { name: es.login.title })).toBeTruthy()

    await act(async () => {
      fireEvent.change(screen.getByRole('combobox'), { target: { value: 'en' } })
    })

    expect(screen.getByRole('heading', { name: en.login.title })).toBeTruthy()
    expect(screen.getByLabelText(en.login.username)).toBeTruthy()
    expect(screen.getByRole('status').textContent).toBe(en.status.available)
    expect(screen.queryByRole('heading', { name: es.login.title })).toBeNull()
    expect(localStorage.getItem(STORAGE_KEY)).toBe('en')
    expect(document.documentElement.lang).toBe('en')
  })

  it('uses a supported browser language on the first visit', async () => {
    mockHealth(new Response('{}', { status: 200 }))
    setBrowserLanguages(['en-GB', 'en'])
    const i18n = await renderApp()
    expect(i18n.resolvedLanguage).toBe('en')
    expect(screen.getByRole('heading', { name: en.login.title })).toBeTruthy()
  })

  it('falls back to Spanish for an unsupported browser language', async () => {
    mockHealth(new Response('{}', { status: 200 }))
    setBrowserLanguages(['fr-FR'])
    const i18n = await renderApp()
    expect(i18n.resolvedLanguage).toBe('es')
    expect(screen.getByRole('heading', { name: es.login.title })).toBeTruthy()
  })

  it('prefers the stored choice over the browser language', async () => {
    mockHealth(new Response('{}', { status: 200 }))
    localStorage.setItem(STORAGE_KEY, 'es')
    setBrowserLanguages(['en-US'])
    const i18n = await renderApp()
    expect(i18n.resolvedLanguage).toBe('es')
  })
})
