/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Francisco Javier Castro Jiménez
 * Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
 * Computer Engineering, Universidad Internacional de La Rioja (UNIR).
 */

// Router and layout (design D11). With add-admin-authentication (D8) the
// layout shows the login screen whenever there is no valid session, for any
// URL, so no page and none of its data appear without one; after logging in
// the page of the current URL is shown. The lab mode banner is gone (D9).
import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { BrowserRouter, Navigate, NavLink, Outlet, Route, Routes } from 'react-router'

import { SessionProvider, useSession } from './auth'
import { LANGUAGES, type Language } from './i18n'
import { DevicePage } from './pages/DevicePage'
import { DevicesPage } from './pages/DevicesPage'
import { DiscoveryPage } from './pages/DiscoveryPage'
import { LoginPage } from './pages/LoginPage'
import { SettingsPage } from './pages/SettingsPage'
import { useApiStatus } from './useApiStatus'

function LanguageSelector() {
  const { t, i18n } = useTranslation()
  const current = (i18n.resolvedLanguage ?? i18n.language) as Language

  return (
    <label className="language">
      <span>{t('language.label')}</span>
      <select value={current} onChange={(e) => void i18n.changeLanguage(e.target.value)}>
        {Object.keys(LANGUAGES).map((code) => (
          <option key={code} value={code}>
            {t(`language.${code}`)}
          </option>
        ))}
      </select>
    </label>
  )
}

function StatusIndicator() {
  const { t } = useTranslation()
  const status = useApiStatus()

  return (
    <p className={`status status-${status}`} role="status" aria-label={t('status.label')}>
      <span className="status-dot" aria-hidden="true" />
      {t(`status.${status}`)}
    </p>
  )
}

function UserMenu() {
  const { t } = useTranslation()
  const { session, logout } = useSession()
  if (session.state !== 'authenticated') return null
  return (
    <div className="user-menu">
      <span className="user-name" aria-label={t('session.user')}>
        {session.username}
      </span>
      <button type="button" onClick={() => void logout()}>
        {t('session.logout')}
      </button>
    </div>
  )
}

const PAGES = [
  ['/settings', 'nav.settings'],
  ['/discovery', 'nav.discovery'],
  ['/devices', 'nav.devices'],
] as const

export function Layout() {
  const { t, i18n } = useTranslation()
  const { session } = useSession()

  useEffect(() => {
    document.documentElement.lang = i18n.resolvedLanguage ?? i18n.language
    document.title = t('app.name')
  }, [i18n.resolvedLanguage, i18n.language, t])

  return (
    <div className="shell">
      <header className="header">
        <div className="brand">
          <h1>{t('app.name')}</h1>
          <p>{t('app.tagline')}</p>
        </div>
        <div className="header-tools">
          <StatusIndicator />
          <LanguageSelector />
          <UserMenu />
        </div>
      </header>
      <nav className="nav" aria-label={t('nav.label')}>
        {session.state === 'authenticated' && (
          <ul>
            {PAGES.map(([path, label]) => (
              <li key={path}>
                <NavLink to={path}>{t(label)}</NavLink>
              </li>
            ))}
          </ul>
        )}
      </nav>
      <main className="main">
        {session.state === 'checking' && <p>{t('common.loading')}</p>}
        {session.state === 'anonymous' && <LoginPage />}
        {session.state === 'authenticated' && <Outlet />}
      </main>
    </div>
  )
}

export function AppRoutes() {
  return (
    <SessionProvider>
      <AppRouteTable />
    </SessionProvider>
  )
}

function AppRouteTable() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Navigate to="/discovery" replace />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="discovery" element={<DiscoveryPage />} />
        <Route path="devices" element={<DevicesPage />} />
        <Route path="devices/:id" element={<DevicePage />} />
        <Route path="*" element={<Navigate to="/discovery" replace />} />
      </Route>
    </Routes>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AppRoutes />
    </BrowserRouter>
  )
}
