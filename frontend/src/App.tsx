/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Francisco Javier Castro Jiménez
 * Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
 * Computer Engineering, Universidad Internacional de La Rioja (UNIR).
 */

// Router and layout (design D11). The lab mode banner belongs to the layout,
// so no page can be shown without it.
import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { BrowserRouter, Navigate, NavLink, Outlet, Route, Routes } from 'react-router'

import { LANGUAGES, type Language } from './i18n'
import { DevicePage } from './pages/DevicePage'
import { DevicesPage } from './pages/DevicesPage'
import { DiscoveryPage } from './pages/DiscoveryPage'
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

export function LabBanner() {
  const { t } = useTranslation()
  return (
    <div className="lab-banner" role="note" aria-label={t('lab.label')}>
      <strong>{t('lab.title')}</strong> {t('lab.text')}
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
        </div>
      </header>
      <LabBanner />
      <nav className="nav" aria-label={t('nav.label')}>
        <ul>
          {PAGES.map(([path, label]) => (
            <li key={path}>
              <NavLink to={path}>{t(label)}</NavLink>
            </li>
          ))}
        </ul>
      </nav>
      <main className="main">
        <Outlet />
      </main>
    </div>
  )
}

export function AppRoutes() {
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
