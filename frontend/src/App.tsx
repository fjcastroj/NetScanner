/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Francisco Javier Castro Jiménez
 * Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
 * Computer Engineering, Universidad Internacional de La Rioja (UNIR).
 */

import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'

import { LANGUAGES, type Language } from './i18n'
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

export default function App() {
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
      <nav className="nav" aria-label={t('nav.label')}>
        <p className="nav-empty">{t('nav.empty')}</p>
      </nav>
      <main className="main">
        <p>{t('home.placeholder')}</p>
      </main>
    </div>
  )
}
