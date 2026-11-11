/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Francisco Javier Castro Jiménez
 * Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
 * Computer Engineering, Universidad Internacional de La Rioja (UNIR).
 */

// Login screen (web-ui spec, add-admin-authentication D8). The failure message
// never says whether the user name or the password was wrong, and the password
// field is emptied after every attempt. With no administrator account, it
// explains that the account is created from the server console.
import { type FormEvent, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { api, ApiError, type Status } from '../api'
import { useSession } from '../auth'

export const CREATE_COMMAND = 'docker compose run --rm api python -m netscanner.admin create --username <name>'

type Message = { kind: 'failed' } | { kind: 'limited'; until: Date } | { kind: 'error' }

export function LoginPage() {
  const { t, i18n } = useTranslation()
  const { login } = useSession()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [message, setMessage] = useState<Message | null>(null)
  const [adminExists, setAdminExists] = useState<boolean | null>(null)
  const [sending, setSending] = useState(false)

  useEffect(() => {
    api
      .get<Status>('/api/status')
      .then((status) => setAdminExists(status.admin_exists))
      .catch(() => setAdminExists(null))
  }, [])

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setSending(true)
    setMessage(null)
    try {
      await login(username, password)
    } catch (error) {
      if (error instanceof ApiError && error.status === 429) {
        setMessage({ kind: 'limited', until: new Date(Date.now() + (error.retryAfter ?? 900) * 1000) })
      } else if (error instanceof ApiError && (error.status === 401 || error.status === 422)) {
        setMessage({ kind: 'failed' })
      } else {
        setMessage({ kind: 'error' })
      }
    } finally {
      setPassword('') // never kept on screen after an attempt
      setSending(false)
    }
  }

  const language = i18n.resolvedLanguage ?? i18n.language
  return (
    <section className="login">
      <h2>{t('login.title')}</h2>
      {adminExists === false && (
        <div className="card no-account" role="note">
          <p>{t('login.no_account')}</p>
          <code>{CREATE_COMMAND}</code>
        </div>
      )}
      <form className="card" onSubmit={(e) => void submit(e)}>
        <div className="field">
          <label htmlFor="login-username">{t('login.username')}</label>
          <input
            id="login-username"
            name="username"
            autoComplete="username"
            value={username}
            required
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="login-password">{t('login.password')}</label>
          <input
            id="login-password"
            name="password"
            type="password"
            autoComplete="current-password"
            value={password}
            required
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <button type="submit" disabled={sending}>
          {t('login.submit')}
        </button>
        {message && (
          <p className="field-error" role="alert">
            {message.kind === 'limited'
              ? t('login.limited', { time: message.until.toLocaleTimeString(language) })
              : t(`login.${message.kind}`)}
          </p>
        )}
      </form>
    </section>
  )
}
