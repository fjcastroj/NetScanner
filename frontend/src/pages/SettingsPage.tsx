/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Francisco Javier Castro Jiménez
 * Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
 * Computer Engineering, Universidad Internacional de La Rioja (UNIR).
 */

// Discovery settings and the credential (web-ui spec, design D11). Secret
// fields are password inputs that start empty and are cleared after saving:
// the API never returns a stored secret, and the screen never fills one in.
import { type FormEvent, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { api, ApiError, type CredentialDescription, type DiscoverySettings, type Problem } from '../api'
import { formatTime } from '../Provenance'

const LIST_FIELDS = ['seeds', 'allowed_ranges', 'exclusions'] as const
const NUMBER_FIELDS = ['max_depth', 'max_candidates', 'max_devices', 'max_datagrams'] as const
const AUTH_PROTOCOLS = ['SHA', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512']
const PRIV_PROTOCOLS = ['AES-128', 'AES-192', 'AES-256']

type Form = Record<(typeof LIST_FIELDS)[number] | (typeof NUMBER_FIELDS)[number], string> & {
  follow_ip_mac: boolean
}

function toForm(s: DiscoverySettings): Form {
  return {
    seeds: s.seeds.join('\n'),
    allowed_ranges: s.allowed_ranges.join('\n'),
    exclusions: s.exclusions.join('\n'),
    max_depth: String(s.max_depth),
    max_candidates: String(s.max_candidates),
    max_devices: String(s.max_devices),
    max_datagrams: String(s.max_datagrams),
    follow_ip_mac: s.follow_ip_mac,
  }
}

function lines(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '')
}

// "seeds.1" -> { seeds: ["line 2: reason"] }: shown next to the field concerned.
export function problemsByField(problems: Problem[], lineLabel: (n: number) => string) {
  const found: Record<string, string[]> = {}
  for (const { field, reason } of problems) {
    const [name, index] = field.split('.')
    const text = index !== undefined && /^\d+$/.test(index) ? `${lineLabel(Number(index) + 1)}: ${reason}` : reason
    ;(found[name] ??= []).push(text)
  }
  return found
}

function FieldError({ id, messages }: { id: string; messages?: string[] }) {
  if (!messages?.length) return null
  return (
    <ul className="field-error" id={id} role="alert">
      {messages.map((m) => (
        <li key={m}>{m}</li>
      ))}
    </ul>
  )
}

function DiscoverySettingsForm() {
  const { t } = useTranslation()
  const [form, setForm] = useState<Form | null>(null)
  const [ceilings, setCeilings] = useState<DiscoverySettings['ceilings']>()
  const [errors, setErrors] = useState<Record<string, string[]>>({})
  const [message, setMessage] = useState<string | null>(null)

  useEffect(() => {
    api
      .get<DiscoverySettings>('/api/settings/discovery')
      .then((s) => {
        setForm(toForm(s))
        setCeilings(s.ceilings)
      })
      .catch(() => setMessage(t('errors.load')))
  }, [t])

  if (form === null) return <p>{message ?? t('common.loading')}</p>

  const lineLabel = (n: number) => t('settings.line', { n })
  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setMessage(null)
    const body = {
      seeds: lines(form.seeds),
      allowed_ranges: lines(form.allowed_ranges),
      exclusions: lines(form.exclusions),
      follow_ip_mac: form.follow_ip_mac,
      ...Object.fromEntries(NUMBER_FIELDS.map((f) => [f, Number(form[f])])),
    }
    try {
      const saved = await api.put<DiscoverySettings>('/api/settings/discovery', body)
      setForm(toForm(saved))
      setErrors({})
      setMessage(t('settings.saved'))
    } catch (error) {
      if (error instanceof ApiError && error.status === 422) {
        setErrors(problemsByField(error.problems, lineLabel))
        setMessage(t('settings.invalid'))
      } else {
        setMessage(t('errors.save'))
      }
    }
  }

  return (
    <form className="card" onSubmit={(e) => void submit(e)} noValidate>
      <h3>{t('settings.discovery')}</h3>
      {LIST_FIELDS.map((name) => (
        <div className="field" key={name}>
          <label htmlFor={`f-${name}`}>{t(`settings.${name}`)}</label>
          <textarea
            id={`f-${name}`}
            rows={3}
            value={form[name]}
            aria-invalid={errors[name] ? true : undefined}
            aria-describedby={errors[name] ? `e-${name}` : undefined}
            onChange={(e) => setForm({ ...form, [name]: e.target.value })}
          />
          <small>{t('settings.one_per_line')}</small>
          <FieldError id={`e-${name}`} messages={errors[name]} />
        </div>
      ))}
      {NUMBER_FIELDS.map((name) => (
        <div className="field" key={name}>
          <label htmlFor={`f-${name}`}>{t(`settings.${name}`)}</label>
          <input
            id={`f-${name}`}
            type="number"
            min={name === 'max_depth' ? 0 : 1}
            value={form[name]}
            aria-invalid={errors[name] ? true : undefined}
            aria-describedby={errors[name] ? `e-${name}` : undefined}
            onChange={(e) => setForm({ ...form, [name]: e.target.value })}
          />
          {ceilings && <small>{t('settings.ceiling', { value: ceilings[name] })}</small>}
          <FieldError id={`e-${name}`} messages={errors[name]} />
        </div>
      ))}
      <div className="field field-inline">
        <input
          id="f-follow_ip_mac"
          type="checkbox"
          checked={form.follow_ip_mac}
          onChange={(e) => setForm({ ...form, follow_ip_mac: e.target.checked })}
        />
        <label htmlFor="f-follow_ip_mac">{t('settings.follow_ip_mac')}</label>
      </div>
      <FieldError id="e-settings" messages={errors.settings} />
      <button type="submit">{t('settings.save')}</button>
      {message && <p role="status">{message}</p>}
    </form>
  )
}

type Secrets = { community: string; auth_key: string; priv_key: string }
const NO_SECRETS: Secrets = { community: '', auth_key: '', priv_key: '' }

function CredentialForm() {
  const { t, i18n } = useTranslation()
  const [description, setDescription] = useState<CredentialDescription | null>(null)
  const [version, setVersion] = useState<'2c' | '3'>('2c')
  const [user, setUser] = useState('')
  const [level, setLevel] = useState<'authPriv' | 'authNoPriv'>('authPriv')
  const [authProtocol, setAuthProtocol] = useState('SHA-256')
  const [privProtocol, setPrivProtocol] = useState('AES-128')
  const [secrets, setSecrets] = useState<Secrets>(NO_SECRETS)
  const [errors, setErrors] = useState<Record<string, string[]>>({})
  const [message, setMessage] = useState<string | null>(null)

  useEffect(() => {
    api
      .get<CredentialDescription>('/api/settings/credential')
      .then(setDescription)
      .catch(() => setMessage(t('errors.load')))
  }, [t])

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setMessage(null)
    const body =
      version === '2c'
        ? { version, community: secrets.community }
        : {
            version,
            user,
            level,
            auth_protocol: authProtocol,
            auth_key: secrets.auth_key,
            ...(level === 'authPriv' ? { priv_protocol: privProtocol, priv_key: secrets.priv_key } : {}),
          }
    try {
      setDescription(await api.put<CredentialDescription>('/api/settings/credential', body))
      setErrors({})
      setMessage(t('credential.saved'))
    } catch (error) {
      if (error instanceof ApiError && error.status === 422) {
        setErrors(problemsByField(error.problems, (n) => t('settings.line', { n })))
        setMessage(t('settings.invalid'))
      } else {
        setMessage(t('errors.save'))
      }
    } finally {
      setSecrets(NO_SECRETS) // never kept on screen after sending
    }
  }

  const secret = (name: keyof Secrets) => (
    <div className="field" key={name}>
      <label htmlFor={`c-${name}`}>{t(`credential.${name}`)}</label>
      <input
        id={`c-${name}`}
        type="password"
        autoComplete="new-password"
        value={secrets[name]}
        aria-invalid={errors[name] ? true : undefined}
        onChange={(e) => setSecrets({ ...secrets, [name]: e.target.value })}
      />
      <FieldError id={`ce-${name}`} messages={errors[name]} />
    </div>
  )

  const language = i18n.resolvedLanguage ?? i18n.language
  return (
    <form className="card" onSubmit={(e) => void submit(e)} noValidate>
      <h3>{t('credential.title')}</h3>
      {description === null ? (
        <p>{message ?? t('common.loading')}</p>
      ) : description.configured ? (
        <p className="credential-state">
          {t('credential.configured', {
            version: description.version,
            time: formatTime(description.updated_at, language),
          })}
          {!description.usable && <strong className="warning"> {t('credential.unusable')}</strong>}
        </p>
      ) : (
        <p className="credential-state">{t('credential.none')}</p>
      )}
      <div className="field">
        <label htmlFor="c-version">{t('credential.version')}</label>
        <select id="c-version" value={version} onChange={(e) => setVersion(e.target.value as '2c' | '3')}>
          <option value="2c">SNMPv2c</option>
          <option value="3">SNMPv3</option>
        </select>
      </div>
      {version === '2c' ? (
        secret('community')
      ) : (
        <>
          <div className="field">
            <label htmlFor="c-user">{t('credential.user')}</label>
            <input id="c-user" value={user} autoComplete="off" onChange={(e) => setUser(e.target.value)} />
            <FieldError id="ce-user" messages={errors.user} />
          </div>
          <div className="field">
            <label htmlFor="c-level">{t('credential.level')}</label>
            <select id="c-level" value={level} onChange={(e) => setLevel(e.target.value as typeof level)}>
              <option value="authPriv">authPriv</option>
              <option value="authNoPriv">authNoPriv</option>
            </select>
          </div>
          <div className="field">
            <label htmlFor="c-auth">{t('credential.auth_protocol')}</label>
            <select id="c-auth" value={authProtocol} onChange={(e) => setAuthProtocol(e.target.value)}>
              {AUTH_PROTOCOLS.map((p) => (
                <option key={p}>{p}</option>
              ))}
            </select>
          </div>
          {secret('auth_key')}
          {level === 'authPriv' && (
            <>
              <div className="field">
                <label htmlFor="c-priv">{t('credential.priv_protocol')}</label>
                <select id="c-priv" value={privProtocol} onChange={(e) => setPrivProtocol(e.target.value)}>
                  {PRIV_PROTOCOLS.map((p) => (
                    <option key={p}>{p}</option>
                  ))}
                </select>
              </div>
              {secret('priv_key')}
            </>
          )}
        </>
      )}
      <FieldError id="ce-credential" messages={errors.credential} />
      <button type="submit">{t('credential.save')}</button>
      {message && description !== null && <p role="status">{message}</p>}
    </form>
  )
}

export function SettingsPage() {
  const { t } = useTranslation()
  return (
    <section>
      <h2>{t('nav.settings')}</h2>
      <div className="cards">
        <DiscoverySettingsForm />
        <CredentialForm />
      </div>
    </section>
  )
}
