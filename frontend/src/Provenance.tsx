/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Francisco Javier Castro Jiménez
 * Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
 * Computer Engineering, Universidad Internacional de La Rioja (UNIR).
 */

// Origin and age of one value (RF-29, RF-30, design D11): an observed or
// inferred badge, the age as relative time, a stale mark with the last seen
// time, and method, source and evidence fragments on demand.
import { useTranslation } from 'react-i18next'

import type { Value } from './api'

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ['day', 86_400],
  ['hour', 3_600],
  ['minute', 60],
  ['second', 1],
]

export function relativeAge(seconds: number, language: string): string {
  const format = new Intl.RelativeTimeFormat(language, { numeric: 'auto' })
  for (const [unit, size] of UNITS) {
    if (seconds >= size || unit === 'second') {
      return format.format(-Math.floor(seconds / size), unit)
    }
  }
  return format.format(0, 'second')
}

export function formatTime(iso: string | null | undefined, language: string): string {
  return iso ? new Date(iso).toLocaleString(language) : '—'
}

export function displayValue(value: Value): string {
  if (value.state === 'unknown') return '—'
  if (value.value === null || value.value === undefined || value.value === '') return '∅'
  return String(value.value)
}

function fragments(value: Value): [string, string][] {
  const found: [string, string][] = []
  for (const input of value.evidence?.inputs ?? []) {
    for (const [key, text] of Object.entries(input.snapshot ?? {})) {
      found.push([key, String(text)])
    }
  }
  return found
}

export function Provenance({ value, raw }: { value: Value; raw?: string }) {
  const { t, i18n } = useTranslation()
  if (value.state === 'unknown' || value.origin === undefined) {
    return <span className="provenance provenance-unknown">{t('provenance.unknown')}</span>
  }
  const language = i18n.resolvedLanguage ?? i18n.language
  const evidence = fragments(value)
  return (
    <span className="provenance">
      <span className={`badge badge-${value.origin}`}>{t(`provenance.${value.origin}`)}</span>
      {value.age_seconds !== undefined && (
        <span className="age" title={formatTime(value.seen_at, language)}>
          {relativeAge(value.age_seconds, language)}
        </span>
      )}
      {value.stale && (
        <span className="badge badge-stale">
          {t('provenance.stale', { time: formatTime(value.seen_at, language) })}
        </span>
      )}
      <details className="provenance-details">
        <summary>{t('provenance.details')}</summary>
        <dl>
          {raw !== undefined && (
            <>
              <dt>{t('provenance.raw')}</dt>
              <dd>
                <code>{raw}</code>
              </dd>
            </>
          )}
          <dt>{t('provenance.method')}</dt>
          <dd>{value.method ?? t('provenance.no_method')}</dd>
          <dt>{t('provenance.source')}</dt>
          <dd>{value.source}</dd>
          <dt>{t('provenance.query')}</dt>
          <dd>
            {t('provenance.query_ref', { query: value.query_id, run: value.run_id })}
          </dd>
          <dt>{t('provenance.seen_at')}</dt>
          <dd>{formatTime(value.seen_at, language)}</dd>
          {evidence.length > 0 && (
            <>
              <dt>{t('provenance.evidence')}</dt>
              <dd>
                <ul className="fragments">
                  {evidence.map(([key, text]) => (
                    <li key={key}>
                      <code>{text}</code>
                    </li>
                  ))}
                </ul>
              </dd>
            </>
          )}
        </dl>
      </details>
    </span>
  )
}
