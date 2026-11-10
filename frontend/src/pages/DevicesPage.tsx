/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Francisco Javier Castro Jiménez
 * Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
 * Computer Engineering, Universidad Internacional de La Rioja (UNIR).
 */

// Device list (RF-11): summary fields, each with its origin and age.
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useSearchParams } from 'react-router'

import { api, type DeviceSummary, type Page } from '../api'
import { displayValue, formatTime, Provenance } from '../Provenance'

export const PAGE_SIZE = 100
const VALUES = ['name', 'vendor', 'model', 'software_version'] as const

export function DevicesPage() {
  const { t, i18n } = useTranslation()
  const [params, setParams] = useSearchParams()
  const offset = Math.max(0, Number(params.get('offset') ?? 0) || 0)
  const [page, setPage] = useState<Page<DeviceSummary> | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    api
      .get<Page<DeviceSummary>>(`/api/devices?limit=${PAGE_SIZE}&offset=${offset}`)
      .then((p) => {
        setPage(p)
        setFailed(false)
      })
      .catch(() => setFailed(true))
  }, [offset])

  const language = i18n.resolvedLanguage ?? i18n.language
  if (failed) return <p role="alert">{t('errors.load')}</p>
  if (page === null) return <p>{t('common.loading')}</p>
  return (
    <section>
      <h2>{t('nav.devices')}</h2>
      {page.items.length === 0 ? (
        <p>{t('devices.none')}</p>
      ) : (
        <table className="devices">
          <thead>
            <tr>
              {VALUES.map((v) => (
                <th key={v}>{t(`devices.${v}`)}</th>
              ))}
              <th>{t('devices.management_address')}</th>
              <th>{t('devices.interfaces')}</th>
              <th>{t('devices.first_seen')}</th>
              <th>{t('devices.last_seen')}</th>
            </tr>
          </thead>
          <tbody>
            {page.items.map((d) => (
              <tr key={d.id}>
                {VALUES.map((v) => (
                  <td key={v}>
                    {v === 'name' ? (
                      <Link to={`/devices/${d.id}`}>{displayValue(d.name) === '—' ? `#${d.id}` : displayValue(d.name)}</Link>
                    ) : (
                      displayValue(d[v])
                    )}
                    <Provenance value={d[v]} />
                  </td>
                ))}
                <td>{d.management_address ?? '—'}</td>
                <td>{d.interface_count}</td>
                <td>{formatTime(d.first_seen_at, language)}</td>
                <td>
                  {formatTime(d.last_seen_at, language)}
                  {d.stale && <span className="badge badge-stale">{t('provenance.stale_short')}</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="pager">
        {t('devices.range', {
          from: page.total === 0 ? 0 : page.offset + 1,
          to: page.offset + page.items.length,
          total: page.total,
        })}
        <button type="button" disabled={offset === 0} onClick={() => setParams({ offset: String(Math.max(0, offset - PAGE_SIZE)) })}>
          {t('devices.previous')}
        </button>
        <button
          type="button"
          disabled={offset + page.items.length >= page.total}
          onClick={() => setParams({ offset: String(offset + PAGE_SIZE) })}
        >
          {t('devices.next')}
        </button>
      </p>
    </section>
  )
}
