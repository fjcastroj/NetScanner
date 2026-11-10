/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Francisco Javier Castro Jiménez
 * Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
 * Computer Engineering, Universidad Internacional de La Rioja (UNIR).
 */

// Device detail (RF-11, RF-29): attribute groups, addresses and interfaces,
// every value with its origin, age and staleness, method and source on demand.
import { useEffect, useState } from 'react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router'

import { api, ApiError, type DeviceDetail, type Group, type RecordItem, type Value } from '../api'
import { displayValue, Provenance } from '../Provenance'

const DEVICE_GROUPS = ['system', 'chassis', 'vendor', 'model'] as const
const INTERFACE_COLUMNS: [string, string][] = [
  ['base', 'if_descr'],
  ['ext', 'if_name'],
  ['base', 'if_type'],
  ['speed', 'speed_bps'],
  ['base', 'admin_status'],
  ['base', 'oper_status'],
  ['base', 'phys_address'],
]

const VENDOR_STATUSES = ['known', 'generic_agent', 'not_in_registry']

// sysUpTime is in hundredths of a second (TimeTicks).
export function uptimeParts(ticks: number): { days: number; hours: number; minutes: number } {
  const minutesTotal = Math.floor(ticks / 6_000)
  return {
    days: Math.floor(minutesTotal / 1_440),
    hours: Math.floor((minutesTotal % 1_440) / 60),
    minutes: minutesTotal % 60,
  }
}

// Text shown for a field, and the raw value when the text is a translation
// or a conversion of it (the raw value stays in the provenance details).
function shown(field: string, value: Value, t: TFunction): { text: string; raw?: string } {
  if (value.state !== 'value') return { text: displayValue(value) }
  if (field === 'vendor_status' && VENDOR_STATUSES.includes(String(value.value))) {
    return { text: t(`vendor_status.${String(value.value)}`), raw: String(value.value) }
  }
  if (field === 'sys_uptime' && typeof value.value === 'number') {
    return { text: t('device.uptime', uptimeParts(value.value)), raw: String(value.value) }
  }
  return { text: displayValue(value) }
}

function GroupTable({ name, group }: { name: string; group: Group | null }) {
  const { t } = useTranslation()
  return (
    <div className="card">
      <h3>{t(`device.groups.${name}`)}</h3>
      {group === null ? (
        <p>{t('device.not_collected')}</p>
      ) : (
        <table>
          <tbody>
            {Object.entries(group.fields).map(([field, value]) => {
              const { text, raw } = shown(field, value, t)
              return (
                <tr key={field}>
                  <th scope="row">{t(`fields.${field}`, { defaultValue: field })}</th>
                  <td data-field={field}>
                    {text} <Provenance value={value} raw={raw} />
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}
    </div>
  )
}

function cell(record: RecordItem, group: string, field: string) {
  const value = record.groups[group]?.fields[field]
  if (!value) return <td key={`${group}.${field}`}>—</td>
  return (
    <td key={`${group}.${field}`}>
      {displayValue(value)} <Provenance value={value} />
    </td>
  )
}

export function DevicePage() {
  const { t } = useTranslation()
  const { id } = useParams()
  const [device, setDevice] = useState<DeviceDetail | null>(null)
  const [error, setError] = useState<'not_found' | 'load' | null>(null)

  useEffect(() => {
    api
      .get<DeviceDetail>(`/api/devices/${encodeURIComponent(id ?? '')}`)
      .then(setDevice)
      .catch((e) => setError(e instanceof ApiError && e.status === 404 ? 'not_found' : 'load'))
  }, [id])

  if (error) return <p role="alert">{t(error === 'not_found' ? 'device.not_found' : 'errors.load')}</p>
  if (device === null) return <p>{t('common.loading')}</p>
  const name = device.groups.system?.fields.sys_name
  return (
    <section>
      <p>
        <Link to="/devices">{t('device.back')}</Link>
      </p>
      <h2>{name && name.state === 'value' ? displayValue(name) : t('device.title', { id: device.id })}</h2>
      <div className="cards">
        {DEVICE_GROUPS.map((g) => (
          <GroupTable key={g} name={g} group={device.groups[g] ?? null} />
        ))}
      </div>
      <div className="card">
        <h3>{t('device.addresses', { count: device.addresses.length })}</h3>
        <table>
          <thead>
            <tr>
              <th>{t('device.address')}</th>
              <th>{t('device.address_source')}</th>
              <th>{t('fields.if_index')}</th>
            </tr>
          </thead>
          <tbody>
            {device.addresses.map((a) => (
              <tr key={a.id}>
                <td>{String(a.address)}</td>
                <td>{t(`device.source.${String(a.source)}`, { defaultValue: String(a.source) })}</td>
                {cell(a, 'address', 'if_index')}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="card">
        <h3>{t('device.interfaces', { count: device.interfaces.length })}</h3>
        <table className="interfaces">
          <thead>
            <tr>
              <th>{t('fields.if_index')}</th>
              {INTERFACE_COLUMNS.map(([, field]) => (
                <th key={field}>{t(`fields.${field}`, { defaultValue: field })}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {device.interfaces.map((i) => (
              <tr key={i.id}>
                <td>{String(i.if_index)}</td>
                {INTERFACE_COLUMNS.map(([group, field]) => cell(i, group, field))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}
