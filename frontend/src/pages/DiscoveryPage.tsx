/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Francisco Javier Castro Jiménez
 * Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
 * Computer Engineering, Universidad Internacional de La Rioja (UNIR).
 */

// Start a run, follow it until it finishes and list past runs (web-ui spec).
// While a run is pending or running the page polls every 2 s (design D11) and
// the start button stays disabled.
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { ACTIVE_STATUSES, api, ApiError, type Page, type Problem, type Run } from '../api'
import { formatTime } from '../Provenance'

export const POLL_INTERVAL_MS = 2_000

async function loadRuns(): Promise<{ items: Run[]; latest: Run | null }> {
  const page = await api.get<Page<Run>>('/api/runs?limit=20')
  const first = page.items[0]
  return { items: page.items, latest: first ? await api.get<Run>(`/api/runs/${first.id}`) : null }
}

function Counts({ run }: { run: Run }) {
  const { t } = useTranslation()
  const p = run.progress
  if (!p) return null
  return (
    <div className="counts">
      <dl>
        <dt>{t('discovery.candidates')}</dt>
        <dd data-testid="count-candidates">{p.candidates}</dd>
        <dt>{t('discovery.devices')}</dt>
        <dd data-testid="count-devices">{p.devices}</dd>
        <dt>{t('discovery.new_devices')}</dt>
        <dd>{p.new_devices}</dd>
        <dt>{t('discovery.queries')}</dt>
        <dd data-testid="count-queries">{p.queries}</dd>
      </dl>
      {Object.keys(p.reasons).length > 0 && (
        <>
          <h4>{t('discovery.reasons')}</h4>
          <ul className="reasons">
            {Object.entries(p.reasons).map(([reason, count]) => (
              <li key={reason}>
                {t(`reasons.${reason}`, { defaultValue: reason })}: {count}
              </li>
            ))}
          </ul>
        </>
      )}
      {run.summary?.limits_reached?.length ? (
        <p>{t('discovery.limits_reached', { limits: run.summary.limits_reached.join(', ') })}</p>
      ) : null}
    </div>
  )
}

export function DiscoveryPage() {
  const { t, i18n } = useTranslation()
  const [runs, setRuns] = useState<Run[] | null>(null)
  const [current, setCurrent] = useState<Run | null>(null)
  const [problems, setProblems] = useState<Problem[]>([])
  const [message, setMessage] = useState<string | null>(null)
  const [starting, setStarting] = useState(false)
  const active = current !== null && ACTIVE_STATUSES.includes(current.status)

  const [tick, setTick] = useState(0) // bumped to reload after starting a run

  // Loaded when the page opens and after a run is started; then every 2 s
  // while the latest run is pending or running.
  useEffect(() => {
    let alive = true
    const load = () => {
      loadRuns()
        .then(({ items, latest }) => {
          if (!alive) return
          setRuns(items)
          setCurrent(latest)
        })
        .catch(() => {
          if (alive) setMessage(t('errors.load'))
        })
    }
    if (!active) load()
    const timer = active ? window.setInterval(load, POLL_INTERVAL_MS) : undefined
    return () => {
      alive = false
      window.clearInterval(timer)
    }
  }, [active, tick, t])

  const start = async () => {
    setStarting(true)
    setProblems([])
    setMessage(null)
    try {
      const created = await api.post<Run>('/api/runs')
      setCurrent(created)
      setTick((n) => n + 1)
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) setMessage(t('discovery.already_running'))
      else if (error instanceof ApiError && error.status === 422) setProblems(error.problems)
      else setMessage(t('errors.save'))
    } finally {
      setStarting(false)
    }
  }

  const language = i18n.resolvedLanguage ?? i18n.language
  return (
    <section>
      <h2>{t('nav.discovery')}</h2>
      <div className="card">
        <button type="button" onClick={() => void start()} disabled={active || starting || runs === null}>
          {t('discovery.start')}
        </button>
        {active && <p role="status">{t('discovery.in_progress')}</p>}
        {message && <p role="alert">{message}</p>}
        {problems.length > 0 && (
          <ul className="field-error" role="alert">
            {problems.map((p) => (
              <li key={p.field}>
                {t(`discovery.field.${p.field}`, { defaultValue: p.field })}: {p.reason}
              </li>
            ))}
          </ul>
        )}
      </div>
      {current && (
        <div className="card">
          <h3>{t('discovery.run', { id: current.id })}</h3>
          <p>
            <span className={`run-status run-${current.status}`}>{t(`runs.${current.status}`)}</span>
            {current.error_category && <> ({t(`run_errors.${current.error_category}`, { defaultValue: current.error_category })})</>}
          </p>
          <Counts run={current} />
        </div>
      )}
      <div className="card">
        <h3>{t('discovery.history')}</h3>
        {runs === null ? (
          <p>{t('common.loading')}</p>
        ) : runs.length === 0 ? (
          <p>{t('discovery.none')}</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>{t('discovery.id')}</th>
                <th>{t('discovery.requested')}</th>
                <th>{t('discovery.finished')}</th>
                <th>{t('discovery.result')}</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((run) => (
                <tr key={run.id}>
                  <td>{run.id}</td>
                  <td>{formatTime(run.requested_at, language)}</td>
                  <td>{formatTime(run.finished_at, language)}</td>
                  <td>
                    {t(`runs.${run.status}`)}
                    {run.error_category && ` (${t(`run_errors.${run.error_category}`, { defaultValue: run.error_category })})`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  )
}
