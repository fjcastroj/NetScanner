/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Francisco Javier Castro Jiménez
 * Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
 * Computer Engineering, Universidad Internacional de La Rioja (UNIR).
 */

import { useEffect, useState } from 'react'

import { REQUEST_HEADER } from './api'

export type ApiStatus = 'checking' | 'available' | 'unavailable'

export const HEALTH_URL = '/api/health'
const POLL_INTERVAL_MS = 30_000

// Any failure (network error, 503, unexpected answer) is shown only as
// "unavailable"; no technical detail reaches the interface.
export async function fetchApiStatus(): Promise<ApiStatus> {
  try {
    const response = await fetch(HEALTH_URL, { headers: { Accept: 'application/json', ...REQUEST_HEADER } })
    return response.ok ? 'available' : 'unavailable'
  } catch {
    return 'unavailable'
  }
}

export function useApiStatus(): ApiStatus {
  const [status, setStatus] = useState<ApiStatus>('checking')

  useEffect(() => {
    let active = true
    const check = () => {
      void fetchApiStatus().then((next) => {
        if (active) setStatus(next)
      })
    }
    check()
    const timer = window.setInterval(check, POLL_INTERVAL_MS)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [])

  return status
}
