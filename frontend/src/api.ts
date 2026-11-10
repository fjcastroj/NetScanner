/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Francisco Javier Castro Jiménez
 * Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
 * Computer Engineering, Universidad Internacional de La Rioja (UNIR).
 */

// Calls to the API of design D10. Errors keep only what the interface may
// show: the status and, for 422, the field and reason of each problem. No
// response body or exception text reaches the screen.

export type Problem = { field: string; reason: string }

export class ApiError extends Error {
  readonly status: number
  readonly problems: Problem[]

  constructor(status: number, problems: Problem[] = []) {
    super(`API error ${status}`)
    this.status = status
    this.problems = problems
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  let response: Response
  try {
    response = await fetch(path, {
      method,
      headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch {
    throw new ApiError(0)
  }
  if (!response.ok) {
    let problems: Problem[] = []
    if (response.status === 422) {
      try {
        const detail = ((await response.json()) as { detail?: unknown }).detail
        if (Array.isArray(detail)) {
          problems = detail
            .filter((p): p is Problem => typeof p?.field === 'string' && typeof p?.reason === 'string')
            .map(({ field, reason }) => ({ field, reason }))
        }
      } catch {
        // an unreadable body is reported by status only
      }
    }
    throw new ApiError(response.status, problems)
  }
  return (await response.json()) as T
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  put: <T>(path: string, body: unknown) => request<T>('PUT', path, body),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body),
}

// --- Types of the responses -------------------------------------------------

export type Ceilings = { max_depth: number; max_candidates: number; max_devices: number; max_datagrams: number }

export type DiscoverySettings = {
  seeds: string[]
  allowed_ranges: string[]
  exclusions: string[]
  max_depth: number
  follow_ip_mac: boolean
  max_candidates: number
  max_devices: number
  max_datagrams: number
  updated_at?: string
  ceilings?: Ceilings
  lab_ranges?: string[]
}

export type CredentialDescription = {
  configured: boolean
  version: string | null
  user: string | null
  level: string | null
  auth_protocol: string | null
  priv_protocol: string | null
  updated_at: string | null
  usable: boolean
}

export type RunStatus = 'pending' | 'running' | 'completed' | 'failed' | 'interrupted'

export type Progress = {
  candidates: number
  reached_by: Record<string, number>
  devices: number
  new_devices: number
  without_answer: number
  reasons: Record<string, number>
  queries: number
}

export type Run = {
  id: number
  kind: string
  status: RunStatus
  requested_at: string
  started_at: string | null
  finished_at: string | null
  error_category: string | null
  summary?: { limits_reached?: string[] } | null
  progress?: Progress
}

export type Page<T> = { total: number; limit: number; offset: number; items: T[] }

export type EvidenceInput = { snapshot?: Record<string, unknown>; [key: string]: unknown }

export type Value = {
  value: unknown
  state: 'value' | 'absent' | 'unknown'
  origin?: 'observed' | 'inferred'
  method?: string | null
  source?: string
  query_id?: number
  run_id?: number
  seen_at?: string
  age_seconds?: number
  stale?: boolean
  evidence?: { inputs?: EvidenceInput[] } | null
}

export type DeviceSummary = {
  id: number
  management_address: string | null
  interface_count: number
  first_seen_at: string | null
  last_seen_at: string | null
  stale: boolean | null
  name: Value
  vendor: Value
  model: Value
  software_version: Value
}

export type Group = {
  first_seen_at: string
  last_seen_at: string
  stale: boolean
  presence: string
  source: string
  fields: Record<string, Value>
}

export type RecordItem = { id: number; groups: Record<string, Group | null>; [key: string]: unknown }

export type DeviceDetail = {
  id: number
  groups: Record<string, Group | null>
  addresses: RecordItem[]
  interfaces: RecordItem[]
}

export const ACTIVE_STATUSES: RunStatus[] = ['pending', 'running']
