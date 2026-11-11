/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Francisco Javier Castro Jiménez
 * Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
 * Computer Engineering, Universidad Internacional de La Rioja (UNIR).
 */

// The administrator's session in the interface (add-admin-authentication D8).
// The session itself lives on the server, in an HttpOnly cookie the page
// cannot read; the interface only knows whether the API accepts it. Any 401
// returns to the login screen without changing the URL, so after logging in
// the page that was open is shown again.
import { createContext, type ReactNode, useCallback, useContext, useEffect, useMemo, useState } from 'react'

import { api, ApiError, LOGIN_URL, onUnauthorized, type SessionInfo } from './api'

export type SessionState =
  | { state: 'checking' }
  | { state: 'anonymous' }
  | { state: 'authenticated'; username: string }

type Session = {
  session: SessionState
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

const SessionContext = createContext<Session | null>(null)

export function SessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionState>({ state: 'checking' })

  useEffect(() => {
    let alive = true
    const stop = onUnauthorized(() => {
      if (alive) setSession({ state: 'anonymous' })
    })
    api
      .get<SessionInfo>('/api/auth/session')
      .then((info) => {
        if (alive) setSession({ state: 'authenticated', username: info.username })
      })
      .catch(() => {
        if (alive) setSession({ state: 'anonymous' })
      })
    return () => {
      alive = false
      stop()
    }
  }, [])

  const login = useCallback(async (username: string, password: string) => {
    const info = await api.post<SessionInfo>(LOGIN_URL, { username, password })
    setSession({ state: 'authenticated', username: info.username })
  }, [])

  const logout = useCallback(async () => {
    try {
      await api.post('/api/auth/logout')
    } catch (error) {
      if (!(error instanceof ApiError)) throw error
      // The server ends the session even if the answer is lost; the screen does too.
    }
    setSession({ state: 'anonymous' })
  }, [])

  const value = useMemo(() => ({ session, login, logout }), [session, login, logout])
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
}

export function useSession(): Session {
  const value = useContext(SessionContext)
  if (value === null) throw new Error('useSession outside SessionProvider')
  return value
}
