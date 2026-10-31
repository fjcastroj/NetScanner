/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Francisco Javier Castro Jiménez
 * Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
 * Computer Engineering, Universidad Internacional de La Rioja (UNIR).
 */

// Translation setup (design D9). To add a language, add its file under
// locales/ and register it in LANGUAGES; nothing else changes.
import i18next, { type i18n } from 'i18next'
import LanguageDetector from 'i18next-browser-languagedetector'
import { initReactI18next } from 'react-i18next'

import en from './locales/en.json'
import es from './locales/es.json'

export const LANGUAGES = { es, en } as const
export type Language = keyof typeof LANGUAGES

export const DEFAULT_LANGUAGE: Language = 'es'
export const STORAGE_KEY = 'netscanner.language'

export function createI18n(): i18n {
  const instance = i18next.createInstance()
  void instance
    .use(LanguageDetector)
    .use(initReactI18next)
    .init({
      resources: Object.fromEntries(
        Object.entries(LANGUAGES).map(([code, translation]) => [code, { translation }]),
      ),
      supportedLngs: Object.keys(LANGUAGES),
      nonExplicitSupportedLngs: true,
      load: 'languageOnly',
      fallbackLng: DEFAULT_LANGUAGE,
      detection: {
        order: ['localStorage', 'navigator'],
        lookupLocalStorage: STORAGE_KEY,
        caches: ['localStorage'],
      },
      interpolation: { escapeValue: false }, // React already escapes
      initAsync: false,
    })
  return instance
}
