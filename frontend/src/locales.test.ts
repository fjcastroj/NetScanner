/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Francisco Javier Castro Jiménez
 * Developed as part of the Final Degree Project (TFE), Bachelor's Degree in
 * Computer Engineering, Universidad Internacional de La Rioja (UNIR).
 */

import { describe, expect, it } from 'vitest'

import { DEFAULT_LANGUAGE, LANGUAGES } from './i18n'

type Tree = { [key: string]: string | Tree }

export function flattenKeys(tree: Tree, prefix = ''): string[] {
  return Object.entries(tree).flatMap(([key, value]) =>
    typeof value === 'string' ? [prefix + key] : flattenKeys(value, `${prefix}${key}.`),
  )
}

const reference = flattenKeys(LANGUAGES[DEFAULT_LANGUAGE] as Tree)

describe('translation files', () => {
  it('flattens nested keys', () => {
    expect(flattenKeys({ a: { b: 'x', c: { d: 'y' } }, e: 'z' })).toEqual(['a.b', 'a.c.d', 'e'])
  })

  it.each(Object.entries(LANGUAGES))('%s has exactly the keys of the default language', (_, tree) => {
    const keys = flattenKeys(tree as Tree)
    const missing = reference.filter((key) => !keys.includes(key))
    const extra = keys.filter((key) => !reference.includes(key))
    expect({ missing, extra }).toEqual({ missing: [], extra: [] })
  })

  it.each(Object.entries(LANGUAGES))('%s has no empty texts', (_, tree) => {
    const empty = flattenKeys(tree as Tree).filter((key) => {
      const value = key.split('.').reduce<string | Tree>((node, part) => (node as Tree)[part], tree as Tree)
      return typeof value !== 'string' || value.trim() === ''
    })
    expect(empty).toEqual([])
  })

  it('offers a label for every registered language', () => {
    for (const code of Object.keys(LANGUAGES)) {
      expect(reference).toContain(`language.${code}`)
    }
  })
})
