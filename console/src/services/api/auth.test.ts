import { describe, it, expect, afterEach } from 'vitest'
import { parseRootEmails, isRootUser } from './auth'

function setRootEmail(value: string | undefined) {
  ;(window as unknown as { ROOT_EMAIL?: string }).ROOT_EMAIL = value as string
}

describe('parseRootEmails', () => {
  it('returns [] for empty or undefined', () => {
    expect(parseRootEmails(undefined)).toEqual([])
    expect(parseRootEmails('')).toEqual([])
  })

  it('parses a single email', () => {
    expect(parseRootEmails('alice@example.com')).toEqual(['alice@example.com'])
  })

  it('parses comma-separated emails', () => {
    expect(parseRootEmails('alice@example.com,bob@example.com')).toEqual([
      'alice@example.com',
      'bob@example.com'
    ])
  })

  it('parses semicolon-separated emails', () => {
    expect(parseRootEmails('alice@example.com;bob@example.com')).toEqual([
      'alice@example.com',
      'bob@example.com'
    ])
  })

  it('trims whitespace and drops empty entries', () => {
    expect(parseRootEmails(' alice@example.com , , bob@example.com ')).toEqual([
      'alice@example.com',
      'bob@example.com'
    ])
  })

  it('splits on whitespace (mirrors backend and the tag separators)', () => {
    expect(parseRootEmails('alice@example.com bob@example.com')).toEqual([
      'alice@example.com',
      'bob@example.com'
    ])
    expect(parseRootEmails('alice@example.com,  bob@example.com\tcarol@example.com')).toEqual([
      'alice@example.com',
      'bob@example.com',
      'carol@example.com'
    ])
  })

  it('preserves case', () => {
    expect(parseRootEmails('Alice@example.com')).toEqual(['Alice@example.com'])
  })
})

describe('isRootUser', () => {
  afterEach(() => {
    setRootEmail(undefined)
  })

  it('returns false when no user email is given', () => {
    setRootEmail('alice@example.com')
    expect(isRootUser(undefined)).toBe(false)
    expect(isRootUser('')).toBe(false)
  })

  it('returns false when ROOT_EMAIL is not set', () => {
    setRootEmail(undefined)
    expect(isRootUser('alice@example.com')).toBe(false)
  })

  it('matches a single configured root (backward compatible)', () => {
    setRootEmail('alice@example.com')
    expect(isRootUser('alice@example.com')).toBe(true)
    expect(isRootUser('bob@example.com')).toBe(false)
  })

  it('matches any email in a configured list', () => {
    setRootEmail('alice@example.com,bob@example.com')
    expect(isRootUser('alice@example.com')).toBe(true)
    expect(isRootUser('bob@example.com')).toBe(true)
    expect(isRootUser('carol@example.com')).toBe(false)
  })

  it('is case-sensitive', () => {
    setRootEmail('alice@example.com')
    expect(isRootUser('Alice@example.com')).toBe(false)
  })
})
