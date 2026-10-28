import { describe, expect, it } from 'vitest'
import {
  decodeBase64Text,
  decodeHexText,
  decodeUrlText,
  encodeBase64Text,
  encodeHexText,
  encodeUrlText,
  formatJson,
  digestText,
  generateSecureIntegers,
  generateSecureRandomBytes,
  generateSecureRandomStrings
} from './common'

describe('common text tools', () => {
  it('round-trips UTF-8 text through Base64', () => {
    const text = '国密 GMSSL ✓'
    expect(decodeBase64Text(encodeBase64Text(text))).toBe(text)
  })

  it('accepts URL-safe Base64 without padding', () => {
    expect(decodeBase64Text('5Zu95a-G')).toBe('国密')
  })

  it('round-trips UTF-8 text through hex', () => {
    const text = '证书-01'
    expect(decodeHexText(encodeHexText(text))).toBe(text)
  })

  it('encodes and decodes URL components', () => {
    const text = '回调地址?name=国密'
    expect(decodeUrlText(encodeUrlText(text))).toBe(text)
  })

  it('formats and minifies JSON', () => {
    expect(formatJson('{"enabled":true}')).toContain('\n')
    expect(formatJson('{ "enabled": true }', true)).toBe('{"enabled":true}')
  })

  it('calculates legacy MD4 for compatibility checks', async () => {
    await expect(digestText('abc', 'MD4')).resolves.toBe('a448017aaf21d8525fc10ae87aa6729d')
  })

  it('generates secure integers inside the requested inclusive range', () => {
    const values = generateSecureIntegers(-10, 10, 100)
    expect(values).toHaveLength(100)
    expect(values.every((value) => Number.isInteger(value) && value >= -10 && value <= 10)).toBe(true)
  })

  it('validates secure integer limits', () => {
    expect(() => generateSecureIntegers(10, 1)).toThrow('最小值')
    expect(() => generateSecureIntegers(0, 0x1_0000_0000)).toThrow('2^32')
    expect(() => generateSecureIntegers(0, 10, 1001)).toThrow('生成数量')
  })

  it('generates random bytes in Hex, Base64 and Base64URL formats', () => {
    const hexValues = generateSecureRandomBytes(16, 2, 'hex')
    expect(hexValues).toHaveLength(2)
    expect(hexValues.every((value) => /^[0-9a-f]{32}$/.test(value))).toBe(true)
    expect(generateSecureRandomBytes(12, 1, 'base64')[0]).toMatch(/^[A-Za-z0-9+/]{16}$/)
    expect(generateSecureRandomBytes(12, 1, 'base64url')[0]).toMatch(/^[A-Za-z0-9_-]{16}$/)
  })

  it('generates secure random strings from selected character sets', () => {
    const values = generateSecureRandomStrings(32, 5, ['abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', '0123456789', '!@#$%'])
    expect(values).toHaveLength(5)
    expect(values.every((value) => value.length === 32 && /^[A-Za-z0-9!@#$%]+$/.test(value))).toBe(true)
  })

  it('validates random string length, count and character pool', () => {
    expect(() => generateSecureRandomStrings(0, 1, ['abc'])).toThrow('字符串长度')
    expect(() => generateSecureRandomStrings(32, 101, ['abc'])).toThrow('生成数量')
    expect(() => generateSecureRandomStrings(32, 1, [''])).toThrow('字符集')
  })
})
