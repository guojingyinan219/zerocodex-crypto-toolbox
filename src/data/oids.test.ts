import { describe, expect, it } from 'vitest'
import { oidMap, oidName, oidRecords } from './oids'

describe('OID dictionary', () => {
  it('contains unique, complete records', () => {
    expect(oidRecords.length).toBeGreaterThanOrEqual(160)
    expect(oidMap.size).toBe(oidRecords.length)

    for (const record of oidRecords) {
      expect(record.oid).toMatch(/^\d+(\.\d+)+$/)
      expect(record.name.trim()).not.toBe('')
      expect(record.english.trim()).not.toBe('')
      expect(record.category.trim()).not.toBe('')
      expect(record.standard.trim()).not.toBe('')
      expect(record.description.trim()).not.toBe('')
    }
  })

  it('covers the major national and international key families', () => {
    const required = [
      '1.2.156.10197.1.301',
      '1.2.840.113549.1.1.1',
      '1.2.840.10045.2.1',
      '1.3.101.110',
      '1.3.101.112',
      '2.16.840.1.101.3.4.4.2',
      '2.16.840.1.101.3.4.1.46',
      '1.2.840.113549.1.5.12',
      '2.5.29.37'
    ]

    for (const oid of required) expect(oidMap.has(oid)).toBe(true)
  })

  it('resolves known and unknown names', () => {
    expect(oidName('1.2.156.10197.1.501')).toBe('SM3withSM2 签名')
    expect(oidName('1.2.840.113549.1.1.1')).toBe('RSA 公钥')
    expect(oidName('9.9.9')).toBe('未知 OID')
  })
})
