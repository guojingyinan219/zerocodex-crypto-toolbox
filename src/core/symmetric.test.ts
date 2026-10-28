import { describe, expect, it } from 'vitest'
import { cbcMac, cipherHex, keyCheckValue, xorBlockCheck, xorHex } from './symmetric'

describe('legacy symmetric tools', () => {
  it('matches the standard DES ECB test vector', () => {
    expect(cipherHex({ cipher: 'DES', mode: 'ECB', padding: 'NONE', key: '133457799BBCDFF1', iv: '', data: '0123456789ABCDEF' })).toBe('85E813540F0AB405')
  })

  it('decrypts the standard DES ECB test vector', () => {
    expect(cipherHex({ cipher: 'DES', mode: 'ECB', padding: 'NONE', key: '133457799BBCDFF1', iv: '', data: '85E813540F0AB405', decrypt: true })).toBe('0123456789ABCDEF')
  })

  it('calculates DES KCV from a zero block', () => {
    expect(keyCheckValue('DES', '133457799BBCDFF1')).toEqual({ full: '948A43F98A834F7E', short: '948A43' })
  })

  it('matches the SM4 ECB standard test vector', () => {
    expect(cipherHex({ cipher: 'SM4', mode: 'ECB', padding: 'NONE', key: '0123456789ABCDEFFEDCBA9876543210', iv: '', data: '0123456789ABCDEFFEDCBA9876543210' })).toBe('681EDF34D206965E86B3E94F536E4246')
  })

  it.each(['CFB', 'OFB'] as const)('round-trips arbitrary-length SM4 data in %s mode', (mode) => {
    const args = { cipher: 'SM4' as const, mode, padding: 'NONE' as const, key: '0123456789ABCDEFFEDCBA9876543210', iv: '00000000000000000000000000000000' }
    const encrypted = cipherHex({ ...args, data: '00112233445566778899' })
    expect(encrypted).toMatch(/^[0-9A-F]{20}$/)
    expect(cipherHex({ ...args, data: encrypted, decrypt: true })).toBe('00112233445566778899')
  })

  it('calculates SM4 CBC-MAC with a zero IV', () => {
    expect(cbcMac('SM4', '0123456789ABCDEFFEDCBA9876543210', '0123456789ABCDEFFEDCBA9876543210')).toBe('681EDF34D206965E86B3E94F536E4246')
  })

  it('matches the AES-128 ECB standard test vector', () => {
    expect(cipherHex({ cipher: 'AES-128', mode: 'ECB', padding: 'NONE', key: '000102030405060708090A0B0C0D0E0F', iv: '', data: '00112233445566778899AABBCCDDEEFF' })).toBe('69C4E0D86A7B0430D8CDB78070B4C55A')
  })

  it('xors equal-length blocks and pads the last checksum block', () => {
    expect(xorHex('A55A', '0FF0')).toBe('AAAA')
    expect(xorBlockCheck('010203040506070809')).toBe('0802030405060708')
  })
})
