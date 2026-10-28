import { describe, expect, it } from 'vitest'
import { sm2GenerateKeyPair } from 'gmkitx'
import { decryptSm2, decryptSm4Advanced, encryptSm2, encryptSm4Advanced, hmacSm3, signSm2, sm2Kdf, sm4Cmac, sm4Gmac, verifySm2 } from './gm-primitives'

describe('GM primitive operations', () => {
  it.each(['raw', 'der'] as const)('signs and verifies SM2 %s signatures', (format) => {
    const key = sm2GenerateKeyPair()
    const signature = signSm2({ privateKey: key.privateKey, message: '签名消息', encoding: 'utf8', format, userId: '1234567812345678' })
    expect(verifySm2({ publicKey: key.publicKey, message: '签名消息', encoding: 'utf8', signature, format, userId: '1234567812345678' })).toBe(true)
    expect(verifySm2({ publicKey: key.publicKey, message: '已篡改', encoding: 'utf8', signature, format, userId: '1234567812345678' })).toBe(false)
  })

  it.each(['C1C3C2', 'C1C2C3'] as const)('round-trips SM2 ciphertext in %s order', (order) => {
    const key = sm2GenerateKeyPair()
    const ciphertext = encryptSm2({ publicKey: key.publicKey, message: '国密互操作', encoding: 'utf8', order })
    expect(decryptSm2({ privateKey: key.privateKey, ciphertext, order, output: 'utf8' })).toBe('国密互操作')
  })

  it('computes stable HMAC-SM3, KDF, CMAC and GMAC values', () => {
    expect(hmacSm3('key', 'abc', 'utf8', 'utf8')).toHaveLength(64)
    expect(sm2Kdf('00112233', 48)).toHaveLength(96)
    expect(sm4Cmac('0123456789ABCDEFFEDCBA9876543210', '')).toHaveLength(32)
    expect(sm4Gmac('0123456789ABCDEFFEDCBA9876543210', '00112233445566778899AABB', 'header', 'utf8')).toHaveLength(32)
  })

  it.each(['CTR', 'GCM', 'CCM'] as const)('round-trips SM4 %s data', (mode) => {
    const iv = mode === 'CTR' ? '00000000000000000000000000000001' : '00112233445566778899AABB'
    const encrypted = encryptSm4Advanced({ mode, key: '0123456789ABCDEFFEDCBA9876543210', iv, data: 'authenticated data', encoding: 'utf8', aad: 'header', aadEncoding: 'utf8', tagLength: 16 })
    expect(decryptSm4Advanced({ mode, key: '0123456789ABCDEFFEDCBA9876543210', iv, ciphertext: encrypted.ciphertext, aad: 'header', aadEncoding: 'utf8', tag: encrypted.tag, tagLength: 16, output: 'utf8' })).toBe('authenticated data')
  })
})
