import { describe, expect, it } from 'vitest'
import {
  digestSm3,
  generateSm2PartyMaterial,
  runSm2KeyAgreement,
  sm2SignaturePrehash
} from './gm-advanced'

describe('advanced GM algorithms', () => {
  it('calculates SM3 from text and hex inputs', () => {
    const expected = '66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0'
    expect(digestSm3('abc', 'text')).toBe(expected)
    expect(digestSm3('616263', 'hex')).toBe(expected)
  })

  it('binds the SM2 signature digest to the user ID and public key', () => {
    const party = generateSm2PartyMaterial()
    const first = sm2SignaturePrehash({ publicX: party.publicX, publicY: party.publicY, userId: 'Alice', userIdEncoding: 'text', data: '616263', dataEncoding: 'hex' })
    const second = sm2SignaturePrehash({ publicX: party.publicX, publicY: party.publicY, userId: 'Bob', userIdEncoding: 'text', data: '616263', dataEncoding: 'hex' })
    expect(first.za).toMatch(/^[0-9A-F]{64}$/)
    expect(first.digest).toMatch(/^[0-9A-F]{64}$/)
    expect(first.za).not.toBe(second.za)
    expect(first.digest).not.toBe(second.digest)
  })

  it('derives the same SM2 shared key and confirmation values for A and B', () => {
    const a = generateSm2PartyMaterial()
    const b = generateSm2PartyMaterial()
    const resultA = runSm2KeyAgreement({
      privateKey: a.privateKey,
      tempPrivateKey: a.tempPrivateKey,
      peerPublicX: b.publicX,
      peerPublicY: b.publicY,
      peerTempPublicX: b.tempPublicX,
      peerTempPublicY: b.tempPublicY,
      userId: 'Alice',
      peerUserId: 'Bob',
      isInitiator: true,
      keyLength: 16
    })
    const resultB = runSm2KeyAgreement({
      privateKey: b.privateKey,
      tempPrivateKey: b.tempPrivateKey,
      peerPublicX: a.publicX,
      peerPublicY: a.publicY,
      peerTempPublicX: a.tempPublicX,
      peerTempPublicY: a.tempPublicY,
      userId: 'Bob',
      peerUserId: 'Alice',
      isInitiator: false,
      keyLength: 16
    })
    expect(resultA.sharedKey).toBe(resultB.sharedKey)
    expect(resultA.sharedKey).toMatch(/^[0-9A-F]{32}$/)
    expect(resultA.s1).toBe(resultB.s1)
    expect(resultA.s2).toBe(resultB.s2)
  })
})
