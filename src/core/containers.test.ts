import { describe, expect, it } from 'vitest'
import forge from 'node-forge'
import { decryptPkcs8, parseCms, parsePkcs12, reencryptPkcs8 } from './containers'
import { generateKeyPair } from './pki'

function binaryBytes(value: string): Uint8Array { return Uint8Array.from(value, (character) => character.charCodeAt(0)) }

function rsaFixture() {
  const keys = forge.pki.rsa.generateKeyPair({ bits: 1024, e: 0x10001 })
  const certificate = forge.pki.createCertificate()
  certificate.publicKey = keys.publicKey
  certificate.serialNumber = '01'
  certificate.validity.notBefore = new Date(Date.now() - 60_000)
  certificate.validity.notAfter = new Date(Date.now() + 86_400_000)
  const attributes = [{ name: 'commonName', value: 'container.test' }]
  certificate.setSubject(attributes); certificate.setIssuer(attributes)
  certificate.sign(keys.privateKey, forge.md.sha256.create())
  return { keys, certificate }
}

describe('PKI containers', () => {
  it('decrypts and inventories PKCS#12', async () => {
    const { keys, certificate } = rsaFixture()
    const asn1 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, [certificate], 'secret', { algorithm: '3des', friendlyName: 'test-key' })
    const source = binaryBytes(forge.asn1.toDer(asn1).getBytes())
    const result = await parsePkcs12(source, 'secret')
    expect(result.groups[0].items).toEqual(expect.arrayContaining([expect.objectContaining({ label: '证书数量', value: '1' }), expect.objectContaining({ label: '私钥数量', value: '1' })]))
    await expect(parsePkcs12(source, 'wrong')).rejects.toThrow('PFX 解密失败')
  })

  it('decrypts and re-encrypts RSA PKCS#8', () => {
    const { keys } = rsaFixture()
    const info = forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(keys.privateKey))
    const encrypted = forge.pki.encryptPrivateKeyInfo(info, 'old-password', { algorithm: 'aes256', count: 10_000, saltSize: 16 })
    const source = binaryBytes(forge.asn1.toDer(encrypted).getBytes())
    const decrypted = decryptPkcs8(source, 'old-password')
    const next = reencryptPkcs8(decrypted.privatePem, 'new-password', 10_000)
    expect(next).toContain('BEGIN ENCRYPTED PRIVATE KEY')
  })

  it('re-encrypts SM2 PKCS#8 without converting the key algorithm', async () => {
    const key = await generateKeyPair('SM2')
    const encryptedPem = reencryptPkcs8(key.privatePem, 'strong-password', 10_000)
    expect(encryptedPem).toContain('BEGIN ENCRYPTED PRIVATE KEY')
    const encryptedDer = Uint8Array.from(forge.util.decode64(encryptedPem.replace(/-----(?:BEGIN|END) ENCRYPTED PRIVATE KEY-----|\s/g, '')), (character) => character.charCodeAt(0))
    expect(decryptPkcs8(encryptedDer, 'strong-password').privatePem).toContain('BEGIN PRIVATE KEY')
  })

  it('recognizes CMS data content', async () => {
    const message = forge.pkcs7.createSignedData()
    message.content = forge.util.createBuffer('hello')
    message.sign()
    const source = binaryBytes(forge.asn1.toDer(message.toAsn1()).getBytes())
    const result = await parseCms(source)
    expect(result.algorithm).toBe('SignedData')
  })
})
