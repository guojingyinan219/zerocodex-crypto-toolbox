import { describe, expect, it } from 'vitest'
import { generateKeyPair, issueCertificate } from './pki'
import { validateCertificateChain } from './chain-validation'

describe('CA issuance and chain validation', () => {
  it('issues a leaf from a root with SKI, AKI, KU, EKU and validates it', async () => {
    const rootKey = await generateKeyPair('RSA-2048')
    const root = await issueCertificate(rootKey, { commonName: 'Test Root', organization: 'ZeroCodeX', country: 'CN' }, [], 3650, { type: 'root', pathLen: 1, keyUsages: ['keyCertSign', 'cRLSign'] })
    const leafKey = await generateKeyPair('RSA-2048')
    const leaf = await issueCertificate(leafKey, { commonName: 'service.example.test', organization: 'ZeroCodeX', country: 'CN' }, ['service.example.test'], 365, { type: 'end-entity', serialHex: '010203', keyUsages: ['digitalSignature', 'keyEncipherment'], extendedKeyUsages: ['1.3.6.1.5.5.7.3.1'] }, { certificate: root.der, key: rootKey })
    const report = await validateCertificateChain({ chain: leaf.pem, roots: root.pem, hostname: 'service.example.test', purpose: 'serverAuth' })
    expect(report.findings).toEqual(expect.arrayContaining([expect.objectContaining({ id: 'CHAIN-OK', status: 'pass' }), expect.objectContaining({ id: 'CHAIN-DNS', status: 'pass' }), expect.objectContaining({ id: 'CHAIN-EKU', status: 'pass' })]))
  }, 20_000)

  it('validates an SM2 chain when WebCrypto does not expose SM2', async () => {
    const rootKey = await generateKeyPair('SM2')
    const root = await issueCertificate(rootKey, { commonName: 'SM2 Root', country: 'CN' }, [], 3650, { type: 'root', pathLen: 0 })
    const leafKey = await generateKeyPair('SM2')
    const leaf = await issueCertificate(leafKey, { commonName: 'gm.example.test', country: 'CN' }, ['gm.example.test'], 365, { type: 'end-entity', extendedKeyUsages: ['1.3.6.1.5.5.7.3.1'] }, { certificate: root.der, key: rootKey })
    const report = await validateCertificateChain({ chain: leaf.pem, roots: root.pem, hostname: 'gm.example.test', purpose: 'serverAuth' })
    expect(report.findings).toEqual(expect.arrayContaining([expect.objectContaining({ id: 'CHAIN-OK', status: 'pass' })]))
  })
})
