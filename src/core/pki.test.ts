import { describe, expect, it } from 'vitest'
import { sm3Digest } from 'gmkitx'
import {
  compareReports,
  formatSm2KeyComponents,
  generateKeyPair,
  generateSm2Certificate,
  generateSm2Csr,
  importSm2KeyPair,
  parseCertificate,
  parseCsr,
  parseKey
} from './pki'

describe('SM2 PKI workflow', () => {
  it('matches the published SM3 abc vector', () => {
    expect(sm3Digest('abc')).toBe('66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')
  })

  it('generates parseable and matching key, CSR and certificate', async () => {
    const key = await generateKeyPair('SM2')
    const subject = { commonName: 'interop.gm.local', organization: 'GM Toolbox', country: 'CN' }
    const csr = generateSm2Csr(key, subject, ['interop.gm.local'])
    const certificate = await generateSm2Certificate(key, subject, ['interop.gm.local'], 30, false)
    const keyReport = await parseKey(key.privateDer, 'private-key')
    const csrReport = await parseCsr(csr.der)
    const certReport = await parseCertificate(certificate.der)

    expect(csrReport.algorithm).toBe('SM2')
    expect(csrReport.findings.find((item) => item.id === 'GM-CSR-0000')?.status).toBe('pass')
    expect(csrReport.findings.some((item) => item.id === 'GM-CSR-3001')).toBe(false)
    expect(csrReport.groups[0].items.find((item) => item.label === '请求的 SAN')?.value).toContain('DNS:interop.gm.local')
    expect(certReport.algorithm).toBe('SM2')
    for (const report of [csrReport, certReport]) {
      const items = report.groups.flatMap((group) => group.items)
      expect(items.find((item) => item.label === '公钥 X')?.value).toMatch(/^[0-9A-F]{64}$/)
      expect(items.find((item) => item.label === '公钥 Y')?.value).toMatch(/^[0-9A-F]{64}$/)
      expect(items.find((item) => item.label === '私钥 D')?.value).toContain('不包含私钥信息')
      expect(items.find((item) => item.label === '公钥 Hex（X || Y）')?.value).toMatch(/^[0-9A-F]{128}$/)
      expect(items.find((item) => item.label === '完整公钥 Hex（04 || X || Y）')?.value).toMatch(/^04[0-9A-F]{128}$/)
      expect(items.find((item) => item.label === '公钥 PEM（SPKI）')?.value).toMatch(/^-----BEGIN PUBLIC KEY-----/)
    }
    const privateItems = keyReport.groups.flatMap((group) => group.items)
    expect(privateItems.find((item) => item.label === '公钥 X')?.value).toMatch(/^[0-9A-F]{64}$/)
    expect(privateItems.find((item) => item.label === '公钥 Y')?.value).toMatch(/^[0-9A-F]{64}$/)
    expect(privateItems.find((item) => item.label === '私钥 D')).toMatchObject({
      value: expect.stringMatching(/^[0-9A-F]{64}$/),
      sensitive: true
    })
    expect(privateItems.find((item) => item.label === '公私钥 Hex（X || Y || D）')).toMatchObject({
      value: expect.stringMatching(/^[0-9A-F]{192}$/),
      sensitive: true
    })
    expect(privateItems.find((item) => item.label === '完整公私钥 Hex（04 || X || Y || D）')).toMatchObject({
      value: expect.stringMatching(/^04[0-9A-F]{192}$/),
      sensitive: true
    })
    expect(privateItems.find((item) => item.label === '私钥 PEM（PKCS#8）')).toMatchObject({
      value: expect.stringMatching(/^-----BEGIN PRIVATE KEY-----/),
      sensitive: true
    })
    expect(compareReports(csrReport, keyReport)[0].status).toBe('pass')
    expect(compareReports(certReport, keyReport)[0].status).toBe('pass')
  })

  it('imports matching SM2 X, Y and D components', async () => {
    const generated = await generateKeyPair('SM2')
    const x = generated.publicKeyHex.slice(2, 66)
    const y = generated.publicKeyHex.slice(66)
    const formats = formatSm2KeyComponents(x, y, generated.privateKeyHex)
    const imported = importSm2KeyPair(x, y, generated.privateKeyHex!)

    expect(formats.publicKeyXYHex).toBe(`${x}${y}`.toUpperCase())
    expect(formats.publicKeyHex).toMatch(/^04[0-9A-F]{128}$/)
    expect(formats.keyPairHex).toBe(`${x}${y}${generated.privateKeyHex}`.toUpperCase())
    expect(formats.completeKeyPairHex).toBe(`04${x}${y}${generated.privateKeyHex}`.toUpperCase())
    expect(formats.publicPem).toMatch(/^-----BEGIN PUBLIC KEY-----/)
    expect(formats.privatePem).toMatch(/^-----BEGIN PRIVATE KEY-----/)
    expect(imported.publicKeyHex).toBe(generated.publicKeyHex.toUpperCase())
    expect(imported.privateKeyHex).toBe(generated.privateKeyHex?.toUpperCase())

    const publicReport = await parseKey(imported.publicDer, 'public-key')
    const privateReport = await parseKey(imported.privateDer, 'private-key')
    expect(publicReport.algorithm).toBe('SM2')
    expect(privateReport.groups.flatMap((group) => group.items).find((item) => item.label === '私钥 PEM（PKCS#8）')).toMatchObject({ sensitive: true })
  })
})
