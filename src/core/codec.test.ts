import { describe, expect, it } from 'vitest'
import { auditText, bytesToHex, classifyDer, formatPem, hexToBytes } from './codec'
import { parseAsn1Tree } from './asn1'

describe('codec and ASN.1 utilities', () => {
  it('round trips hex and PEM data', () => {
    const bytes = hexToBytes('30 03 02 01 01')
    expect(bytesToHex(bytes)).toBe('3003020101')
    expect(formatPem(bytes, 'DATA')).toContain('MAMCAQE=')
    expect(classifyDer(bytes)).toBe('unknown')
  })

  it('builds an ASN.1 tree with exact offsets', () => {
    const root = parseAsn1Tree(hexToBytes('3003020101'))
    expect(root.type).toBe('SEQUENCE')
    expect(root.length).toBe(5)
    expect(root.children[0]).toMatchObject({ type: 'INTEGER', offset: 2, length: 3 })
  })

  it('reports BOM and malformed PEM labels', () => {
    const findings = auditText('\ufeff-----BEGIN CERTIFICATE-----\nAAAA\n-----END PRIVATE KEY-----')
    expect(findings.find((item) => item.id === 'C6')?.status).toBe('warn')
    expect(findings.find((item) => item.id === 'C2')?.status).toBe('fail')
  })
})
