import { fromBER } from 'asn1js'
import { BasicOCSPResponse, Certificate, CertificateChainValidationEngine, CertificateRevocationList, OCSPResponse } from 'pkijs'
import { sm2Verify } from 'gmkitx'
import type { FieldGroup, Finding, ParseReport } from '../types'
import { bytesToHex, decodeFlexibleInput, extractPemBlocks } from './codec'

export interface ChainValidationOptions {
  chain: string
  roots: string
  crls?: string
  ocsps?: string
  hostname?: string
  checkDate?: Date
  purpose?: 'any' | 'serverAuth' | 'clientAuth' | 'codeSigning' | 'emailProtection'
}

function parseCertificates(input: string): Certificate[] {
  const blocks = extractPemBlocks(input).filter((item) => item.label === 'CERTIFICATE')
  const values = blocks.length ? blocks.map((item) => item.text) : input.trim() ? [input] : []
  return values.map((value) => {
    const decoded = decodeFlexibleInput(value)
    const parsed = fromBER(Uint8Array.from(decoded.bytes).buffer)
    if (parsed.offset === -1) throw new Error('证书链中存在无效 ASN.1 证书。')
    return new Certificate({ schema: parsed.result })
  })
}

function parseCrls(input = ''): CertificateRevocationList[] {
  if (!input.trim()) return []
  const blocks = extractPemBlocks(input)
  const values = blocks.length ? blocks.map((item) => item.text) : [input]
  return values.map((value) => {
    const decoded = decodeFlexibleInput(value)
    const parsed = fromBER(Uint8Array.from(decoded.bytes).buffer)
    if (parsed.offset === -1) throw new Error('CRL 不是有效 ASN.1 数据。')
    return new CertificateRevocationList({ schema: parsed.result })
  })
}

function parseOcsps(input = ''): BasicOCSPResponse[] {
  if (!input.trim()) return []
  const blocks = extractPemBlocks(input)
  const values = blocks.length ? blocks.map((item) => item.text) : [input]
  return values.map((value) => {
    const decoded = decodeFlexibleInput(value)
    const parsed = fromBER(Uint8Array.from(decoded.bytes).buffer)
    if (parsed.offset === -1) throw new Error('OCSP 响应不是有效 ASN.1 数据。')
    try {
      const response = new OCSPResponse({ schema: parsed.result })
      if (!response.responseBytes) throw new Error('OCSP 响应没有 ResponseBytes。')
      const basic = fromBER(response.responseBytes.response.valueBlock.valueHex)
      if (basic.offset === -1) throw new Error('BasicOCSPResponse 数据无效。')
      return new BasicOCSPResponse({ schema: basic.result })
    } catch {
      return new BasicOCSPResponse({ schema: parsed.result })
    }
  })
}

function name(certificate: Certificate, issuer = false): string {
  const target = issuer ? certificate.issuer : certificate.subject
  return target.typesAndValues.map((item) => `${item.type}=${item.value.valueBlock.value ?? item.value.toString()}`).join(', ')
}

function extension(certificate: Certificate, oid: string): any {
  return certificate.extensions?.find((item) => item.extnID === oid)?.parsedValue
}

function dnsNames(certificate: Certificate): string[] {
  const san = extension(certificate, '2.5.29.17')
  return (san?.altNames ?? []).filter((item: any) => item.type === 2).map((item: any) => String(item.value))
}

function matchHostname(hostname: string, pattern: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, '')
  const value = pattern.toLowerCase().replace(/\.$/, '')
  if (!value.startsWith('*.')) return host === value
  const suffix = value.slice(1)
  return host.endsWith(suffix) && host.split('.').length === value.split('.').length
}

function ekuOids(certificate: Certificate): string[] {
  return extension(certificate, '2.5.29.37')?.keyPurposes ?? []
}

function aiaUrls(certificate: Certificate): string[] {
  const aia = extension(certificate, '1.3.6.1.5.5.7.1.1')
  return (aia?.accessDescriptions ?? []).map((item: any) => item.accessLocation?.value).filter((item: unknown): item is string => typeof item === 'string')
}

function verifySm2Path(certs: Certificate[], roots: Certificate[], date: Date): { valid: boolean; message: string; length: number } {
  const candidates = [...certs.slice(1), ...roots]
  let current = certs[0]
  const visited = new Set<string>()
  for (let depth = 0; depth <= candidates.length; depth++) {
    if (date < current.notBefore.value || date > current.notAfter.value) return { valid: false, message: `证书不在验证时间内：${name(current)}`, length: depth + 1 }
    const issuer = candidates.find((item) => name(item) === name(current, true) && !visited.has(name(item)))
    if (!issuer) return { valid: false, message: `找不到签发者：${name(current, true)}`, length: depth + 1 }
    const publicKey = bytesToHex(issuer.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView)
    let signatureValid = false
    try { signatureValid = sm2Verify(publicKey, current.tbsView, current.signatureValue.valueBlock.valueHexView, { signatureFormat: 'der' }) } catch { signatureValid = false }
    if (!signatureValid) return { valid: false, message: `SM2 签名验证失败：${name(current)}`, length: depth + 1 }
    const trusted = roots.some((root) => name(root) === name(issuer) && bytesToHex(root.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView) === publicKey)
    if (trusted) return { valid: true, message: `SM2 证书链签名与自定义信任根匹配，共 ${depth + 2} 张证书。`, length: depth + 2 }
    const constraints = extension(issuer, '2.5.29.19')
    if (!constraints?.cA) return { valid: false, message: `签发者不是 CA：${name(issuer)}`, length: depth + 2 }
    visited.add(name(issuer)); current = issuer
  }
  return { valid: false, message: 'SM2 证书链存在循环或超过最大深度。', length: candidates.length + 1 }
}

export async function validateCertificateChain(options: ChainValidationOptions): Promise<ParseReport> {
  const certs = parseCertificates(options.chain)
  const trustedCerts = parseCertificates(options.roots)
  if (!certs.length) throw new Error('请至少提供一张终端证书。')
  if (!trustedCerts.length) throw new Error('请提供至少一张自定义信任根。')
  const crls = parseCrls(options.crls)
  const ocsps = parseOcsps(options.ocsps)
  const date = options.checkDate ?? new Date()
  const findings: Finding[] = []
  const groups: FieldGroup[] = []
  const leaf = certs[0]
  const engine = new CertificateChainValidationEngine({ certs, trustedCerts, crls, ocsps, checkDate: date })
  try {
    const result = await engine.verify({ passedWhenNotRevValues: crls.length === 0 && ocsps.length === 0 })
    if (result.result) findings.push({ id: 'CHAIN-OK', status: 'pass', title: '证书链验证通过', detail: `已构建到自定义信任根，共 ${result.certificatePath?.length ?? certs.length} 张证书。` })
    else if (leaf.signatureAlgorithm.algorithmId === '1.2.156.10197.1.501') {
      const fallback = verifySm2Path(certs, trustedCerts, date)
      findings.push(fallback.valid ? { id: 'CHAIN-OK', status: 'pass', title: 'SM2 证书链验证通过', detail: fallback.message } : { id: 'CHAIN-FAIL', status: 'fail', title: 'SM2 证书链验证失败', detail: fallback.message })
    } else findings.push({ id: 'CHAIN-FAIL', status: 'fail', title: '证书链验证失败', detail: result.resultMessage || `错误码 ${result.resultCode}` })
  } catch (cause) {
    if (leaf.signatureAlgorithm.algorithmId === '1.2.156.10197.1.501') {
      const fallback = verifySm2Path(certs, trustedCerts, date)
      findings.push(fallback.valid ? { id: 'CHAIN-OK', status: 'pass', title: 'SM2 证书链验证通过', detail: fallback.message } : { id: 'CHAIN-FAIL', status: 'fail', title: 'SM2 证书链验证失败', detail: fallback.message })
    } else findings.push({ id: 'CHAIN-ENGINE', status: 'fail', title: '证书链验证失败', detail: cause instanceof Error ? cause.message : '验证引擎异常' })
  }

  const names = dnsNames(leaf)
  if (options.hostname?.trim()) findings.push(names.some((item) => matchHostname(options.hostname!, item))
    ? { id: 'CHAIN-DNS', status: 'pass', title: '域名匹配', detail: `${options.hostname} 与证书 SAN 匹配。` }
    : { id: 'CHAIN-DNS', status: 'fail', title: '域名不匹配', detail: `目标 ${options.hostname} 不在证书 SAN 中。` })

  const purposeOids: Record<string, string> = { serverAuth: '1.3.6.1.5.5.7.3.1', clientAuth: '1.3.6.1.5.5.7.3.2', codeSigning: '1.3.6.1.5.5.7.3.3', emailProtection: '1.3.6.1.5.5.7.3.4' }
  if (options.purpose && options.purpose !== 'any') {
    const ekus = ekuOids(leaf); const required = purposeOids[options.purpose]
    findings.push(!ekus.length || ekus.includes(required) || ekus.includes('2.5.29.37.0')
      ? { id: 'CHAIN-EKU', status: 'pass', title: '证书用途匹配', detail: `EKU 允许 ${options.purpose}。` }
      : { id: 'CHAIN-EKU', status: 'fail', title: '证书用途不匹配', detail: `EKU 未包含 ${required}。` })
  }
  if (!crls.length && !ocsps.length) findings.push({ id: 'CHAIN-REV', status: 'warn', title: '未执行吊销检查', detail: '未提供 CRL 或 OCSP 响应；链可信不等于证书当前未被吊销。' })
  else findings.push({ id: 'CHAIN-REV', status: 'pass', title: '已加载吊销状态材料', detail: `验证时使用了 ${crls.length} 份 CRL、${ocsps.length} 份 OCSP 响应。` })
  const urls = certs.flatMap(aiaUrls)
  groups.push({ title: '验证条件', items: [
    { label: '检查时间', value: date.toISOString() }, { label: '终端主题', value: name(leaf) }, { label: '终端颁发者', value: name(leaf, true) },
    { label: '用途', value: options.purpose ?? 'any' }, { label: '域名', value: options.hostname || '未指定' }, { label: '自定义根', value: `${trustedCerts.length} 张` }
  ] })
  groups.push({ title: '状态与在线服务', items: [
    { label: 'CRL / OCSP', value: `${crls.length} 份 CRL · ${ocsps.length} 份 OCSP 响应` },
    { label: 'AIA / OCSP / CA Issuers', value: urls.length ? urls.join('\n') : '证书未声明', mono: true },
    { label: '在线获取策略', value: '默认关闭；本站不会在浏览器中自动请求证书声明的 URL' }
  ] })
  const failed = findings.some((item) => item.status === 'fail')
  return { kind: 'certificate', label: '证书链验证', algorithm: leaf.signatureAlgorithm.algorithmId, summary: `${certs.length} 张链证书 · ${trustedCerts.length} 张信任根`, status: failed ? 'fail' : findings.some((item) => item.status === 'warn') ? 'warn' : 'pass', findings, groups, bytes: new Uint8Array(leaf.toSchema(true).toBER(false)) }
}
