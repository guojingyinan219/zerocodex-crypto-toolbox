import { fromBER } from 'asn1js'
import { Certificate, CertificationRequest, Extensions, GeneralNames } from 'pkijs'
import {
  configureRNG,
  sm2GenerateKeyPair,
  sm2GetPublicKeyFromPrivateKey,
  sm2Sign,
  sm2Verify,
  sm3Digest
} from 'gmkitx'
import { oidName } from '../data/oids'
import type { FieldGroup, Finding, MaterialKind, ParseReport, Status } from '../types'
import {
  bytesToBase64,
  bytesToHex,
  classifyDer,
  decodeFlexibleInput,
  formatPem,
  hexToBytes
} from './codec'

configureRNG('strict')

const OIDS = {
  commonName: '2.5.4.3',
  country: '2.5.4.6',
  locality: '2.5.4.7',
  state: '2.5.4.8',
  organization: '2.5.4.10',
  organizationalUnit: '2.5.4.11',
  email: '1.2.840.113549.1.9.1',
  ecPublicKey: '1.2.840.10045.2.1',
  sm2Curve: '1.2.156.10197.1.301',
  sm3WithSm2: '1.2.156.10197.1.501',
  rsa: '1.2.840.113549.1.1.1',
  sha256WithRsa: '1.2.840.113549.1.1.11',
  extensionRequest: '1.2.840.113549.1.9.14',
  basicConstraints: '2.5.29.19',
  keyUsage: '2.5.29.15',
  san: '2.5.29.17',
  ski: '2.5.29.14',
  aki: '2.5.29.35'
  ,extendedKeyUsage: '2.5.29.37'
}

const dnLabels: Record<string, string> = {
  [OIDS.commonName]: 'CN',
  [OIDS.country]: 'C',
  [OIDS.locality]: 'L',
  [OIDS.state]: 'ST',
  [OIDS.organization]: 'O',
  [OIDS.organizationalUnit]: 'OU',
  [OIDS.email]: 'emailAddress'
}

type PkiName = {
  typesAndValues: Array<{
    type: string
    value: { valueBlock?: { value?: string; valueHexView?: Uint8Array }; toString?: () => string }
  }>
}

export interface GeneratedKeyPair {
  algorithm: string
  privatePem: string
  publicPem: string
  privateDer: Uint8Array
  publicDer: Uint8Array
  publicKeyHex: string
  privateKeyHex?: string
  jwk?: JsonWebKey
}

export interface Sm2KeyFormats {
  x: string
  y: string
  d?: string
  publicKeyXYHex: string
  publicKeyHex: string
  keyPairHex?: string
  completeKeyPairHex?: string
  publicPem: string
  privatePem?: string
  publicDer: Uint8Array
  privateDer?: Uint8Array
}

export interface SubjectInput {
  commonName: string
  organization?: string
  organizationalUnit?: string
  country?: string
  email?: string
}

export interface CertificateProfile {
  type: 'root' | 'intermediate' | 'end-entity'
  serialHex?: string
  pathLen?: number
  keyUsages?: Array<'digitalSignature' | 'contentCommitment' | 'keyEncipherment' | 'dataEncipherment' | 'keyAgreement' | 'keyCertSign' | 'cRLSign'>
  extendedKeyUsages?: string[]
}

export interface IssuerMaterial {
  certificate: Uint8Array
  key: GeneratedKeyPair
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0))
  let offset = 0
  for (const part of parts) {
    output.set(part, offset)
    offset += part.length
  }
  return output
}

function encodeLength(length: number): Uint8Array {
  if (length < 0x80) return Uint8Array.of(length)
  const bytes: number[] = []
  let value = length
  while (value > 0) {
    bytes.unshift(value & 0xff)
    value >>>= 8
  }
  return Uint8Array.of(0x80 | bytes.length, ...bytes)
}

function tlv(tag: number, content: Uint8Array): Uint8Array {
  return concat(Uint8Array.of(tag), encodeLength(content.length), content)
}

function sequence(...parts: Uint8Array[]): Uint8Array {
  return tlv(0x30, concat(...parts))
}

function set(...parts: Uint8Array[]): Uint8Array {
  return tlv(0x31, concat(...parts))
}

function integer(value: number | Uint8Array): Uint8Array {
  let bytes: Uint8Array
  if (typeof value === 'number') {
    const list: number[] = []
    let cursor = value
    do {
      list.unshift(cursor & 0xff)
      cursor >>>= 8
    } while (cursor > 0)
    bytes = Uint8Array.from(list)
  } else {
    let firstNonZero = 0
    while (firstNonZero < value.length - 1 && value[firstNonZero] === 0) firstNonZero += 1
    bytes = value.subarray(firstNonZero)
  }
  if (bytes[0] & 0x80) bytes = concat(Uint8Array.of(0), bytes)
  return tlv(0x02, bytes)
}

function objectIdentifier(value: string): Uint8Array {
  const arcs = value.split('.').map(Number)
  if (arcs.length < 2) throw new Error(`OID ${value} 不完整`)
  const output = [arcs[0] * 40 + arcs[1]]
  for (const arc of arcs.slice(2)) {
    const encoded = [arc & 0x7f]
    let cursor = Math.floor(arc / 128)
    while (cursor > 0) {
      encoded.unshift(0x80 | (cursor & 0x7f))
      cursor = Math.floor(cursor / 128)
    }
    output.push(...encoded)
  }
  return tlv(0x06, Uint8Array.from(output))
}

function utf8(value: string): Uint8Array {
  return tlv(0x0c, new TextEncoder().encode(value))
}

function printable(value: string): Uint8Array {
  return tlv(0x13, new TextEncoder().encode(value))
}

function ia5(value: string): Uint8Array {
  return tlv(0x16, new TextEncoder().encode(value))
}

function octetString(value: Uint8Array): Uint8Array {
  return tlv(0x04, value)
}

function bitString(value: Uint8Array, unusedBits = 0): Uint8Array {
  return tlv(0x03, concat(Uint8Array.of(unusedBits), value))
}

function boolean(value: boolean): Uint8Array {
  return tlv(0x01, Uint8Array.of(value ? 0xff : 0))
}

function explicit(tag: number, value: Uint8Array): Uint8Array {
  return tlv(0xa0 + tag, value)
}

function algorithmIdentifier(algorithmOid: string, parameterOid?: string, includeNull = false): Uint8Array {
  const parts = [objectIdentifier(algorithmOid)]
  if (parameterOid) parts.push(objectIdentifier(parameterOid))
  else if (includeNull) parts.push(tlv(0x05, new Uint8Array()))
  return sequence(...parts)
}

function encodeName(subject: SubjectInput): Uint8Array {
  const attributes: Array<[string, string, 'printable' | 'utf8' | 'ia5']> = []
  if (subject.country) attributes.push([OIDS.country, subject.country.toUpperCase().slice(0, 2), 'printable'])
  if (subject.organization) attributes.push([OIDS.organization, subject.organization, 'utf8'])
  if (subject.organizationalUnit) attributes.push([OIDS.organizationalUnit, subject.organizationalUnit, 'utf8'])
  attributes.push([OIDS.commonName, subject.commonName, 'utf8'])
  if (subject.email) attributes.push([OIDS.email, subject.email, 'ia5'])
  return sequence(...attributes.map(([oid, value, type]) => set(sequence(objectIdentifier(oid), type === 'printable' ? printable(value) : type === 'ia5' ? ia5(value) : utf8(value)))))
}

function encodeSm2Spki(publicKeyHex: string): Uint8Array {
  return sequence(
    algorithmIdentifier(OIDS.ecPublicKey, OIDS.sm2Curve),
    bitString(hexToBytes(publicKeyHex))
  )
}

function encodeSm2PrivateKey(privateKeyHex: string, publicKeyHex: string): { pkcs8: Uint8Array; spki: Uint8Array } {
  const spki = encodeSm2Spki(publicKeyHex)
  const ecPrivateKey = sequence(
    integer(1),
    octetString(hexToBytes(privateKeyHex.padStart(64, '0'))),
    explicit(0, objectIdentifier(OIDS.sm2Curve)),
    explicit(1, bitString(hexToBytes(publicKeyHex)))
  )
  const pkcs8 = sequence(
    integer(0),
    algorithmIdentifier(OIDS.ecPublicKey, OIDS.sm2Curve),
    octetString(ecPrivateKey)
  )
  return { pkcs8, spki }
}

function encodeSans(values: string[]): Uint8Array {
  const names = values.filter(Boolean).map((value) => {
    if (/^[\d.]+$/.test(value) && value.split('.').length === 4) {
      const octets = value.split('.').map(Number)
      if (octets.every((item) => item >= 0 && item <= 255)) return tlv(0x87, Uint8Array.from(octets))
    }
    if (/^[^@\s]+@[^@\s]+$/.test(value)) return tlv(0x81, new TextEncoder().encode(value))
    if (/^[a-z]+:\/\//i.test(value)) return tlv(0x86, new TextEncoder().encode(value))
    return tlv(0x82, new TextEncoder().encode(value))
  })
  return sequence(...names)
}

function extension(oid: string, valueDer: Uint8Array, critical = false): Uint8Array {
  return sequence(objectIdentifier(oid), ...(critical ? [boolean(true)] : []), octetString(valueDer))
}

function encodeExtensionRequest(sans: string[]): Uint8Array {
  const extensions = [extension(OIDS.san, encodeSans(sans))]
  const attribute = sequence(objectIdentifier(OIDS.extensionRequest), set(sequence(...extensions)))
  return tlv(0xa0, attribute)
}

function formatDate(date: Date): Uint8Array {
  const year = date.getUTCFullYear()
  const text = `${year < 2050 ? String(year).slice(-2) : String(year)}${String(date.getUTCMonth() + 1).padStart(2, '0')}${String(date.getUTCDate()).padStart(2, '0')}${String(date.getUTCHours()).padStart(2, '0')}${String(date.getUTCMinutes()).padStart(2, '0')}${String(date.getUTCSeconds()).padStart(2, '0')}Z`
  return tlv(year < 2050 ? 0x17 : 0x18, new TextEncoder().encode(text))
}

function formatDn(name: PkiName): { display: string; values: Record<string, string> } {
  const values: Record<string, string> = {}
  const items = name.typesAndValues.map((attribute) => {
    const label = dnLabels[attribute.type] ?? attribute.type
    const value = String(attribute.value.valueBlock?.value ?? attribute.value.toString?.() ?? '')
    values[label] = value
    return `${label}=${value.replace(/([,=+<>#;"\\])/g, '\\$1')}`
  })
  return { display: items.reverse().join(','), values }
}

function getAlgorithmDetails(info: { algorithm: { algorithmId: string; algorithmParams?: unknown }; subjectPublicKey: { valueBlock: { valueHexView: Uint8Array } } }): { algorithm: string; curve?: string; publicKeyHex: string; bits: number } {
  const algorithmOid = info.algorithm.algorithmId
  let curveOid = ''
  const params = info.algorithm.algorithmParams as { valueBlock?: { toString?: () => string } } | undefined
  if (params?.valueBlock?.toString) curveOid = params.valueBlock.toString()
  const publicKey = info.subjectPublicKey.valueBlock.valueHexView
  if (algorithmOid === OIDS.rsa) {
    const parsed = fromBER(asArrayBuffer(publicKey))
    const root = parsed.result as { valueBlock?: { value?: Array<{ valueBlock?: { valueHexView?: Uint8Array } }> } }
    const modulus = root.valueBlock?.value?.[0]?.valueBlock?.valueHexView
    return { algorithm: 'RSA', publicKeyHex: bytesToHex(publicKey), bits: modulus ? (modulus[0] === 0 ? modulus.length - 1 : modulus.length) * 8 : publicKey.length * 8 }
  }
  if (algorithmOid === OIDS.ecPublicKey || algorithmOid === OIDS.sm2Curve) {
    return {
      algorithm: curveOid === OIDS.sm2Curve || algorithmOid === OIDS.sm2Curve ? 'SM2' : 'ECC',
      curve: curveOid || algorithmOid,
      publicKeyHex: bytesToHex(publicKey),
      bits: publicKey.length === 65 ? 256 : Math.max(0, (publicKey.length - 1) * 4)
    }
  }
  return { algorithm: `${oidName(algorithmOid)} (${algorithmOid})`, publicKeyHex: bytesToHex(publicKey), bits: publicKey.length * 8 }
}

function statusFromFindings(findings: Finding[]): Status {
  if (findings.some((finding) => finding.status === 'fail')) return 'fail'
  if (findings.some((finding) => finding.status === 'warn')) return 'warn'
  return 'pass'
}

function publicKeyComponentItems(
  algorithm: string,
  publicKeyHex: string,
  privateKeyHex?: string,
  unavailablePrivateMessage?: string
): FieldGroup['items'] {
  const point = publicKeyHex.replace(/[\s:,-]/g, '').toUpperCase()
  if (algorithm === 'SM2' && /^04[0-9A-F]{128}$/.test(point)) {
    const formats = formatSm2KeyComponents(point.slice(2, 66), point.slice(66), privateKeyHex)
    return [
      { label: '公钥 X', value: formats.x, mono: true },
      { label: '公钥 Y', value: formats.y, mono: true },
      formats.d
        ? { label: '私钥 D', value: formats.d, mono: true, sensitive: true }
        : { label: '私钥 D', value: unavailablePrivateMessage ?? '当前材料中不包含私钥信息' },
      { label: '公钥 Hex（X || Y）', value: formats.publicKeyXYHex, mono: true },
      { label: '完整公钥 Hex（04 || X || Y）', value: formats.publicKeyHex, mono: true },
      ...(formats.keyPairHex
        ? [
            { label: '公私钥 Hex（X || Y || D）', value: formats.keyPairHex, mono: true, sensitive: true },
            { label: '完整公私钥 Hex（04 || X || Y || D）', value: formats.completeKeyPairHex!, mono: true, sensitive: true }
          ]
        : []),
      { label: '公钥 PEM（SPKI）', value: formats.publicPem, mono: true },
      ...(formats.privatePem
        ? [{ label: '私钥 PEM（PKCS#8）', value: formats.privatePem, mono: true, sensitive: true }]
        : [])
    ]
  }
  if (algorithm === 'ECC' && /^04[0-9A-F]{128}$/.test(point)) {
    return [
      { label: '公钥 X', value: point.slice(2, 66), mono: true },
      { label: '公钥 Y', value: point.slice(66, 130), mono: true }
    ]
  }
  return [{ label: '公钥值', value: point, mono: true }]
}

function extensionSummary(extensions: Array<{ extnID: string; critical: boolean; extnValue: { valueBlock: { valueHexView: Uint8Array } }; parsedValue?: unknown }> = []): FieldGroup {
  return {
    title: 'X.509 扩展',
    items: extensions.map((item) => ({
      label: `${oidName(item.extnID)}${item.critical ? ' · critical' : ''}`,
      value: `${item.extnID} · ${bytesToHex(item.extnValue.valueBlock.valueHexView).slice(0, 120)}${item.extnValue.valueBlock.valueHexView.length > 60 ? '…' : ''}`,
      mono: true
    }))
  }
}

function getSanValues(extensions: Array<{ extnID: string; parsedValue?: unknown }> = []): string[] {
  const san = extensions.find((item) => item.extnID === OIDS.san)?.parsedValue as { altNames?: Array<{ type: number; value: string | ArrayBuffer | { valueBlock?: { valueHexView?: Uint8Array } } }> } | undefined
  return (san?.altNames ?? []).map((name) => {
    const prefix = ['other', 'email', 'DNS', 'x400', 'directory', 'edi', 'URI', 'IP'][name.type] ?? `type-${name.type}`
    if (typeof name.value === 'string') return `${prefix}:${name.value}`
    const bytes = name.value instanceof ArrayBuffer ? new Uint8Array(name.value) : name.value.valueBlock?.valueHexView ?? new Uint8Array()
    if (name.type === 7 && bytes.length === 4) return `${prefix}:${Array.from(bytes).join('.')}`
    return `${prefix}:${bytesToHex(bytes)}`
  })
}

export async function parseCertificate(bytes: Uint8Array): Promise<ParseReport> {
  const parsed = fromBER(asArrayBuffer(bytes))
  if (parsed.offset === -1) throw new Error('证书不是完整的 ASN.1 DER 数据')
  const certificate = new Certificate({ schema: parsed.result })
  const subject = formatDn(certificate.subject as unknown as PkiName)
  const issuer = formatDn(certificate.issuer as unknown as PkiName)
  const signatureOid = certificate.signatureAlgorithm.algorithmId
  const key = getAlgorithmDetails(certificate.subjectPublicKeyInfo)
  const notBefore = certificate.notBefore.value
  const notAfter = certificate.notAfter.value
  const now = new Date()
  const remainingDays = Math.ceil((notAfter.getTime() - now.getTime()) / 86_400_000)
  const extensions = certificate.extensions ?? []
  const sans = getSanValues(extensions)
  const basic = extensions.find((item) => item.extnID === OIDS.basicConstraints)?.parsedValue as { cA?: boolean; pathLenConstraint?: number } | undefined
  const isCa = Boolean(basic?.cA)
  const isSelfIssued = subject.display === issuer.display
  const findings: Finding[] = []

  if (now < notBefore) findings.push({ id: 'GM-CERT-1001', status: 'fail', title: '证书尚未生效', detail: `生效时间为 ${notBefore.toLocaleString('zh-CN')}。`, fix: '校准系统时间，或换用已生效的证书。' })
  else if (now > notAfter) findings.push({ id: 'GM-CERT-1002', status: 'fail', title: '证书已过期', detail: `证书于 ${notAfter.toLocaleString('zh-CN')} 过期。`, fix: '向 CA 申请续期并替换部署。' })
  else if (remainingDays <= 30) findings.push({ id: 'GM-CERT-1003', status: 'warn', title: '证书即将到期', detail: `距离到期还有 ${remainingDays} 天。`, fix: '安排续期并预留灰度替换时间。' })
  else findings.push({ id: 'GM-CERT-0000', status: 'pass', title: '有效期正常', detail: `当前有效，距离到期还有 ${remainingDays} 天。` })

  if (/\.1\.1\.(4|5)$/.test(signatureOid) || signatureOid === '1.2.840.10045.4.1') {
    findings.push({ id: 'GM-CERT-2001', status: 'fail', title: '使用弱签名摘要', detail: `${oidName(signatureOid)} (${signatureOid}) 已不适合新系统。`, fix: '请 CA 使用 SM3 或 SHA-256 及以上摘要重新签发。' })
  } else if (key.algorithm === 'SM2' && signatureOid !== OIDS.sm3WithSm2) {
    findings.push({ id: 'GM-CERT-2002', status: 'fail', title: '国密算法标识不一致', detail: `公钥为 SM2，但签名算法是 ${oidName(signatureOid)} (${signatureOid})。`, fix: '使用 GmSSL/铜锁并显式指定 SM3withSM2 重新签发。' })
  } else {
    findings.push({ id: 'GM-CERT-0001', status: 'pass', title: '算法标识一致', detail: `${key.algorithm} 公钥与 ${oidName(signatureOid)} 签名组合可识别。` })
  }

  if (!isCa && !subject.values.CN && !sans.length) findings.push({ id: 'GM-CERT-3001', status: 'fail', title: '缺少主体标识', detail: 'CN 与 SAN 均为空，无法确认该证书代表的身份。', fix: '重新申请并至少提供一个 SAN。' })
  else if (!isCa && !sans.length) findings.push({ id: 'GM-CERT-3002', status: 'warn', title: '缺少 SAN', detail: '证书只有 CN；现代 TLS 客户端通常以 SAN 为准。', fix: '重新申请并在 SAN 中加入域名或 IP。' })

  const sha1 = bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-1', asArrayBuffer(bytes))), ':').toUpperCase()
  const sha256 = bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', asArrayBuffer(bytes))), ':').toUpperCase()
  const sm3 = sm3Digest(bytes).toUpperCase().match(/.{2}/g)?.join(':') ?? ''
  const role = isCa ? (isSelfIssued ? '自签根 CA' : '中间 CA') : '终端证书'
  const status = statusFromFindings(findings)
  return {
    kind: 'certificate',
    label: 'X.509 证书',
    algorithm: key.algorithm,
    summary: `${key.algorithm} · ${subject.values.CN || subject.display || '未命名主体'} · ${role}`,
    status,
    findings,
    bytes,
    pemLabel: 'CERTIFICATE',
    publicKeyHex: key.publicKeyHex,
    groups: [
      {
        title: '基本信息',
        items: [
          { label: '证书角色', value: role },
          { label: '版本', value: `v${certificate.version + 1}` },
          { label: '序列号', value: bytesToHex(certificate.serialNumber.valueBlock.valueHexView), mono: true },
          { label: '签名算法', value: `${oidName(signatureOid)} (${signatureOid})`, mono: true },
          { label: '有效期', value: `${notBefore.toLocaleString('zh-CN')} 至 ${notAfter.toLocaleString('zh-CN')}` },
          { label: '剩余时间', value: `${remainingDays} 天` }
        ]
      },
      { title: '主体与签发者', items: [{ label: '主体', value: subject.display }, { label: '签发者', value: issuer.display }, { label: '主体备用名称', value: sans.join('\n') || '无' }] },
      {
        title: '公钥与格式',
        items: [
          { label: '算法', value: key.algorithm },
          { label: '算法 OID', value: certificate.subjectPublicKeyInfo.algorithm.algorithmId, mono: true },
          { label: '曲线 OID', value: key.curve ? `${oidName(key.curve)} (${key.curve})` : '不适用', mono: true },
          { label: '密钥位数', value: `${key.bits} bit` },
          ...publicKeyComponentItems(key.algorithm, key.publicKeyHex, undefined, '证书中不包含私钥信息')
        ]
      },
      { title: '指纹', items: [{ label: 'SHA-1', value: sha1, mono: true }, { label: 'SHA-256', value: sha256, mono: true }, { label: 'SM3', value: sm3, mono: true }] },
      extensionSummary(extensions)
    ]
  }
}

function extractRequestedSans(request: CertificationRequest): string[] {
  const attribute = request.attributes?.find((item) => item.type === OIDS.extensionRequest)
  if (!attribute) return []
  try {
    const extensions = new Extensions({ schema: attribute.values[0] })
    const sanExtension = extensions.extensions.find((item) => item.extnID === OIDS.san)
    if (!sanExtension) return []
    const parsed = fromBER(asArrayBuffer(sanExtension.extnValue.valueBlock.valueHexView))
    if (parsed.offset === -1) return []
    const names = new GeneralNames({ schema: parsed.result })
    return getSanValues([{ extnID: OIDS.san, parsedValue: { altNames: names.names } }])
  } catch {
    return []
  }
}

export async function parseCsr(bytes: Uint8Array): Promise<ParseReport> {
  const parsed = fromBER(asArrayBuffer(bytes))
  if (parsed.offset === -1) throw new Error('CSR 不是完整的 ASN.1 DER 数据')
  const request = new CertificationRequest({ schema: parsed.result })
  const subject = formatDn(request.subject as unknown as PkiName)
  const signatureOid = request.signatureAlgorithm.algorithmId
  const key = getAlgorithmDetails(request.subjectPublicKeyInfo)
  const sans = extractRequestedSans(request)
  const findings: Finding[] = []
  let signatureValid: boolean | undefined
  if (key.algorithm === 'SM2' && signatureOid === OIDS.sm3WithSm2) {
    try {
      signatureValid = sm2Verify(key.publicKeyHex, request.tbsView, request.signatureValue.valueBlock.valueHexView, { signatureFormat: 'der' })
    } catch {
      signatureValid = false
    }
  } else {
    try {
      signatureValid = await request.verify()
    } catch {
      signatureValid = undefined
    }
  }
  findings.push(signatureValid === true
    ? { id: 'GM-CSR-0000', status: 'pass', title: 'CSR 自签名有效', detail: '请求内容完整，且签名与内含公钥匹配。' }
    : signatureValid === false
      ? { id: 'GM-CSR-1002', status: 'fail', title: 'CSR 自签名无效', detail: '请求内容可能被修改，或签名编码不符合声明算法。', fix: '使用原始私钥重新生成 CSR，不要手工编辑 Base64 内容。' }
      : { id: 'GM-CSR-1003', status: 'warn', title: '当前浏览器无法验证该签名', detail: '字段已正常解析，但此算法不在当前 WebCrypto/国密内核验签范围内。' })

  if (!subject.values.CN) findings.push({ id: 'GM-CSR-2001', status: 'fail', title: '主体 CN 为空', detail: '多数 CA 会拒收没有 CN 的请求。', fix: '补充通用名称后重新生成 CSR。' })
  else if (subject.values.CN.length > 64) findings.push({ id: 'GM-CSR-2002', status: 'fail', title: '主体 CN 过长', detail: `当前 CN 长度为 ${subject.values.CN.length}，超过 64。`, fix: '缩短 CN，其他身份放入 SAN。' })
  else findings.push({ id: 'GM-CSR-0001', status: 'pass', title: '主体名称可用', detail: `CN=${subject.values.CN}` })

  if (key.algorithm === 'SM2' && signatureOid !== OIDS.sm3WithSm2) findings.push({ id: 'GM-CSR-1001', status: 'fail', title: '签名算法 OID 非国密标准值', detail: `该 CSR 的公钥为 SM2，但签名算法是 ${oidName(signatureOid)} (${signatureOid})。`, fix: '改用 GmSSL/铜锁并显式指定 SM3 摘要重新生成。' })
  else findings.push({ id: 'GM-CSR-0002', status: 'pass', title: '签名算法标识正常', detail: `${oidName(signatureOid)} (${signatureOid})` })

  if (!sans.length) findings.push({ id: 'GM-CSR-3001', status: 'warn', title: '未请求 SAN', detail: '现代 CA 与浏览器通常以 SAN 作为服务身份。', fix: '在 CSR 的 extensionRequest 中加入 DNS/IP SAN。' })
  const status = statusFromFindings(findings)
  return {
    kind: 'csr',
    label: '证书请求（CSR）',
    algorithm: key.algorithm,
    summary: `${key.algorithm} · ${subject.values.CN || '未命名主体'} · ${signatureValid === true ? '签名有效' : '需检查'}`,
    status,
    findings,
    bytes,
    pemLabel: 'CERTIFICATE REQUEST',
    publicKeyHex: key.publicKeyHex,
    groups: [
      { title: '请求信息', items: [{ label: '版本', value: `${request.version}` }, { label: '主体', value: subject.display }, { label: '请求的 SAN', value: sans.join('\n') || '未请求' }, { label: '签名算法', value: `${oidName(signatureOid)} (${signatureOid})`, mono: true }, { label: '自签名校验', value: signatureValid === true ? '有效' : signatureValid === false ? '无效' : '当前环境不支持' }] },
      { title: '公钥与格式', items: [{ label: '算法', value: key.algorithm }, { label: '曲线 OID', value: key.curve ? `${oidName(key.curve)} (${key.curve})` : '不适用', mono: true }, { label: '密钥位数', value: `${key.bits} bit` }, ...publicKeyComponentItems(key.algorithm, key.publicKeyHex, undefined, 'CSR 中不包含私钥信息')] }
    ]
  }
}

type AsnNode = {
  idBlock?: { tagClass?: number; tagNumber?: number }
  valueBlock?: { value?: AsnNode[]; valueHexView?: Uint8Array; toString?: () => string; valueDec?: number }
}

function flattenAsn(node: AsnNode): AsnNode[] {
  const children = node.valueBlock?.value ?? []
  return [node, ...children.flatMap(flattenAsn)]
}

function findOids(node: AsnNode): string[] {
  return flattenAsn(node)
    .filter((item) => item.idBlock?.tagClass === 1 && item.idBlock?.tagNumber === 6)
    .map((item) => item.valueBlock?.toString?.() ?? '')
    .filter(Boolean)
}

export async function parseKey(bytes: Uint8Array, kind: MaterialKind): Promise<ParseReport> {
  const parsed = fromBER(asArrayBuffer(bytes))
  if (parsed.offset === -1) throw new Error('密钥不是完整的 ASN.1 DER 数据')
  const root = parsed.result as AsnNode
  const oids = findOids(root)
  const encrypted = kind === 'encrypted-private-key'
  const isPrivate = kind === 'private-key' || encrypted
  const isRsa = oids.includes(OIDS.rsa) || (!oids.length && flattenAsn(root).filter((item) => item.idBlock?.tagNumber === 2).length >= 8)
  const isSm2 = oids.includes(OIDS.sm2Curve)
  const algorithm = isSm2 ? 'SM2' : isRsa ? 'RSA' : oids.some((oid) => oid.startsWith('1.2.840.10045')) ? 'ECC' : '未知算法'
  const allNodes = flattenAsn(root)
  const bitNode = allNodes.find((node) => {
    const value = node.valueBlock?.valueHexView
    return node.idBlock?.tagNumber === 3 && value && (value.length === 65 || value.length === 33) && [2, 3, 4].includes(value[0])
  })
  let publicKeyHex = bitNode?.valueBlock?.valueHexView ? bytesToHex(bitNode.valueBlock.valueHexView) : undefined
  const octets = allNodes.filter((node) => node.idBlock?.tagNumber === 4).map((node) => node.valueBlock?.valueHexView).filter(Boolean) as Uint8Array[]
  const scalar = octets.find((value) => value.length === 32)
  if (!publicKeyHex && isSm2 && scalar) publicKeyHex = sm2GetPublicKeyFromPrivateKey(bytesToHex(scalar))
  if (!publicKeyHex && kind === 'public-key') {
    const lastBit = allNodes.findLast((node) => node.idBlock?.tagNumber === 3)?.valueBlock?.valueHexView
    if (lastBit) publicKeyHex = bytesToHex(lastBit)
  }
  const findings: Finding[] = encrypted
    ? [{ id: 'GM-KEY-0001', status: 'pass', title: '私钥已加密', detail: '检测到 EncryptedPrivateKeyInfo。当前版本仅展示容器参数，不在内存中解密。' }]
    : isPrivate
      ? [{ id: 'GM-KEY-1001', status: 'warn', title: '当前是明文私钥', detail: '页面不会上传或持久化该内容，但导出和传递时仍需加密保护。', fix: '生产材料建议使用 PBES2 加密的 PKCS#8 容器。' }]
      : [{ id: 'GM-KEY-0000', status: 'pass', title: '公钥材料可解析', detail: '该材料不包含私钥标量。' }]
  const keyItems: FieldGroup['items'] = [
    { label: '算法', value: algorithm },
    { label: '容器', value: encrypted ? 'EncryptedPrivateKeyInfo' : isPrivate ? 'PrivateKeyInfo / SEC1 / PKCS#1' : 'SubjectPublicKeyInfo' },
    { label: 'OID', value: oids.map((oid) => `${oid} (${oidName(oid)})`).join('\n') || '未声明', mono: true }
  ]
  if (publicKeyHex) {
    const unavailableMessage = encrypted
      ? '私钥已加密，无法读取 D'
      : isPrivate
        ? '当前容器中无法提取私钥 D'
        : '公钥中不包含私钥信息'
    keyItems.push(...publicKeyComponentItems(algorithm, publicKeyHex, scalar ? bytesToHex(scalar) : undefined, unavailableMessage))
  } else keyItems.push({ label: '公钥', value: '容器中未携带，当前无法推导', mono: true })
  if (algorithm !== 'SM2' && scalar) {
    keyItems.push({ label: '私钥标量', value: bytesToHex(scalar).toUpperCase(), mono: true, sensitive: true })
  }
  return {
    kind,
    label: encrypted ? '加密私钥' : isPrivate ? '私钥' : '公钥',
    algorithm,
    summary: `${algorithm} · ${encrypted ? '加密 PKCS#8' : isPrivate ? '私钥材料' : '公钥材料'}`,
    status: statusFromFindings(findings),
    findings,
    groups: [
      { title: '密钥信息', items: keyItems }
    ],
    bytes,
    pemLabel: encrypted ? 'ENCRYPTED PRIVATE KEY' : isPrivate ? 'PRIVATE KEY' : 'PUBLIC KEY',
    publicKeyHex
  }
}

export async function parseMaterial(input: string | Uint8Array, suppliedKind?: MaterialKind): Promise<ParseReport> {
  let bytes: Uint8Array
  let kind: MaterialKind
  let pemLabel: string | undefined
  if (typeof input === 'string') {
    const decoded = decodeFlexibleInput(input)
    bytes = decoded.bytes
    kind = suppliedKind ?? decoded.kind
    pemLabel = decoded.pemLabel
  } else {
    bytes = input
    kind = suppliedKind ?? classifyDer(input)
  }
  if (kind === 'certificate') return parseCertificate(bytes)
  if (kind === 'csr') return parseCsr(bytes)
  if (['private-key', 'encrypted-private-key', 'public-key'].includes(kind)) return parseKey(bytes, kind)
  const finding: Finding = kind === 'jks'
    ? { id: 'GM-FMT-2001', status: 'warn', title: 'JKS 暂不支持', detail: '已识别 Java KeyStore 魔数，但 v1 不解析 JKS。', fix: '请先用 keytool 转为 PKCS#12。' }
    : { id: 'GM-FMT-1001', status: 'warn', title: '已识别编码，尚未识别材料类型', detail: '可继续使用 ASN.1 查看器与格式体检定位结构。' }
  return {
    kind,
    label: kind === 'pkcs12' ? 'PKCS#12 容器' : kind === 'pkcs7' ? 'PKCS#7 容器' : kind === 'jks' ? 'JKS 容器' : '通用数据',
    algorithm: '待识别',
    summary: `${bytes.length} 字节 · ${kind.toUpperCase()}`,
    status: 'warn',
    findings: [finding],
    groups: [{ title: '材料信息', items: [{ label: '识别类型', value: kind }, { label: '字节长度', value: `${bytes.length}` }, { label: 'PEM 标签', value: pemLabel ?? '无' }, { label: '数据头', value: bytesToHex(bytes.subarray(0, 32), ' '), mono: true }] }],
    bytes,
    pemLabel
  }
}

export async function generateKeyPair(algorithm: 'SM2' | 'RSA-2048' | 'RSA-3072' | 'P-256' | 'P-384'): Promise<GeneratedKeyPair> {
  if (algorithm === 'SM2') {
    const pair = sm2GenerateKeyPair(false)
    const encoded = encodeSm2PrivateKey(pair.privateKey, pair.publicKey)
    return {
      algorithm: 'SM2 / sm2p256v1',
      privatePem: formatPem(encoded.pkcs8, 'PRIVATE KEY'),
      publicPem: formatPem(encoded.spki, 'PUBLIC KEY'),
      privateDer: encoded.pkcs8,
      publicDer: encoded.spki,
      publicKeyHex: pair.publicKey,
      privateKeyHex: pair.privateKey
    }
  }
  if (algorithm.startsWith('RSA')) {
    const bits = Number(algorithm.split('-')[1])
    const pair = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt'])
    const privateDer = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey))
    const publicDer = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey))
    const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey)
    return { algorithm: `RSA ${bits}`, privatePem: formatPem(privateDer, 'PRIVATE KEY'), publicPem: formatPem(publicDer, 'PUBLIC KEY'), privateDer, publicDer, publicKeyHex: jwk.n ?? '', jwk }
  }
  const namedCurve = algorithm
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve }, true, ['sign', 'verify'])
  const privateDer = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey))
  const publicDer = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey))
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey)
  return { algorithm: `ECC ${namedCurve}`, privatePem: formatPem(privateDer, 'PRIVATE KEY'), publicPem: formatPem(publicDer, 'PUBLIC KEY'), privateDer, publicDer, publicKeyHex: jwk.x && jwk.y ? `04${base64UrlToHex(jwk.x)}${base64UrlToHex(jwk.y)}` : '', jwk }
}

export async function importRsaKeyPair(privateMaterial: string, publicMaterial?: string): Promise<GeneratedKeyPair> {
  const privateDer = decodeFlexibleInput(privateMaterial).bytes
  const privateKey = await crypto.subtle.importKey('pkcs8', asArrayBuffer(privateDer), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt'])
  const privateJwk = await crypto.subtle.exportKey('jwk', privateKey)
  if (!privateJwk.n || !privateJwk.e) throw new Error('私钥不是可识别的 RSA PKCS#8 密钥。')
  let publicDer: Uint8Array
  if (publicMaterial?.trim()) {
    publicDer = decodeFlexibleInput(publicMaterial).bytes
    const publicKey = await crypto.subtle.importKey('spki', asArrayBuffer(publicDer), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt'])
    const publicJwk = await crypto.subtle.exportKey('jwk', publicKey)
    if (publicJwk.n !== privateJwk.n || publicJwk.e !== privateJwk.e) throw new Error('公钥与私钥不匹配，请确认来自同一密钥对。')
  } else {
    const publicKey = await crypto.subtle.importKey('jwk', { kty: 'RSA', n: privateJwk.n, e: privateJwk.e, ext: true }, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt'])
    publicDer = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey))
  }
  const bits = Math.ceil((privateJwk.n.length * 3) / 4 / 8) * 8
  return { algorithm: `RSA ${bits}`, privatePem: formatPem(privateDer, 'PRIVATE KEY'), publicPem: formatPem(publicDer, 'PUBLIC KEY'), privateDer, publicDer, publicKeyHex: privateJwk.n, jwk: privateJwk }
}

function normalizeSm2Component(value: string, name: string) {
  const compact = value.replace(/[\s:,-]/g, '').replace(/^0x/i, '').toUpperCase()
  if (!/^[0-9A-F]{64}$/.test(compact)) throw new Error(`${name}必须是 32 字节（64 位 Hex）。`)
  return compact
}

export function formatSm2KeyComponents(x: string, y: string, d?: string): Sm2KeyFormats {
  const normalizedX = normalizeSm2Component(x, '公钥 X')
  const normalizedY = normalizeSm2Component(y, '公钥 Y')
  const publicKeyXYHex = `${normalizedX}${normalizedY}`
  const publicKeyHex = `04${publicKeyXYHex}`
  const publicDer = encodeSm2Spki(publicKeyHex)
  const normalizedD = d?.trim() ? normalizeSm2Component(d, '私钥 D') : undefined

  if (!normalizedD) {
    return {
      x: normalizedX,
      y: normalizedY,
      publicKeyXYHex,
      publicKeyHex,
      publicPem: formatPem(publicDer, 'PUBLIC KEY'),
      publicDer
    }
  }

  const derivedPublicKey = sm2GetPublicKeyFromPrivateKey(normalizedD).toUpperCase()
  if (derivedPublicKey !== publicKeyHex) throw new Error('X、Y 与 D 不匹配，请确认来自同一 SM2 密钥对。')
  const encoded = encodeSm2PrivateKey(normalizedD, publicKeyHex)
  return {
    x: normalizedX,
    y: normalizedY,
    d: normalizedD,
    publicKeyXYHex,
    publicKeyHex,
    keyPairHex: `${publicKeyXYHex}${normalizedD}`,
    completeKeyPairHex: `${publicKeyHex}${normalizedD}`,
    publicPem: formatPem(encoded.spki, 'PUBLIC KEY'),
    privatePem: formatPem(encoded.pkcs8, 'PRIVATE KEY'),
    publicDer: encoded.spki,
    privateDer: encoded.pkcs8
  }
}

export function importSm2KeyPair(x: string, y: string, d: string): GeneratedKeyPair {
  const formats = formatSm2KeyComponents(x, y, d)
  return {
    algorithm: 'SM2 / sm2p256v1',
    privatePem: formats.privatePem!,
    publicPem: formats.publicPem,
    privateDer: formats.privateDer!,
    publicDer: formats.publicDer,
    publicKeyHex: formats.publicKeyHex,
    privateKeyHex: formats.d
  }
}

function base64UrlToHex(value: string): string {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=')
  return bytesToHex(Uint8Array.from(atob(normalized), (char) => char.charCodeAt(0)))
}

export function generateSm2Csr(key: GeneratedKeyPair, subject: SubjectInput, sans: string[]): { der: Uint8Array; pem: string } {
  if (!key.privateKeyHex || !key.publicKeyHex) throw new Error('生成 SM2 CSR 需要 SM2 私钥')
  const cri = sequence(integer(0), encodeName(subject), encodeSm2Spki(key.publicKeyHex), encodeExtensionRequest(sans))
  const signature = hexToBytes(sm2Sign(key.privateKeyHex, cri, { signatureFormat: 'der' }))
  const csr = sequence(cri, algorithmIdentifier(OIDS.sm3WithSm2), bitString(signature))
  return { der: csr, pem: formatPem(csr, 'CERTIFICATE REQUEST') }
}

async function signRsaSha256(privateDer: Uint8Array, content: Uint8Array): Promise<Uint8Array> {
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    asArrayBuffer(privateDer),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  )
  return new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, asArrayBuffer(content)))
}

function rsaSha256AlgorithmIdentifier(): Uint8Array {
  return algorithmIdentifier(OIDS.sha256WithRsa, undefined, true)
}

export async function generateRsaCsr(key: GeneratedKeyPair, subject: SubjectInput, sans: string[]): Promise<{ der: Uint8Array; pem: string }> {
  if (!key.algorithm.startsWith('RSA')) throw new Error('生成 RSA CSR 需要 RSA 私钥')
  const cri = sequence(integer(0), encodeName(subject), key.publicDer, encodeExtensionRequest(sans))
  const signature = await signRsaSha256(key.privateDer, cri)
  const csr = sequence(cri, rsaSha256AlgorithmIdentifier(), bitString(signature))
  return { der: csr, pem: formatPem(csr, 'CERTIFICATE REQUEST') }
}

export async function generateSm2Certificate(key: GeneratedKeyPair, subject: SubjectInput, sans: string[], days: number, isCa: boolean): Promise<{ der: Uint8Array; pem: string }> {
  if (!key.privateKeyHex || !key.publicKeyHex) throw new Error('生成 SM2 证书需要 SM2 私钥')
  const now = new Date()
  const notBefore = new Date(now.getTime() - 5 * 60_000)
  const notAfter = new Date(now.getTime() + Math.max(1, days) * 86_400_000)
  const serial = crypto.getRandomValues(new Uint8Array(16))
  serial[0] &= 0x7f
  if (serial.every((value) => value === 0)) serial[15] = 1
  const name = encodeName(subject)
  const spki = encodeSm2Spki(key.publicKeyHex)
  const ski = new Uint8Array(await crypto.subtle.digest('SHA-1', asArrayBuffer(hexToBytes(key.publicKeyHex))))
  const extensions = [
    extension(OIDS.basicConstraints, isCa ? sequence(boolean(true)) : sequence(), true),
    extension(OIDS.keyUsage, isCa ? bitString(Uint8Array.of(0x06), 1) : bitString(Uint8Array.of(0xa0), 5), true),
    extension(OIDS.ski, octetString(ski)),
    extension(OIDS.aki, sequence(tlv(0x80, ski)))
  ]
  if (sans.length) extensions.push(extension(OIDS.san, encodeSans(sans)))
  const sigAlgorithm = algorithmIdentifier(OIDS.sm3WithSm2)
  const tbs = sequence(
    explicit(0, integer(2)),
    integer(serial),
    sigAlgorithm,
    name,
    sequence(formatDate(notBefore), formatDate(notAfter)),
    name,
    spki,
    explicit(3, sequence(...extensions))
  )
  const signature = hexToBytes(sm2Sign(key.privateKeyHex, tbs, { signatureFormat: 'der' }))
  const certificate = sequence(tbs, sigAlgorithm, bitString(signature))
  return { der: certificate, pem: formatPem(certificate, 'CERTIFICATE') }
}

export async function generateRsaCertificate(key: GeneratedKeyPair, subject: SubjectInput, sans: string[], days: number, isCa: boolean): Promise<{ der: Uint8Array; pem: string }> {
  if (!key.algorithm.startsWith('RSA')) throw new Error('生成 RSA 证书需要 RSA 私钥')
  const now = new Date()
  const notBefore = new Date(now.getTime() - 5 * 60_000)
  const notAfter = new Date(now.getTime() + Math.max(1, days) * 86_400_000)
  const serial = crypto.getRandomValues(new Uint8Array(16))
  serial[0] &= 0x7f
  if (serial.every((value) => value === 0)) serial[15] = 1
  const name = encodeName(subject)
  const ski = new Uint8Array(await crypto.subtle.digest('SHA-1', asArrayBuffer(key.publicDer)))
  const extensions = [
    extension(OIDS.basicConstraints, isCa ? sequence(boolean(true)) : sequence(), true),
    extension(OIDS.keyUsage, isCa ? bitString(Uint8Array.of(0x06), 1) : bitString(Uint8Array.of(0xa0), 5), true),
    extension(OIDS.ski, octetString(ski)),
    extension(OIDS.aki, sequence(tlv(0x80, ski)))
  ]
  if (sans.length) extensions.push(extension(OIDS.san, encodeSans(sans)))
  const signatureAlgorithm = rsaSha256AlgorithmIdentifier()
  const tbs = sequence(
    explicit(0, integer(2)),
    integer(serial),
    signatureAlgorithm,
    name,
    sequence(formatDate(notBefore), formatDate(notAfter)),
    name,
    key.publicDer,
    explicit(3, sequence(...extensions))
  )
  const signature = await signRsaSha256(key.privateDer, tbs)
  const certificate = sequence(tbs, signatureAlgorithm, bitString(signature))
  return { der: certificate, pem: formatPem(certificate, 'CERTIFICATE') }
}

function keyUsageValue(usages: CertificateProfile['keyUsages']): Uint8Array {
  const positions: Record<string, number> = { digitalSignature: 0, contentCommitment: 1, keyEncipherment: 2, dataEncipherment: 3, keyAgreement: 4, keyCertSign: 5, cRLSign: 6 }
  let value = 0
  for (const usage of usages ?? []) value |= 0x80 >>> positions[usage]
  let lastBit = 0
  for (const usage of usages ?? []) lastBit = Math.max(lastBit, positions[usage])
  return bitString(Uint8Array.of(value), usages?.length ? 7 - lastBit : 7)
}

function certificateSerial(value?: string): Uint8Array {
  if (value?.trim()) {
    const normalized = value.replace(/[^0-9a-f]/gi, '')
    if (!normalized || normalized.length > 40) throw new Error('序列号应为不超过 20 字节的 Hex。')
    const serial = hexToBytes(normalized.length % 2 ? `0${normalized}` : normalized)
    if (serial.every((item) => item === 0)) throw new Error('序列号不能为 0。')
    return serial
  }
  const serial = crypto.getRandomValues(new Uint8Array(16)); serial[0] &= 0x7f
  if (serial.every((item) => item === 0)) serial[15] = 1
  return serial
}

function subjectPublicKeyBytes(key: GeneratedKeyPair): Uint8Array {
  if (key.algorithm.startsWith('SM2') && key.publicKeyHex) return hexToBytes(key.publicKeyHex)
  const parsed = fromBER(asArrayBuffer(key.publicDer))
  const children = (parsed.result as AsnNode).valueBlock?.value
  return children?.[1]?.valueBlock?.valueHexView ?? key.publicDer
}

export async function issueCertificate(
  subjectKey: GeneratedKeyPair,
  subject: SubjectInput,
  sans: string[],
  days: number,
  profile: CertificateProfile,
  issuer?: IssuerMaterial
): Promise<{ der: Uint8Array; pem: string }> {
  const signer = issuer?.key ?? subjectKey
  const now = new Date()
  const notBefore = new Date(now.getTime() - 5 * 60_000)
  const notAfter = new Date(now.getTime() + Math.max(1, days) * 86_400_000)
  const subjectName = encodeName(subject)
  let issuerName = subjectName
  let issuerPublic = subjectPublicKeyBytes(signer)
  if (issuer) {
    const parsed = fromBER(asArrayBuffer(issuer.certificate)); if (parsed.offset === -1) throw new Error('CA 证书不是有效 DER。')
    const issuerCertificate = new Certificate({ schema: parsed.result })
    issuerName = new Uint8Array(issuerCertificate.subject.toSchema().toBER(false))
    issuerPublic = issuerCertificate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView
  }
  const isCa = profile.type !== 'end-entity'
  const defaultUsages: CertificateProfile['keyUsages'] = isCa ? ['keyCertSign', 'cRLSign'] : ['digitalSignature', 'keyEncipherment']
  const subjectPublic = subjectPublicKeyBytes(subjectKey)
  const ski = new Uint8Array(await crypto.subtle.digest('SHA-1', asArrayBuffer(subjectPublic)))
  const aki = new Uint8Array(await crypto.subtle.digest('SHA-1', asArrayBuffer(issuerPublic)))
  const basicConstraints = isCa
    ? sequence(boolean(true), ...(profile.pathLen === undefined ? [] : [integer(Math.max(0, profile.pathLen))]))
    : sequence()
  const extensions = [
    extension(OIDS.basicConstraints, basicConstraints, true),
    extension(OIDS.keyUsage, keyUsageValue(profile.keyUsages?.length ? profile.keyUsages : defaultUsages), true),
    extension(OIDS.ski, octetString(ski)),
    extension(OIDS.aki, sequence(tlv(0x80, aki)))
  ]
  if (profile.extendedKeyUsages?.length) extensions.push(extension(OIDS.extendedKeyUsage, sequence(...profile.extendedKeyUsages.map(objectIdentifier))))
  if (sans.length) extensions.push(extension(OIDS.san, encodeSans(sans)))
  const signatureAlgorithm = signer.algorithm.startsWith('SM2') ? algorithmIdentifier(OIDS.sm3WithSm2) : rsaSha256AlgorithmIdentifier()
  const tbs = sequence(
    explicit(0, integer(2)), integer(certificateSerial(profile.serialHex)), signatureAlgorithm, issuerName,
    sequence(formatDate(notBefore), formatDate(notAfter)), subjectName, subjectKey.publicDer, explicit(3, sequence(...extensions))
  )
  const signature = signer.algorithm.startsWith('SM2')
    ? hexToBytes(sm2Sign(signer.privateKeyHex!, tbs, { signatureFormat: 'der' }))
    : await signRsaSha256(signer.privateDer, tbs)
  const certificate = sequence(tbs, signatureAlgorithm, bitString(signature))
  return { der: certificate, pem: formatPem(certificate, 'CERTIFICATE') }
}

export function normalizePublicKey(value?: string): string | undefined {
  return value?.replace(/^00/, '').toLowerCase()
}

export function compareReports(left: ParseReport, right: ParseReport): Finding[] {
  if (!left.publicKeyHex || !right.publicKeyHex) return [{ id: 'GM-MATCH-1000', status: 'fail', title: '缺少可比对的公钥', detail: '至少一份材料没有携带公钥，或当前解析器无法从私钥推导公钥。', fix: '确认私钥格式为带曲线参数的 PKCS#8/SEC1，或使用本站生成的材料。' }]
  const leftKey = normalizePublicKey(left.publicKeyHex)
  const rightKey = normalizePublicKey(right.publicKeyHex)
  if (left.algorithm !== right.algorithm && !(left.algorithm === 'ECC' && right.algorithm === 'SM2') && !(left.algorithm === 'SM2' && right.algorithm === 'ECC')) {
    return [{ id: 'GM-MATCH-1001', status: 'fail', title: '算法不匹配', detail: `左侧为 ${left.algorithm}，右侧为 ${right.algorithm}。`, fix: '选择同一算法体系生成的证书、CSR 与私钥。' }]
  }
  return leftKey === rightKey
    ? [{ id: 'GM-MATCH-0000', status: 'pass', title: '公钥完全匹配', detail: `${left.label} 与 ${right.label} 的公钥值一致。` }]
    : [{ id: 'GM-MATCH-1002', status: 'fail', title: '公钥不匹配', detail: `${left.label} 与 ${right.label} 使用了不同密钥对。`, fix: '重新选择与证书/CSR 同源的私钥，避免混用签名与加密密钥。' }]
}

export function downloadBytes(bytes: Uint8Array, filename: string, mime = 'application/octet-stream'): void {
  const blob = new Blob([asArrayBuffer(bytes)], { type: mime })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export function textToBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value)
}

export function encodeOutput(bytes: Uint8Array, mode: 'PEM' | 'Base64' | 'Hex', label = 'DATA'): string {
  if (mode === 'PEM') return formatPem(bytes, label)
  if (mode === 'Base64') return bytesToBase64(bytes)
  return bytesToHex(bytes)
}
