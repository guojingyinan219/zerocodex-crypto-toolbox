import forge from 'node-forge'
import { fromBER } from 'asn1js'
import { ContentInfo, SignedData } from 'pkijs'
import type { FieldGroup, Finding, MaterialKind, ParseReport } from '../types'
import { bytesToHex, decodeFlexibleInput, formatPem } from './codec'
import { parseCertificate } from './pki'

function binary(bytes: Uint8Array): string {
  let value = ''
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    value += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000))
  }
  return value
}

function bytes(value: string): Uint8Array {
  return Uint8Array.from(value, (character) => character.charCodeAt(0))
}

function report(kind: MaterialKind, label: string, algorithm: string, source: Uint8Array, groups: FieldGroup[], findings: Finding[] = []): ParseReport {
  return {
    kind,
    label,
    algorithm,
    summary: `${source.length} 字节 · ${groups.reduce((total, group) => total + group.items.length, 0)} 项信息`,
    status: findings.some((item) => item.status === 'fail') ? 'fail' : findings.some((item) => item.status === 'warn') ? 'warn' : 'pass',
    findings,
    groups,
    bytes: source
  }
}

function friendlyName(attributes?: unknown): string {
  if (Array.isArray(attributes)) return attributes.find((item) => item?.name === 'friendlyName')?.value ?? '未命名条目'
  const values = (attributes as { friendlyName?: unknown[] } | undefined)?.friendlyName
  return typeof values?.[0] === 'string' ? values[0] : '未命名条目'
}

export async function parsePkcs12(source: Uint8Array, password: string): Promise<ParseReport> {
  let p12: forge.pkcs12.Pkcs12Pfx
  try {
    const asn1 = forge.asn1.fromDer(forge.util.createBuffer(binary(source)))
    p12 = forge.pkcs12.pkcs12FromAsn1(asn1, false, password)
  } catch (cause) {
    throw new Error(`PFX 解密失败，请检查口令或文件完整性：${cause instanceof Error ? cause.message : '未知错误'}`)
  }

  const groups: FieldGroup[] = []
  let certificateCount = 0
  let privateKeyCount = 0
  for (const safeContent of p12.safeContents) {
    for (const bag of safeContent.safeBags) {
      const name = friendlyName(bag.attributes)
      if (bag.cert) {
        certificateCount++
        const pem = forge.pki.certificateToPem(bag.cert)
        const der = bytes(forge.asn1.toDer(forge.pki.certificateToAsn1(bag.cert)).getBytes())
        const parsed = await parseCertificate(der)
        groups.push({ title: `证书 ${certificateCount} · ${name}`, items: [
          { label: '主题', value: bag.cert.subject.attributes.map((item) => `${item.shortName ?? item.name}=${item.value}`).join(', ') },
          { label: '颁发者', value: bag.cert.issuer.attributes.map((item) => `${item.shortName ?? item.name}=${item.value}`).join(', ') },
          { label: '算法', value: parsed.algorithm },
          { label: '证书 PEM', value: pem, mono: true }
        ] })
      }
      if (bag.key) {
        privateKeyCount++
        groups.push({ title: `私钥 ${privateKeyCount} · ${name}`, items: [
          { label: '私钥 PEM', value: forge.pki.privateKeyToPem(bag.key), mono: true, sensitive: true }
        ] })
      }
    }
  }
  groups.unshift({ title: '容器摘要', items: [
    { label: '证书数量', value: String(certificateCount) },
    { label: '私钥数量', value: String(privateKeyCount) },
    { label: '完整性校验', value: '口令 MAC 校验通过' }
  ] })
  return report('pkcs12', 'PKCS#12 / PFX 容器', 'PKCS#12', source, groups, privateKeyCount ? [{ id: 'PFX-KEY', status: 'warn', title: '容器含私钥', detail: '私钥仅在当前页面内解密，默认遮罩显示。关闭或刷新页面后即丢弃。' }] : [])
}

export function decryptPkcs8(source: Uint8Array, password: string): { report: ParseReport; privatePem: string } {
  try {
    const encrypted = forge.asn1.fromDer(forge.util.createBuffer(binary(source)))
    const privateInfo = forge.pki.decryptPrivateKeyInfo(encrypted, password)
    if (!privateInfo) throw new Error('口令不正确或加密算法不受支持')
    const privatePem = forge.pki.privateKeyInfoToPem(privateInfo)
    const result = report('encrypted-private-key', '加密 PKCS#8 私钥', 'PBES2 / PKCS#8', source, [
      { title: '解密结果', items: [
        { label: '状态', value: '口令验证通过' },
        { label: '明文私钥 PEM', value: privatePem, mono: true, sensitive: true }
      ] }
    ], [{ id: 'PK8-PLAIN', status: 'warn', title: '明文私钥已进入页面内存', detail: '请完成转换后立即离开本页，不要将明文私钥保存到不受控位置。' }])
    return { report: result, privatePem }
  } catch (cause) {
    throw new Error(`PKCS#8 解密失败：${cause instanceof Error ? cause.message : '未知错误'}`)
  }
}

export function reencryptPkcs8(privatePem: string, password: string, iterations = 100_000): string {
  if (password.length < 8) throw new Error('新口令至少需要 8 个字符。')
  const decoded = decodeFlexibleInput(privatePem).bytes
  const privateInfo = forge.asn1.fromDer(forge.util.createBuffer(binary(decoded)))
  const encrypted = forge.pki.encryptPrivateKeyInfo(privateInfo, password, { algorithm: 'aes256', count: Math.max(10_000, iterations), saltSize: 16 })
  return forge.pki.encryptedPrivateKeyToPem(encrypted)
}

export async function parseCms(source: Uint8Array): Promise<ParseReport> {
  const parsed = fromBER(Uint8Array.from(source).buffer)
  if (parsed.offset === -1) throw new Error('CMS / PKCS#7 不是完整的 ASN.1 DER 数据。')
  const content = new ContentInfo({ schema: parsed.result })
  const typeNames: Record<string, string> = {
    '1.2.840.113549.1.7.1': 'Data',
    '1.2.840.113549.1.7.2': 'SignedData',
    '1.2.840.113549.1.7.3': 'EnvelopedData',
    '1.2.840.113549.1.7.5': 'DigestedData',
    '1.2.840.113549.1.7.6': 'EncryptedData'
  }
  const type = typeNames[content.contentType] ?? content.contentType
  const groups: FieldGroup[] = [{ title: 'CMS 摘要', items: [{ label: '内容类型', value: type }, { label: 'OID', value: content.contentType, mono: true }] }]
  const findings: Finding[] = []
  if (content.contentType === '1.2.840.113549.1.7.2') {
    const signed = new SignedData({ schema: content.content })
    groups[0].items.push({ label: '签名者数量', value: String(signed.signerInfos.length) }, { label: '证书数量', value: String(signed.certificates?.length ?? 0) }, { label: 'CRL 数量', value: String(signed.crls?.length ?? 0) })
    signed.signerInfos.forEach((signer, index) => groups.push({ title: `签名者 ${index + 1}`, items: [
      { label: '摘要算法', value: signer.digestAlgorithm.algorithmId, mono: true },
      { label: '签名算法', value: signer.signatureAlgorithm.algorithmId, mono: true },
      { label: '签名长度', value: `${signer.signature.valueBlock.valueHexView.length} 字节` }
    ] }))
    if (signed.signerInfos.length && signed.encapContentInfo.eContent) {
      for (let index = 0; index < signed.signerInfos.length; index++) {
        try {
          const valid = await signed.verify({ signer: index, checkChain: false })
          findings.push(valid
            ? { id: `CMS-SIG-${index}`, status: 'pass', title: `签名者 ${index + 1} 验签通过`, detail: '封装内容与 CMS 签名值一致；证书信任链需另行验证。' }
            : { id: `CMS-SIG-${index}`, status: 'fail', title: `签名者 ${index + 1} 验签失败`, detail: '封装内容、签名值或签名者证书不一致。' })
        } catch (cause) {
          findings.push({ id: `CMS-SIG-${index}`, status: 'fail', title: `签名者 ${index + 1} 无法验签`, detail: cause instanceof Error ? cause.message : '签名算法不受当前浏览器支持。' })
        }
      }
    } else if (signed.signerInfos.length) findings.push({ id: 'CMS-DETACHED', status: 'info', title: '分离签名需要原文', detail: '该 CMS 未封装被签名内容，需要原始文件才能验签。' })
  }
  return report('pkcs7', 'CMS / PKCS#7 容器', type, source, groups, findings)
}

class Reader {
  offset = 0
  constructor(readonly data: Uint8Array) {}
  take(length: number): Uint8Array { if (length < 0 || this.offset + length > this.data.length) throw new Error('JKS 数据被截断'); const value = this.data.slice(this.offset, this.offset + length); this.offset += length; return value }
  u16(): number { const value = new DataView(this.take(2).buffer).getUint16(0); return value }
  i32(): number { return new DataView(this.take(4).buffer).getInt32(0) }
  i64(): bigint { return new DataView(this.take(8).buffer).getBigInt64(0) }
  utf(): string { return new TextDecoder().decode(this.take(this.u16())) }
}

function javaPassword(password: string): Uint8Array {
  const output = new Uint8Array(password.length * 2)
  for (let index = 0; index < password.length; index++) { const code = password.charCodeAt(index); output[index * 2] = code >>> 8; output[index * 2 + 1] = code & 0xff }
  return output
}

async function sha1(...parts: Uint8Array[]): Promise<Uint8Array> {
  const size = parts.reduce((total, part) => total + part.length, 0)
  const joined = new Uint8Array(size); let offset = 0
  for (const part of parts) { joined.set(part, offset); offset += part.length }
  return new Uint8Array(await crypto.subtle.digest('SHA-1', joined))
}

async function decryptJksKey(protectedInfo: Uint8Array, password: string): Promise<Uint8Array> {
  const parsed = fromBER(Uint8Array.from(protectedInfo).buffer)
  const sequence = (parsed.result as any).valueBlock?.value
  const algorithm = sequence?.[0]?.valueBlock?.value?.[0]?.valueBlock?.toString?.()
  if (algorithm !== '1.3.6.1.4.1.42.2.17.1.1') throw new Error(`不支持的 JKS 私钥保护算法：${algorithm || '未知'}`)
  const value: Uint8Array = sequence?.[1]?.valueBlock?.valueHexView
  if (!value || value.length < 40) throw new Error('JKS 受保护私钥数据无效。')
  const passwordBytes = javaPassword(password)
  const salt = value.subarray(0, 20)
  const encrypted = value.subarray(20, value.length - 20)
  const expected = value.subarray(value.length - 20)
  const xorKey = new Uint8Array(encrypted.length)
  let digest = salt
  for (let offset = 0; offset < xorKey.length; offset += 20) {
    digest = await sha1(passwordBytes, digest)
    xorKey.set(digest.subarray(0, Math.min(20, xorKey.length - offset)), offset)
  }
  const plain = encrypted.map((item, index) => item ^ xorKey[index])
  const actual = await sha1(passwordBytes, plain)
  if (!expected.every((item, index) => item === actual[index])) throw new Error('JKS 私钥口令校验失败。')
  return plain
}

export async function parseJks(source: Uint8Array, password: string): Promise<ParseReport> {
  if (source.length < 32) throw new Error('JKS 文件过短。')
  const body = source.subarray(0, source.length - 20)
  const actual = source.subarray(source.length - 20)
  const expected = await sha1(javaPassword(password), new TextEncoder().encode('Mighty Aphrodite'), body)
  if (!actual.every((value, index) => value === expected[index])) throw new Error('JKS 口令错误或完整性校验失败。')
  const reader = new Reader(body)
  if ((reader.i32() >>> 0) !== 0xfeedfeed) throw new Error('不是 JKS KeyStore。')
  const version = reader.i32(); if (version !== 1 && version !== 2) throw new Error(`不支持 JKS v${version}。`)
  const count = reader.i32(); if (count < 0 || count > 10_000) throw new Error('JKS 条目数量无效。')
  const groups: FieldGroup[] = [{ title: 'KeyStore 摘要', items: [{ label: '版本', value: `JKS v${version}` }, { label: '条目数', value: String(count) }, { label: '完整性校验', value: 'SHA-1 口令校验通过' }] }]
  for (let index = 0; index < count; index++) {
    const tag = reader.i32(); const alias = reader.utf(); const modified = new Date(Number(reader.i64())).toISOString()
    if (tag === 1) {
      const protectedKey = reader.take(reader.i32()); const chainCount = reader.i32()
      const privateKey = await decryptJksKey(protectedKey, password)
      const items = [{ label: '类型', value: '私钥条目' }, { label: '别名', value: alias }, { label: '修改时间', value: modified }, { label: '证书链长度', value: String(chainCount) }, { label: '私钥 PEM（PKCS#8）', value: formatPem(privateKey, 'PRIVATE KEY'), mono: true, sensitive: true }]
      for (let cert = 0; cert < chainCount; cert++) { const certType = version === 2 ? reader.utf() : 'X.509'; const certBytes = reader.take(reader.i32()); items.push({ label: `证书 ${cert + 1}`, value: `${certType} · ${certBytes.length} 字节` }) }
      groups.push({ title: `条目 ${index + 1} · ${alias}`, items })
    } else if (tag === 2) {
      const certType = version === 2 ? reader.utf() : 'X.509'; const certBytes = reader.take(reader.i32())
      groups.push({ title: `条目 ${index + 1} · ${alias}`, items: [{ label: '类型', value: '信任证书' }, { label: '别名', value: alias }, { label: '修改时间', value: modified }, { label: '证书', value: `${certType} · ${certBytes.length} 字节` }, { label: '证书 PEM', value: formatPem(certBytes, 'CERTIFICATE'), mono: true }] })
    } else throw new Error(`未知 JKS 条目类型：${tag}`)
  }
  return report('jks', 'Java KeyStore', 'JKS', source, groups, [{ id: 'JKS-SHA1', status: 'warn', title: 'JKS 使用旧式 SHA-1 完整性保护', detail: '建议迁移到使用强口令与现代 PBE 的 PKCS#12。' }])
}

export async function inspectContainer(input: string | Uint8Array, kind: 'auto' | 'pkcs12' | 'pkcs7' | 'jks' | 'encrypted-private-key', password: string): Promise<ParseReport> {
  const decoded = typeof input === 'string' ? decodeFlexibleInput(input) : { bytes: input, kind: 'binary' as MaterialKind }
  const selected = kind === 'auto' ? decoded.kind : kind
  if (selected === 'pkcs12') return parsePkcs12(decoded.bytes, password)
  if (selected === 'pkcs7') return parseCms(decoded.bytes)
  if (selected === 'jks') return parseJks(decoded.bytes, password)
  if (selected === 'encrypted-private-key') return decryptPkcs8(decoded.bytes, password).report
  throw new Error('未识别容器类型，请手动选择 PFX、JKS、CMS 或加密 PKCS#8。')
}
