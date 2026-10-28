import { fromBER } from 'asn1js'
import type { Finding, MaterialKind } from '../types'

export interface PemBlock {
  label: string
  body: string
  text: string
  bytes: Uint8Array
}

const pemPattern = /-----BEGIN ([A-Z0-9 #]+)-----([\s\S]*?)-----END \1-----/g

export function bytesToHex(bytes: Uint8Array, separator = ''): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join(separator)
}

export function hexToBytes(value: string): Uint8Array {
  const clean = value.replace(/(?:0x|[^a-fA-F0-9])/g, '')
  if (!clean || clean.length % 2 !== 0) throw new Error('Hex 内容必须包含偶数个十六进制字符')
  return Uint8Array.from(clean.match(/.{2}/g)!.map((item) => Number.parseInt(item, 16)))
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = ''
  const chunkSize = 0x8000
  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize))
  }
  return btoa(binary)
}

export function base64ToBytes(value: string): Uint8Array {
  const clean = value.replace(/\s/g, '')
  if (!clean || !/^[A-Za-z0-9+/]*={0,2}$/.test(clean) || clean.length % 4 !== 0) {
    throw new Error('Base64 内容包含非法字符或填充不完整')
  }
  const binary = atob(clean)
  return Uint8Array.from(binary, (char) => char.charCodeAt(0))
}

export function formatPem(bytes: Uint8Array, label: string, width = 64): string {
  const base64 = bytesToBase64(bytes)
  const body = base64.match(new RegExp(`.{1,${width}}`, 'g'))?.join('\n') ?? base64
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----`
}

export function extractPemBlocks(input: string): PemBlock[] {
  const blocks: PemBlock[] = []
  pemPattern.lastIndex = 0
  for (const match of input.matchAll(pemPattern)) {
    const label = match[1]
    const body = match[2].replace(/\s/g, '')
    try {
      blocks.push({ label, body, text: match[0], bytes: base64ToBytes(body) })
    } catch {
      // The format doctor reports malformed blocks; recognition keeps going.
    }
  }
  return blocks
}

export function pemLabelToKind(label: string): MaterialKind {
  if (label === 'CERTIFICATE') return 'certificate'
  if (label === 'CERTIFICATE REQUEST' || label === 'NEW CERTIFICATE REQUEST') return 'csr'
  if (label === 'ENCRYPTED PRIVATE KEY') return 'encrypted-private-key'
  if (label.includes('PRIVATE KEY')) return 'private-key'
  if (label === 'PUBLIC KEY') return 'public-key'
  if (label === 'PKCS7' || label === 'CMS') return 'pkcs7'
  if (label === 'PKCS12') return 'pkcs12'
  return 'unknown'
}

function firstOid(bytes: Uint8Array): string | undefined {
  const parsed = fromBER(bytes.slice().buffer)
  if (parsed.offset === -1) return undefined
  const stack: unknown[] = [parsed.result]
  while (stack.length) {
    const node = stack.shift() as {
      idBlock?: { tagClass?: number; tagNumber?: number }
      valueBlock?: { toString?: () => string; value?: unknown[] }
    }
    if (node.idBlock?.tagClass === 1 && node.idBlock.tagNumber === 6) return node.valueBlock?.toString?.()
    if (Array.isArray(node.valueBlock?.value)) stack.push(...node.valueBlock.value)
  }
  return undefined
}

export function classifyDer(bytes: Uint8Array): MaterialKind {
  if (bytes.length >= 4 && bytes[0] === 0xfe && bytes[1] === 0xed && bytes[2] === 0xfe && bytes[3] === 0xed) return 'jks'
  const parsed = fromBER(bytes.slice().buffer)
  if (parsed.offset === -1) return 'binary'
  const root = parsed.result as {
    idBlock: { tagClass: number; tagNumber: number }
    valueBlock?: { value?: unknown[] }
  }
  if (root.idBlock.tagClass !== 1 || root.idBlock.tagNumber !== 16) return 'binary'
  const children = root.valueBlock?.value as Array<{
    idBlock?: { tagClass?: number; tagNumber?: number }
    valueBlock?: { value?: unknown[]; valueDec?: number }
  }> | undefined
  if (!children) return 'unknown'
  const oid = firstOid(bytes)
  if (oid === '1.2.840.113549.1.7.2') return 'pkcs7'
  if (children[0]?.idBlock?.tagNumber === 2 && children[0]?.valueBlock?.valueDec === 3 && oid?.startsWith('1.2.840.113549.1.7.')) return 'pkcs12'
  if (children.length === 3 && children[0]?.idBlock?.tagNumber === 16 && children[1]?.idBlock?.tagNumber === 16 && children[2]?.idBlock?.tagNumber === 3) {
    const inner = children[0]?.valueBlock?.value as Array<{ idBlock?: { tagNumber?: number } }> | undefined
    if (inner?.[0]?.idBlock?.tagNumber === 2) {
      const hasAttributes = inner.some((item) => item.idBlock?.tagNumber === 0)
      return hasAttributes ? 'csr' : 'certificate'
    }
  }
  if (children.length >= 3 && children[0]?.idBlock?.tagNumber === 2 && children[1]?.idBlock?.tagNumber === 16 && children[2]?.idBlock?.tagNumber === 4) return 'private-key'
  if (children.length === 2 && children[0]?.idBlock?.tagNumber === 16 && children[1]?.idBlock?.tagNumber === 4) return 'encrypted-private-key'
  if (children.length === 2 && children[0]?.idBlock?.tagNumber === 16 && children[1]?.idBlock?.tagNumber === 3) return 'public-key'
  return 'unknown'
}

export function decodeFlexibleInput(input: string): { bytes: Uint8Array; kind: MaterialKind; pemLabel?: string } {
  const trimmed = input.trim()
  const blocks = extractPemBlocks(trimmed)
  if (blocks.length) {
    const first = blocks[0]
    return { bytes: first.bytes, kind: pemLabelToKind(first.label), pemLabel: first.label }
  }
  const compact = trimmed.replace(/\s/g, '')
  if (/^(?:0x)?[a-fA-F0-9\s:,-]+$/.test(trimmed) && compact.replace(/^0x/, '').length % 2 === 0) {
    const bytes = hexToBytes(trimmed)
    return { bytes, kind: classifyDer(bytes) === 'binary' ? 'hex' : classifyDer(bytes) }
  }
  if (/^[A-Za-z0-9+/\s]+={0,2}$/.test(trimmed) && compact.length % 4 === 0) {
    const bytes = base64ToBytes(compact)
    const kind = classifyDer(bytes)
    return { bytes, kind: kind === 'binary' ? 'base64' : kind }
  }
  const bytes = new TextEncoder().encode(input)
  return { bytes, kind: 'unknown' }
}

export function auditText(input: string): Finding[] {
  const findings: Finding[] = []
  const hasBom = input.charCodeAt(0) === 0xfeff
  findings.push({ id: 'C6', status: hasBom ? 'warn' : 'pass', title: 'UTF-8 BOM', detail: hasBom ? '检测到 UTF-8 BOM，部分命令行工具会因此无法识别首行。' : '未检测到 BOM。', fix: hasBom ? '移除首字符后重新解析。' : undefined })

  const begin = input.match(/-----BEGIN ([A-Z0-9 #]+)-----/)
  const end = input.match(/-----END ([A-Z0-9 #]+)-----/)
  const paired = Boolean(begin && end && begin[1] === end[1])
  findings.push({ id: 'C2', status: begin || end ? (paired ? 'pass' : 'fail') : 'info', title: 'PEM 首尾标签', detail: begin || end ? (paired ? `BEGIN/END ${begin?.[1]} 标签配对正确。` : 'PEM 首尾标签缺失或名称不一致。') : '当前内容不是 PEM 包装。', fix: !paired && (begin || end) ? '补齐标签，并确保 BEGIN 与 END 名称完全一致。' : undefined })

  const escaped = /&(?:amp|lt|gt|quot|#39);/.exec(input)
  findings.push({ id: 'C7', status: escaped ? 'fail' : 'pass', title: '转义与多余空白', detail: escaped ? `检测到 HTML 转义残留 ${escaped[0]}，位置 ${escaped.index + 1}。` : '未发现 HTML 转义残留。', fix: escaped ? '先还原 HTML 实体，再重新识别内容。' : undefined })

  const newlineStyle = input.includes('\r\n') && /(?<!\r)\n/.test(input) ? 'mixed' : input.includes('\r\n') ? 'crlf' : 'lf'
  findings.push({ id: 'C5', status: newlineStyle === 'mixed' ? 'warn' : 'pass', title: '换行与行宽', detail: newlineStyle === 'mixed' ? '检测到 CRLF 与 LF 混用。' : `使用 ${newlineStyle.toUpperCase()} 换行。` })

  let base64Body = input
  if (begin && end) base64Body = input.slice(input.indexOf(begin[0]) + begin[0].length, input.lastIndexOf(end[0]))
  const lines = base64Body.trim().split(/\r?\n/)
  const illegal: string[] = []
  lines.forEach((line, lineIndex) => {
    for (let column = 0; column < line.length; column += 1) {
      const char = line[column]
      if (!/[A-Za-z0-9+/=\s]/.test(char)) illegal.push(`第 ${lineIndex + 1} 行第 ${column + 1} 列 “${char}”`)
    }
  })
  findings.push({ id: 'C4', status: illegal.length ? 'fail' : 'pass', title: 'Base64 字符集', detail: illegal.length ? `发现非法字符：${illegal.slice(0, 3).join('、')}${illegal.length > 3 ? ` 等 ${illegal.length} 处` : ''}。` : '字符集合法。', fix: illegal.length ? '删除非法字符；不要直接粘贴富文本。' : undefined })

  const compact = base64Body.replace(/\s/g, '')
  findings.push({ id: 'C8', status: compact.length % 4 === 0 ? 'pass' : 'fail', title: 'Base64 长度', detail: compact.length % 4 === 0 ? `长度 ${compact.length}，是 4 的倍数。` : `长度 ${compact.length}，不是 4 的倍数。`, fix: compact.length % 4 ? '检查内容是否被截断，或补齐正确的 = 填充。' : undefined })

  const blocks = extractPemBlocks(input)
  findings.push({ id: 'C10', status: blocks.length > 1 ? 'warn' : 'pass', title: '多份材料', detail: blocks.length > 1 ? `检测到 ${blocks.length} 份 PEM 材料，将逐份处理。` : '未检测到多份材料混排。' })

  let derValid = false
  try {
    const bytes = blocks[0]?.bytes ?? base64ToBytes(compact)
    derValid = fromBER(bytes.slice().buffer).offset !== -1
  } catch {
    derValid = false
  }
  findings.push({ id: 'C9', status: derValid ? 'pass' : 'fail', title: 'DER 结构', detail: derValid ? 'Base64 解码后是结构完整的 ASN.1 DER/BER 数据。' : '解码后无法得到完整 ASN.1 结构。', fix: derValid ? undefined : '检查 Base64 是否截断，或确认输入不是普通文本。' })
  return findings
}

export function repairText(input: string): string {
  const textarea = document.createElement('textarea')
  textarea.innerHTML = input.replace(/^\ufeff/, '')
  const decoded = textarea.value
  const blocks = extractPemBlocks(decoded)
  if (!blocks.length) return decoded.trim()
  return blocks.map((block) => formatPem(block.bytes, block.label)).join('\n')
}
