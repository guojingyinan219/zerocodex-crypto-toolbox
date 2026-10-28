import type { Asn1TreeNode } from '../types'
import { oidName } from '../data/oids'
import { bytesToHex } from './codec'

const universalNames: Record<number, string> = {
  1: 'BOOLEAN', 2: 'INTEGER', 3: 'BIT STRING', 4: 'OCTET STRING', 5: 'NULL',
  6: 'OBJECT IDENTIFIER', 10: 'ENUMERATED', 12: 'UTF8String', 16: 'SEQUENCE',
  17: 'SET', 18: 'NumericString', 19: 'PrintableString', 20: 'TeletexString',
  22: 'IA5String', 23: 'UTCTime', 24: 'GeneralizedTime', 28: 'UniversalString', 30: 'BMPString'
}

function decodeOid(bytes: Uint8Array): string {
  if (!bytes.length) return ''
  const values = [Math.floor(bytes[0] / 40), bytes[0] % 40]
  let value = 0
  for (let index = 1; index < bytes.length; index += 1) {
    value = (value << 7) | (bytes[index] & 0x7f)
    if ((bytes[index] & 0x80) === 0) {
      values.push(value)
      value = 0
    }
  }
  return values.join('.')
}

function decodeValue(tagClass: number, tag: number, content: Uint8Array): string | undefined {
  if (tagClass !== 0) return undefined
  if (tag === 1) return content[0] === 0 ? 'false' : 'true'
  if (tag === 2) {
    if (content.length <= 6) {
      let value = 0
      for (const byte of content) value = value * 256 + byte
      return `${value} (0x${bytesToHex(content)})`
    }
    return `0x${bytesToHex(content)}`
  }
  if (tag === 3) return `${Math.max(0, content.length - 1)} 字节，未用位 ${content[0] ?? 0}`
  if (tag === 4) return content.length <= 24 ? `0x${bytesToHex(content)}` : `${content.length} 字节`
  if (tag === 5) return 'NULL'
  if (tag === 6) {
    const oid = decodeOid(content)
    return `${oid}（${oidName(oid)}）`
  }
  if ([12, 18, 19, 20, 22, 23, 24].includes(tag)) return new TextDecoder().decode(content)
  return undefined
}

function readTag(bytes: Uint8Array, start: number): { tagClass: number; constructed: boolean; tag: number; next: number } {
  if (start >= bytes.length) throw new Error(`偏移 0x${start.toString(16)} 后数据已截断`)
  const first = bytes[start]
  const tagClass = first >> 6
  const constructed = Boolean(first & 0x20)
  let tag = first & 0x1f
  let next = start + 1
  if (tag === 0x1f) {
    tag = 0
    do {
      if (next >= bytes.length) throw new Error(`偏移 0x${next.toString(16)} 的长标签已截断`)
      tag = (tag << 7) | (bytes[next] & 0x7f)
    } while (bytes[next++] & 0x80)
  }
  return { tagClass, constructed, tag, next }
}

function readLength(bytes: Uint8Array, start: number): { length: number; next: number } {
  if (start >= bytes.length) throw new Error(`偏移 0x${start.toString(16)} 缺少长度字段`)
  const first = bytes[start]
  if ((first & 0x80) === 0) return { length: first, next: start + 1 }
  const count = first & 0x7f
  if (count === 0) throw new Error(`偏移 0x${start.toString(16)} 使用了 DER 不允许的不定长编码`)
  if (count > 4 || start + count >= bytes.length) throw new Error(`偏移 0x${start.toString(16)} 的长度字段非法或被截断`)
  let length = 0
  for (let index = 1; index <= count; index += 1) length = length * 256 + bytes[start + index]
  return { length, next: start + count + 1 }
}

function readNode(bytes: Uint8Array, start: number, id: string, depth: number): { node: Asn1TreeNode; next: number } {
  if (depth > 100) throw new Error('ASN.1 嵌套超过 100 层，已停止解析')
  const tagInfo = readTag(bytes, start)
  const lengthInfo = readLength(bytes, tagInfo.next)
  const contentStart = lengthInfo.next
  const end = contentStart + lengthInfo.length
  if (end > bytes.length) throw new Error(`偏移 0x${start.toString(16)} 声明长度 ${lengthInfo.length}，但数据已在 0x${bytes.length.toString(16)} 截断`)
  const children: Asn1TreeNode[] = []
  if (tagInfo.constructed) {
    let cursor = contentStart
    let childIndex = 0
    while (cursor < end) {
      const parsed = readNode(bytes, cursor, `${id}.${childIndex}`, depth + 1)
      children.push(parsed.node)
      cursor = parsed.next
      childIndex += 1
    }
    if (cursor !== end) throw new Error(`偏移 0x${start.toString(16)} 的子节点长度与父节点不一致`)
  }
  const classLabel = ['UNIVERSAL', 'APPLICATION', 'CONTEXT', 'PRIVATE'][tagInfo.tagClass]
  const type = tagInfo.tagClass === 0 ? (universalNames[tagInfo.tag] ?? `UNIVERSAL ${tagInfo.tag}`) : `${classLabel} [${tagInfo.tag}]`
  const content = bytes.subarray(contentStart, end)
  return {
    node: {
      id,
      type,
      offset: start,
      length: end - start,
      value: decodeValue(tagInfo.tagClass, tagInfo.tag, content),
      children
    },
    next: end
  }
}

export function parseAsn1Tree(bytes: Uint8Array): Asn1TreeNode {
  const parsed = readNode(bytes, 0, '0', 0)
  if (parsed.next !== bytes.length) throw new Error(`ASN.1 结构在 0x${parsed.next.toString(16)} 结束，尾部还有 ${bytes.length - parsed.next} 字节`)
  return parsed.node
}

export function hexDump(bytes: Uint8Array, width = 16): string[] {
  const rows: string[] = []
  for (let offset = 0; offset < bytes.length; offset += width) {
    const chunk = bytes.subarray(offset, offset + width)
    const hex = Array.from(chunk, (byte) => byte.toString(16).padStart(2, '0')).join(' ').padEnd(width * 3 - 1)
    const ascii = Array.from(chunk, (byte) => (byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.')).join('')
    rows.push(`${offset.toString(16).padStart(8, '0')}  ${hex}  |${ascii}|`)
  }
  return rows
}
