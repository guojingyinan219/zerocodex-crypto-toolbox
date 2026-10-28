import { sm3Digest } from 'gmkitx'
import CryptoJS from 'crypto-js'
import { md4 } from 'hash-wasm'

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder('utf-8', { fatal: true })

function bytesToBinary(bytes: Uint8Array) {
  let binary = ''
  const chunkSize = 0x8000
  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize))
  }
  return binary
}

function normalizeBase64(value: string) {
  const compact = value.replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/')
  if (!compact || /[^A-Za-z0-9+/=]/.test(compact) || /=/.test(compact.slice(0, -2))) {
    throw new Error('输入不是有效的 Base64 文本。')
  }
  const withoutPadding = compact.replace(/=+$/, '')
  if (withoutPadding.length % 4 === 1) throw new Error('Base64 长度不正确。')
  return withoutPadding.padEnd(Math.ceil(withoutPadding.length / 4) * 4, '=')
}

export function encodeBase64Text(value: string) {
  return btoa(bytesToBinary(textEncoder.encode(value)))
}

export function decodeBase64Text(value: string) {
  try {
    const binary = atob(normalizeBase64(value))
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0))
    return textDecoder.decode(bytes)
  } catch (cause) {
    if (cause instanceof Error && cause.message.includes('Base64')) throw cause
    throw new Error('Base64 内容不是有效的 UTF-8 文本。')
  }
}

export function encodeHexText(value: string) {
  return Array.from(textEncoder.encode(value), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

export function decodeHexText(value: string) {
  const compact = value.replace(/[\s:,-]/g, '')
  if (!compact || compact.length % 2 !== 0 || /[^0-9a-f]/i.test(compact)) {
    throw new Error('Hex 必须由偶数个十六进制字符组成。')
  }
  try {
    const bytes = Uint8Array.from(compact.match(/.{2}/g) ?? [], (pair) => Number.parseInt(pair, 16))
    return textDecoder.decode(bytes)
  } catch {
    throw new Error('Hex 内容不是有效的 UTF-8 文本。')
  }
}

export function encodeUrlText(value: string) {
  return encodeURIComponent(value)
}

export function decodeUrlText(value: string) {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '))
  } catch {
    throw new Error('URL 编码包含不完整或无效的转义序列。')
  }
}

export function formatJson(value: string, compact = false) {
  try {
    return JSON.stringify(JSON.parse(value), null, compact ? 0 : 2)
  } catch (cause) {
    const detail = cause instanceof Error ? cause.message : '未知语法错误'
    throw new Error(`JSON 解析失败：${detail}`)
  }
}

export type DigestAlgorithm = 'SM3' | 'MD4' | 'MD5' | 'SHA-1' | 'SHA-224' | 'SHA-256' | 'SHA-384' | 'SHA-512'

export async function digestText(value: string, algorithm: DigestAlgorithm) {
  const bytes = textEncoder.encode(value)
  if (algorithm === 'SM3') return sm3Digest(bytes)
  if (algorithm === 'MD4') return md4(value)
  if (algorithm === 'MD5') return CryptoJS.MD5(value).toString()
  if (algorithm === 'SHA-1') return CryptoJS.SHA1(value).toString()
  if (algorithm === 'SHA-224') return CryptoJS.SHA224(value).toString()
  const digest = new Uint8Array(await crypto.subtle.digest(algorithm, bytes))
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

export function createUuid() {
  return crypto.randomUUID()
}

export type RandomByteFormat = 'hex' | 'base64' | 'base64url'

const randomWordRange = 0x1_0000_0000

export function generateSecureIntegers(minimum: number, maximum: number, count = 1) {
  if (!Number.isSafeInteger(minimum) || !Number.isSafeInteger(maximum)) {
    throw new Error('最小值和最大值必须是安全整数。')
  }
  if (minimum > maximum) throw new Error('最小值不能大于最大值。')
  if (!Number.isInteger(count) || count < 1 || count > 1000) {
    throw new Error('生成数量必须在 1 到 1000 之间。')
  }
  const span = maximum - minimum + 1
  if (span > randomWordRange) throw new Error('随机整数范围不能超过 2^32。')

  const cutoff = Math.floor(randomWordRange / span) * span
  const source = new Uint32Array(Math.min(count * 2, 2048))
  const output: number[] = []
  while (output.length < count) {
    crypto.getRandomValues(source)
    for (const value of source) {
      if (value < cutoff) output.push(minimum + (value % span))
      if (output.length === count) break
    }
  }
  return output
}

function encodeRandomBytes(bytes: Uint8Array, format: RandomByteFormat) {
  if (format === 'hex') return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
  const base64 = btoa(bytesToBinary(bytes))
  return format === 'base64url' ? base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') : base64
}

export function generateSecureRandomBytes(length: number, count = 1, format: RandomByteFormat = 'hex') {
  if (!Number.isInteger(length) || length < 1 || length > 4096) {
    throw new Error('字节长度必须在 1 到 4096 之间。')
  }
  if (!Number.isInteger(count) || count < 1 || count > 100) {
    throw new Error('生成数量必须在 1 到 100 之间。')
  }
  if (!['hex', 'base64', 'base64url'].includes(format)) throw new Error('不支持的随机字节输出格式。')

  return Array.from({ length: count }, () => {
    const bytes = new Uint8Array(length)
    crypto.getRandomValues(bytes)
    return encodeRandomBytes(bytes, format)
  })
}

export function generateSecureRandomStrings(length: number, count: number, characterSets: string[]) {
  if (!Number.isInteger(length) || length < 1 || length > 4096) {
    throw new Error('字符串长度必须在 1 到 4096 之间。')
  }
  if (!Number.isInteger(count) || count < 1 || count > 100) {
    throw new Error('生成数量必须在 1 到 100 之间。')
  }
  const characters = Array.from(new Set(characterSets.flatMap((set) => Array.from(set))))
  if (characters.length < 2) throw new Error('请至少选择一个包含两个字符的字符集。')

  const cutoff = Math.floor(randomWordRange / characters.length) * characters.length
  return Array.from({ length: count }, () => {
    const output: string[] = []
    const source = new Uint32Array(Math.min(length * 2, 8192))
    while (output.length < length) {
      crypto.getRandomValues(source)
      for (const value of source) {
        if (value < cutoff) output.push(characters[value % characters.length])
        if (output.length === length) break
      }
    }
    return output.join('')
  })
}
