import CryptoJS from 'crypto-js'
import { sm4DecryptBytes, sm4Encrypt } from 'gmkitx'

export type SymmetricCipher = 'DES' | '3DES-2K' | '3DES-3K' | 'SM4' | 'AES-128' | 'AES-192' | 'AES-256'
export type LegacyCipher = Extract<SymmetricCipher, 'DES' | '3DES-2K' | '3DES-3K'>
export type CipherMode = 'ECB' | 'CBC' | 'CFB' | 'OFB'
export type Padding = 'NONE' | 'PKCS7' | 'ZERO'

const legacyBlockSize = 8

function compactHex(value: string) {
  return value.replace(/[\s:,-]/g, '').toUpperCase()
}

export function normalizeHex(value: string, field = '输入') {
  const compact = compactHex(value)
  if (!compact) throw new Error(`${field}不能为空。`)
  if (compact.length % 2 !== 0 || /[^0-9A-F]/.test(compact)) throw new Error(`${field}必须是偶数长度的十六进制文本。`)
  return compact
}

function byteLength(value: string) {
  return value.length / 2
}

function wordArray(hex: string) {
  return CryptoJS.enc.Hex.parse(hex)
}

function hex(value: CryptoJS.lib.WordArray) {
  return value.toString(CryptoJS.enc.Hex).toUpperCase()
}

export function cipherBlockSize(cipher: SymmetricCipher) {
  return ['DES', '3DES-2K', '3DES-3K'].includes(cipher) ? 8 : 16
}

function keyParts(cipher: SymmetricCipher, rawKey: string) {
  const key = normalizeHex(rawKey, '密钥')
  const expected = cipher === 'DES' ? 8 : cipher === '3DES-2K' ? 16 : cipher === '3DES-3K' ? 24 : cipher === 'AES-192' ? 24 : cipher === 'AES-256' ? 32 : 16
  if (byteLength(key) !== expected) throw new Error(`${cipher} 需要 ${expected} 字节密钥，当前为 ${byteLength(key)} 字节。`)
  return key
}

function validateIV(mode: CipherMode, rawIV: string, blockSize: number) {
  if (mode === 'ECB') return ''
  const iv = normalizeHex(rawIV, 'IV')
  if (byteLength(iv) !== blockSize) throw new Error(`${mode} 模式的 IV 必须为 ${blockSize} 字节。`)
  return iv
}

function paddingMode(padding: Padding) {
  if (padding === 'PKCS7') return CryptoJS.pad.Pkcs7
  if (padding === 'ZERO') return CryptoJS.pad.ZeroPadding
  return CryptoJS.pad.NoPadding
}

function algorithm(cipher: LegacyCipher) {
  return cipher === 'DES' ? CryptoJS.DES : CryptoJS.TripleDES
}

function config(mode: CipherMode, padding: Padding, iv: string) {
  const cryptoMode = mode === 'ECB'
    ? CryptoJS.mode.ECB
    : mode === 'CBC'
      ? CryptoJS.mode.CBC
      : mode === 'CFB'
        ? CryptoJS.mode.CFB
        : CryptoJS.mode.OFB
  return {
    mode: cryptoMode,
    padding: paddingMode(padding),
    ...(mode !== 'ECB' ? { iv: wordArray(iv) } : {})
  }
}

export function cipherHex(args: {
  cipher: SymmetricCipher
  mode: CipherMode
  padding: Padding
  key: string
  iv: string
  data: string
  decrypt?: boolean
}) {
  const data = normalizeHex(args.data, args.decrypt ? '密文' : '数据')
  const key = keyParts(args.cipher, args.key)
  const blockSize = cipherBlockSize(args.cipher)
  const iv = validateIV(args.mode, args.iv, blockSize)
  const streamMode = args.mode === 'CFB' || args.mode === 'OFB'
  const effectivePadding: Padding = streamMode ? 'NONE' : args.padding
  if (!streamMode && effectivePadding === 'NONE' && byteLength(data) % blockSize !== 0) throw new Error(`无填充模式要求数据长度为 ${blockSize} 字节的整数倍。`)
  if (!streamMode && args.decrypt && byteLength(data) % blockSize !== 0) throw new Error(`密文长度必须是 ${blockSize} 字节的整数倍。`)
  if (args.cipher === 'SM4') {
    const options = { mode: args.mode.toLowerCase() as 'ecb' | 'cbc' | 'cfb' | 'ofb', padding: effectivePadding.toLowerCase() as 'pkcs7' | 'zero' | 'none', ...(args.mode !== 'ECB' ? { iv } : {}) }
    if (args.decrypt) return Array.from(sm4DecryptBytes(key, data, options), (byte) => byte.toString(16).padStart(2, '0')).join('').toUpperCase()
    return sm4Encrypt(key, Uint8Array.from(data.match(/.{2}/g) ?? [], (pair) => Number.parseInt(pair, 16)), options).ciphertext.toUpperCase()
  }
  const options = config(args.mode, effectivePadding, iv)
  const engine = args.cipher.startsWith('AES') ? CryptoJS.AES : algorithm(args.cipher as LegacyCipher)
  if (args.decrypt) {
    const result = engine.decrypt(CryptoJS.lib.CipherParams.create({ ciphertext: wordArray(data) }), wordArray(key), options)
    return hex(result)
  }
  return hex(engine.encrypt(wordArray(data), wordArray(key), options).ciphertext)
}

function padZero(hexValue: string, blockSize = legacyBlockSize) {
  const remainder = byteLength(hexValue) % blockSize
  return remainder === 0 ? hexValue : hexValue.padEnd(hexValue.length + (blockSize - remainder) * 2, '0')
}

function desBlock(value: string, key: string, decrypt = false) {
  const options = { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding }
  if (decrypt) return hex(CryptoJS.DES.decrypt(CryptoJS.lib.CipherParams.create({ ciphertext: wordArray(value) }), wordArray(key), options))
  return hex(CryptoJS.DES.encrypt(wordArray(value), wordArray(key), options).ciphertext)
}

export function keyCheckValue(cipher: SymmetricCipher, rawKey: string) {
  const key = keyParts(cipher, rawKey)
  const encrypted = cipherHex({ cipher, mode: 'ECB', padding: 'NONE', key, iv: '', data: ''.padStart(cipherBlockSize(cipher) * 2, '0') })
  return { full: encrypted, short: encrypted.slice(0, 6) }
}

export function xorHex(first: string, second: string) {
  const left = normalizeHex(first, '数据'); const right = normalizeHex(second, '数据 1')
  if (left.length !== right.length) throw new Error('数据与数据 1 的长度必须一致。')
  let output = ''
  for (let index = 0; index < left.length; index += 2) output += (Number.parseInt(left.slice(index, index + 2), 16) ^ Number.parseInt(right.slice(index, index + 2), 16)).toString(16).padStart(2, '0')
  return output.toUpperCase()
}

export function xorBlockCheck(rawData: string) {
  const data = padZero(normalizeHex(rawData, '数据'))
  let result = '0000000000000000'
  for (let index = 0; index < data.length; index += legacyBlockSize * 2) result = xorHex(result, data.slice(index, index + legacyBlockSize * 2))
  return result
}

export function cbcMac(cipher: SymmetricCipher, rawKey: string, rawData: string) {
  const blockSize = cipherBlockSize(cipher)
  const data = padZero(normalizeHex(rawData, '数据'), blockSize)
  const encrypted = cipherHex({ cipher, mode: 'CBC', padding: 'NONE', key: rawKey, iv: ''.padStart(blockSize * 2, '0'), data })
  return encrypted.slice(-blockSize * 2)
}

export function x919Mac(rawKey: string, rawData: string) {
  const key = normalizeHex(rawKey, '密钥')
  if (byteLength(key) !== 16 && byteLength(key) !== 24) throw new Error('X9.19 MAC 需要 16 或 24 字节的 3DES 密钥。')
  const data = padZero(normalizeHex(rawData, '数据'))
  const leftKey = key.slice(0, 16)
  const rightKey = key.slice(16, 32)
  const encrypted = cipherHex({ cipher: 'DES', mode: 'CBC', padding: 'NONE', key: leftKey, iv: '0000000000000000', data })
  const middle = desBlock(encrypted.slice(-16), rightKey, true)
  return desBlock(middle, leftKey)
}
