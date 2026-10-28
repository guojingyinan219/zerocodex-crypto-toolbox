import {
  CipherMode,
  InputFormat,
  OutputFormat,
  PaddingMode,
  SM2CipherMode,
  sm2Decrypt,
  sm2DecryptBytes,
  sm2Encrypt,
  sm2Sign,
  sm2Verify,
  sm3Digest,
  sm3Hmac,
  sm4Decrypt,
  sm4DecryptBytes,
  sm4Encrypt
} from 'gmkitx'
import { bytesToHex, hexToBytes } from './codec'

export type DataEncoding = 'utf8' | 'hex'
export type Sm2CipherOrder = 'C1C3C2' | 'C1C2C3'
export type Sm2SignatureEncoding = 'raw' | 'der'
export type Sm4AdvancedMode = 'CTR' | 'GCM' | 'CCM'

function cleanHex(value: string, label: string, expectedBytes?: number): string {
  const normalized = value.replace(/[\s:]/g, '').toUpperCase()
  if (!normalized || !/^[0-9A-F]+$/.test(normalized) || normalized.length % 2) throw new Error(`${label} 必须是偶数长度 Hex。`)
  if (expectedBytes !== undefined && normalized.length !== expectedBytes * 2) throw new Error(`${label} 必须是 ${expectedBytes} 字节。`)
  return normalized
}

function messageBytes(value: string, encoding: DataEncoding): Uint8Array {
  return encoding === 'hex' ? hexToBytes(cleanHex(value, '数据')) : new TextEncoder().encode(value)
}

function cipherMode(order: Sm2CipherOrder) {
  return order === 'C1C2C3' ? SM2CipherMode.C1C2C3 : SM2CipherMode.C1C3C2
}

export function signSm2(args: { privateKey: string; message: string; encoding: DataEncoding; format: Sm2SignatureEncoding; userId: string }) {
  const privateKey = cleanHex(args.privateKey, 'SM2 私钥 D', 32)
  return sm2Sign(privateKey, messageBytes(args.message, args.encoding), {
    signatureFormat: args.format,
    outputFormat: OutputFormat.HEX,
    userId: args.userId || undefined
  }).toUpperCase()
}

export function verifySm2(args: { publicKey: string; message: string; encoding: DataEncoding; signature: string; format: Sm2SignatureEncoding | 'auto'; userId: string }) {
  let publicKey = cleanHex(args.publicKey, 'SM2 公钥')
  if (publicKey.length === 128) publicKey = `04${publicKey}`
  if (![66, 130].includes(publicKey.length)) throw new Error('SM2 公钥必须是压缩点或 04 || X || Y。')
  const signature = cleanHex(args.signature, 'SM2 签名')
  return sm2Verify(publicKey, messageBytes(args.message, args.encoding), signature, {
    signatureFormat: args.format,
    inputFormat: InputFormat.HEX,
    userId: args.userId || undefined
  })
}

export function encryptSm2(args: { publicKey: string; message: string; encoding: DataEncoding; order: Sm2CipherOrder }) {
  let publicKey = cleanHex(args.publicKey, 'SM2 公钥')
  if (publicKey.length === 128) publicKey = `04${publicKey}`
  return sm2Encrypt(publicKey, messageBytes(args.message, args.encoding), { mode: cipherMode(args.order), outputFormat: OutputFormat.HEX }).toUpperCase()
}

export function decryptSm2(args: { privateKey: string; ciphertext: string; order: Sm2CipherOrder; output: DataEncoding }) {
  const privateKey = cleanHex(args.privateKey, 'SM2 私钥 D', 32)
  const ciphertext = cleanHex(args.ciphertext, 'SM2 密文')
  const options = { mode: cipherMode(args.order), inputFormat: InputFormat.HEX }
  if (args.output === 'hex') return bytesToHex(sm2DecryptBytes(privateKey, ciphertext, options))
  return sm2Decrypt(privateKey, ciphertext, options)
}

export function hmacSm3(key: string, message: string, keyEncoding: DataEncoding, messageEncoding: DataEncoding) {
  return sm3Hmac(messageBytes(key, keyEncoding), messageBytes(message, messageEncoding), { outputFormat: OutputFormat.HEX }).toUpperCase()
}

export function sm2Kdf(zHex: string, outputBytes: number) {
  const z = hexToBytes(cleanHex(zHex, '共享秘密 Z'))
  if (!Number.isInteger(outputBytes) || outputBytes < 1 || outputBytes > 8192) throw new Error('派生长度必须在 1 到 8192 字节之间。')
  const result = new Uint8Array(outputBytes)
  let offset = 0
  for (let counter = 1; offset < outputBytes; counter += 1) {
    const input = new Uint8Array(z.length + 4)
    input.set(z)
    new DataView(input.buffer).setUint32(z.length, counter, false)
    const block = hexToBytes(sm3Digest(input, { outputFormat: OutputFormat.HEX }))
    const take = Math.min(block.length, outputBytes - offset)
    result.set(block.subarray(0, take), offset)
    offset += take
  }
  return bytesToHex(result)
}

function sm4Block(key: string, block: Uint8Array) {
  return hexToBytes(sm4Encrypt(key, block, { mode: CipherMode.ECB, padding: PaddingMode.NONE, outputFormat: OutputFormat.HEX }).ciphertext)
}

function xorBytes(left: Uint8Array, right: Uint8Array) {
  return left.map((value, index) => value ^ right[index])
}

function doubleBlock(block: Uint8Array) {
  const result = new Uint8Array(16)
  let carry = 0
  for (let index = 15; index >= 0; index -= 1) {
    const nextCarry = block[index] >>> 7
    result[index] = ((block[index] << 1) & 0xff) | carry
    carry = nextCarry
  }
  if (carry) result[15] ^= 0x87
  return result
}

export function sm4Cmac(keyHex: string, dataHex: string) {
  const key = cleanHex(keyHex, 'SM4 密钥', 16)
  const data = dataHex.trim() ? hexToBytes(cleanHex(dataHex, '消息')) : new Uint8Array()
  const subKey1 = doubleBlock(sm4Block(key, new Uint8Array(16)))
  const subKey2 = doubleBlock(subKey1)
  const blockCount = Math.max(1, Math.ceil(data.length / 16))
  const complete = data.length > 0 && data.length % 16 === 0
  const last = new Uint8Array(16)
  if (complete) last.set(data.subarray((blockCount - 1) * 16))
  else { const tail = data.subarray((blockCount - 1) * 16); last.set(tail); last[tail.length] = 0x80 }
  const finalBlock = xorBytes(last, complete ? subKey1 : subKey2)
  let state: Uint8Array<ArrayBufferLike> = new Uint8Array(16)
  for (let index = 0; index < blockCount - 1; index += 1) state = sm4Block(key, xorBytes(state, data.subarray(index * 16, index * 16 + 16)))
  return bytesToHex(sm4Block(key, xorBytes(state, finalBlock)))
}

export function encryptSm4Advanced(args: { mode: Sm4AdvancedMode; key: string; iv: string; data: string; encoding: DataEncoding; aad: string; aadEncoding: DataEncoding; tagLength: number }) {
  const key = cleanHex(args.key, 'SM4 密钥', 16)
  const iv = cleanHex(args.iv, args.mode === 'CCM' ? 'Nonce' : 'IV', args.mode === 'GCM' ? 12 : args.mode === 'CTR' ? 16 : undefined)
  const result = sm4Encrypt(key, messageBytes(args.data, args.encoding), {
    mode: CipherMode[args.mode], padding: PaddingMode.NONE, iv,
    aad: args.aad ? messageBytes(args.aad, args.aadEncoding) : undefined,
    tagLength: args.tagLength, outputFormat: OutputFormat.HEX
  })
  return { ciphertext: result.ciphertext.toUpperCase(), tag: result.tag?.toUpperCase() ?? '' }
}

export function decryptSm4Advanced(args: { mode: Sm4AdvancedMode; key: string; iv: string; ciphertext: string; aad: string; aadEncoding: DataEncoding; tag: string; tagLength: number; output: DataEncoding }) {
  const key = cleanHex(args.key, 'SM4 密钥', 16)
  const iv = cleanHex(args.iv, args.mode === 'CCM' ? 'Nonce' : 'IV', args.mode === 'GCM' ? 12 : args.mode === 'CTR' ? 16 : undefined)
  const options = {
    mode: CipherMode[args.mode], padding: PaddingMode.NONE, iv,
    aad: args.aad ? messageBytes(args.aad, args.aadEncoding) : undefined,
    tag: args.mode === 'CTR' ? undefined : cleanHex(args.tag, '认证标签'),
    tagLength: args.tagLength, inputFormat: InputFormat.HEX
  }
  const ciphertext = cleanHex(args.ciphertext, '密文')
  if (args.output === 'hex') return bytesToHex(sm4DecryptBytes(key, ciphertext, options))
  return sm4Decrypt(key, ciphertext, options)
}

export function sm4Gmac(key: string, iv: string, aad: string, aadEncoding: DataEncoding, tagLength = 16) {
  const result = encryptSm4Advanced({ mode: 'GCM', key, iv, data: '', encoding: 'utf8', aad, aadEncoding, tagLength })
  return result.tag
}
