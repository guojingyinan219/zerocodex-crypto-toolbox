import {
  sm2GenerateKeyPair,
  sm2GetPublicKeyFromPrivateKey,
  sm2KeyExchange,
  sm3Digest
} from 'gmkitx'

export type DataEncoding = 'text' | 'hex'

export interface Sm2PartyMaterial {
  privateKey: string
  publicX: string
  publicY: string
  tempPrivateKey: string
  tempPublicX: string
  tempPublicY: string
}

export interface Sm2AgreementInput {
  privateKey: string
  tempPrivateKey: string
  peerPublicX: string
  peerPublicY: string
  peerTempPublicX: string
  peerTempPublicY: string
  userId: string
  peerUserId: string
  isInitiator: boolean
  keyLength: number
}

export interface Sm2AgreementOutput {
  sharedKey: string
  s1: string
  s2: string
  selfPublicX: string
  selfPublicY: string
  selfTempPublicX: string
  selfTempPublicY: string
}

const SM2_A = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC'
const SM2_B = '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93'
const SM2_GX = '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7'
const SM2_GY = 'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0'

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0))
  let offset = 0
  for (const part of parts) {
    output.set(part, offset)
    offset += part.length
  }
  return output
}

function strictHex(value: string, field: string, allowEmpty = false): string {
  const compact = value.replace(/[\s:,-]/g, '').replace(/^0x/i, '').toUpperCase()
  if (!compact && allowEmpty) return ''
  if (!compact) throw new Error(`${field}不能为空。`)
  if (compact.length % 2 !== 0 || /[^0-9A-F]/.test(compact)) throw new Error(`${field}必须是偶数长度的 Hex。`)
  return compact
}

function component(value: string, field: string): string {
  const normalized = strictHex(value, field)
  if (normalized.length !== 64) throw new Error(`${field}必须是 32 字节（64 位 Hex）。`)
  return normalized
}

function hexBytes(value: string): Uint8Array {
  if (!value) return new Uint8Array()
  return Uint8Array.from(value.match(/.{2}/g)!, (pair) => Number.parseInt(pair, 16))
}

function bytes(value: string, encoding: DataEncoding, field: string): Uint8Array {
  return encoding === 'hex'
    ? hexBytes(strictHex(value, field, true))
    : new TextEncoder().encode(value)
}

function splitPublicKey(publicKey: string): { x: string; y: string } {
  const normalized = publicKey.replace(/[\s:,-]/g, '').toUpperCase()
  if (!/^04[0-9A-F]{128}$/.test(normalized)) throw new Error('SM2 公钥必须是 04 || X || Y 格式。')
  return { x: normalized.slice(2, 66), y: normalized.slice(66) }
}

function publicKey(x: string, y: string, prefix: string): string {
  return `04${component(x, `${prefix}公钥 X`)}${component(y, `${prefix}公钥 Y`)}`
}

function privateKey(value: string, field: string): string {
  return component(value, field)
}

export function digestSm3(value: string, encoding: DataEncoding): string {
  return sm3Digest(bytes(value, encoding, '数据')).toUpperCase()
}

export function sm2SignaturePrehash(input: {
  publicX: string
  publicY: string
  userId: string
  userIdEncoding: DataEncoding
  data: string
  dataEncoding: DataEncoding
}): { za: string; digest: string } {
  const x = component(input.publicX, '公钥 X')
  const y = component(input.publicY, '公钥 Y')
  const userId = bytes(input.userId, input.userIdEncoding, '用户 ID')
  if (userId.length * 8 > 0xffff) throw new Error('用户 ID 过长，ENTL 无法使用 16 位表示。')
  const entl = Uint8Array.of((userId.length * 8) >>> 8, (userId.length * 8) & 0xff)
  const za = sm3Digest(concatBytes(
    entl,
    userId,
    hexBytes(SM2_A),
    hexBytes(SM2_B),
    hexBytes(SM2_GX),
    hexBytes(SM2_GY),
    hexBytes(x),
    hexBytes(y)
  )).toUpperCase()
  const digest = sm3Digest(concatBytes(hexBytes(za), bytes(input.data, input.dataEncoding, '数据'))).toUpperCase()
  return { za, digest }
}

export function generateSm2PartyMaterial(): Sm2PartyMaterial {
  const permanent = sm2GenerateKeyPair(false)
  const temporary = sm2GenerateKeyPair(false)
  const publicParts = splitPublicKey(permanent.publicKey)
  const tempParts = splitPublicKey(temporary.publicKey)
  return {
    privateKey: permanent.privateKey.toUpperCase(),
    publicX: publicParts.x,
    publicY: publicParts.y,
    tempPrivateKey: temporary.privateKey.toUpperCase(),
    tempPublicX: tempParts.x,
    tempPublicY: tempParts.y
  }
}

export function deriveSm2PublicComponents(rawPrivateKey: string): { x: string; y: string } {
  return splitPublicKey(sm2GetPublicKeyFromPrivateKey(privateKey(rawPrivateKey, '私钥 D')))
}

export function runSm2KeyAgreement(input: Sm2AgreementInput): Sm2AgreementOutput {
  if (!Number.isSafeInteger(input.keyLength) || input.keyLength < 1 || input.keyLength > 1024) {
    throw new Error('派生密钥长度必须是 1 到 1024 之间的整数（字节）。')
  }
  const ownPrivate = privateKey(input.privateKey, '己方长期私钥 D')
  const ownTempPrivate = privateKey(input.tempPrivateKey, '己方临时私钥 r')
  const ownPublic = sm2GetPublicKeyFromPrivateKey(ownPrivate).toUpperCase()
  const ownTempPublic = sm2GetPublicKeyFromPrivateKey(ownTempPrivate).toUpperCase()
  const result = sm2KeyExchange({
    privateKey: ownPrivate,
    publicKey: ownPublic,
    tempPrivateKey: ownTempPrivate,
    peerPublicKey: publicKey(input.peerPublicX, input.peerPublicY, '对方长期'),
    peerTempPublicKey: publicKey(input.peerTempPublicX, input.peerTempPublicY, '对方临时'),
    userId: input.userId,
    peerUserId: input.peerUserId,
    isInitiator: input.isInitiator,
    keyLength: input.keyLength
  })
  const own = splitPublicKey(ownPublic)
  const ownTemp = splitPublicKey(ownTempPublic)
  return {
    sharedKey: result.sharedKey.toUpperCase(),
    s1: (result.s1 ?? '').toUpperCase(),
    s2: (result.s2 ?? '').toUpperCase(),
    selfPublicX: own.x,
    selfPublicY: own.y,
    selfTempPublicX: ownTemp.x,
    selfTempPublicY: ownTemp.y
  }
}
