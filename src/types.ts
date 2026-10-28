export type MaterialKind =
  | 'certificate'
  | 'csr'
  | 'private-key'
  | 'encrypted-private-key'
  | 'public-key'
  | 'pkcs7'
  | 'pkcs12'
  | 'jks'
  | 'hex'
  | 'base64'
  | 'binary'
  | 'unknown'

export type Status = 'pass' | 'warn' | 'fail' | 'info'

export interface Finding {
  id: string
  status: Status
  title: string
  detail: string
  fix?: string
}

export interface FieldItem {
  label: string
  value: string
  mono?: boolean
  sensitive?: boolean
}

export interface FieldGroup {
  title: string
  items: FieldItem[]
}

export interface ParseReport {
  kind: MaterialKind
  label: string
  algorithm: string
  summary: string
  status: Status
  findings: Finding[]
  groups: FieldGroup[]
  bytes: Uint8Array
  pemLabel?: string
  publicKeyHex?: string
}

export interface Asn1TreeNode {
  id: string
  type: string
  offset: number
  length: number
  value?: string
  children: Asn1TreeNode[]
}

export interface OidRecord {
  oid: string
  name: string
  english: string
  category: string
  standard: string
  description: string
}
