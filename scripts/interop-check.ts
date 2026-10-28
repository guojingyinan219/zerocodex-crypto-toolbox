import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { generateKeyPair, generateSm2Certificate, generateSm2Csr } from '../src/core/pki'

const directory = mkdtempSync(join(tmpdir(), 'crypto-toolbox-interop-'))
const key = await generateKeyPair('SM2')
const subject = { commonName: 'interop.gm.local', organization: 'GM Toolbox', country: 'CN' }
const csr = generateSm2Csr(key, subject, ['interop.gm.local', '127.0.0.1'])
const certificate = await generateSm2Certificate(key, subject, ['interop.gm.local', '127.0.0.1'], 30, false)

const files = {
  key: join(directory, 'private-key.pem'),
  csr: join(directory, 'request.pem'),
  cert: join(directory, 'certificate.pem')
}
writeFileSync(files.key, key.privatePem)
writeFileSync(files.csr, csr.pem)
writeFileSync(files.cert, certificate.pem)

const checks: Array<[string, string[]]> = [
  ['private key', ['pkey', '-in', files.key, '-check', '-noout']],
  ['CSR parse and verify', ['req', '-in', files.csr, '-verify', '-noout']],
  ['certificate parse', ['x509', '-in', files.cert, '-noout', '-subject', '-issuer', '-dates']],
  ['self-signed certificate verify', ['verify', '-CAfile', files.cert, files.cert]]
]

for (const [name, args] of checks) {
  const result = spawnSync('openssl', args, { encoding: 'utf8' })
  if (result.status !== 0) {
    throw new Error(`${name} failed:\n${result.stdout}\n${result.stderr}`)
  }
  console.log(`[pass] ${name}: ${(result.stdout || result.stderr).trim()}`)
}
console.log(`[artifacts] ${directory}`)
