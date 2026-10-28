<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from 'vue'
import { KeyRound, FileKey2, BadgeCheck, Copy, Download, Eye, EyeOff, RefreshCw, TriangleAlert, Keyboard } from '@lucide/vue'
import type { CertificateProfile, GeneratedKeyPair, SubjectInput } from '../core/pki'
import { downloadBytes, generateKeyPair, generateRsaCsr, generateSm2Csr, importRsaKeyPair, importSm2KeyPair, issueCertificate, textToBytes } from '../core/pki'
import { decodeFlexibleInput } from '../core/codec'

type Mode = 'key' | 'csr' | 'cert'

const mode = ref<Mode>('cert')
const algorithm = ref<'SM2' | 'RSA-2048' | 'RSA-3072' | 'P-256' | 'P-384'>('SM2')
const generatedKey = ref<GeneratedKeyPair>()
const artifact = ref<{ type: 'csr' | 'cert'; pem: string; der: Uint8Array }>()
const busy = ref(false)
const revealPrivate = ref(false)
const subject = ref<SubjectInput>({ commonName: 'demo.gm.local', organization: '示例组织', organizationalUnit: '研发部', country: 'CN', email: '' })
const sanText = ref('demo.gm.local\n127.0.0.1')
const days = ref(365)
const certificateType = ref<CertificateProfile['type']>('root')
const serialHex = ref('')
const pathLen = ref(1)
const keyUsages = ref<NonNullable<CertificateProfile['keyUsages']>>(['keyCertSign', 'cRLSign'])
const extendedKeyUsages = ref<string[]>([])
const issuerAlgorithm = ref<'SM2' | 'RSA'>('SM2')
const issuerCertificate = ref('')
const issuerPrivate = ref('')
const issuerX = ref('')
const issuerY = ref('')
const issuerD = ref('')
const sans = computed(() => sanText.value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean))
const keySource = ref<'auto' | 'manual'>('auto')
const privateMaterial = ref('')
const publicMaterial = ref('')
const sm2X = ref('')
const sm2Y = ref('')
const sm2D = ref('')
const materialError = ref('')

const certificateAlgorithms = ['SM2', 'RSA-2048', 'RSA-3072'] as const

async function ensureCertificateKey() {
  materialError.value = ''
  if (keySource.value === 'manual') {
    if (algorithm.value === 'SM2') {
      generatedKey.value = importSm2KeyPair(sm2X.value, sm2Y.value, sm2D.value)
      return
    }
    if (!privateMaterial.value.trim()) throw new Error('请粘贴 RSA PKCS#8 私钥。')
    generatedKey.value = await importRsaKeyPair(privateMaterial.value, publicMaterial.value)
    return
  }
  if (!generatedKey.value || !generatedKey.value.algorithm.startsWith(algorithm.value === 'SM2' ? 'SM2' : 'RSA')) {
    generatedKey.value = await generateKeyPair(algorithm.value)
  }
}

async function generate() {
  busy.value = true
  artifact.value = undefined
  try {
    if (mode.value === 'key') {
      generatedKey.value = await generateKeyPair(algorithm.value)
      return
    }
    await ensureCertificateKey()
    if (mode.value === 'csr') {
      artifact.value = { type: 'csr', ...(algorithm.value === 'SM2'
        ? generateSm2Csr(generatedKey.value!, subject.value, sans.value)
        : await generateRsaCsr(generatedKey.value!, subject.value, sans.value)) }
    } else {
      let issuer
      if (certificateType.value !== 'root') {
        if (!issuerCertificate.value.trim()) throw new Error('签发下级 CA 或终端证书需要 CA 证书。')
        const issuerKey = issuerAlgorithm.value === 'SM2'
          ? importSm2KeyPair(issuerX.value, issuerY.value, issuerD.value)
          : await importRsaKeyPair(issuerPrivate.value)
        issuer = { certificate: decodeFlexibleInput(issuerCertificate.value).bytes, key: issuerKey }
      }
      artifact.value = { type: 'cert', ...(await issueCertificate(generatedKey.value!, subject.value, sans.value, days.value, {
        type: certificateType.value,
        serialHex: serialHex.value,
        pathLen: certificateType.value === 'end-entity' ? undefined : pathLen.value,
        keyUsages: keyUsages.value,
        extendedKeyUsages: extendedKeyUsages.value
      }, issuer)) }
    }
  } catch (cause) {
    materialError.value = cause instanceof Error ? cause.message : '密钥材料无法使用。'
  } finally {
    busy.value = false
  }
}

function downloadText(value: string, filename: string) {
  downloadBytes(textToBytes(value), filename, 'application/x-pem-file')
}

async function copyText(value: string) {
  await navigator.clipboard.writeText(value)
}

onBeforeUnmount(() => {
  if (generatedKey.value?.privateKeyHex) generatedKey.value.privateKeyHex = ''.padStart(generatedKey.value.privateKeyHex.length, '0')
  generatedKey.value = undefined
  artifact.value = undefined
})
</script>

<template>
  <div class="tool-view">
    <header class="page-header compact-header">
      <div><p class="eyebrow">F8–F10 · 本地生成</p><h1>密钥、CSR 与证书签发</h1><p>支持根 CA、下级 CA 和终端证书；私钥不会离开当前页面。</p></div>
    </header>

    <div class="segmented" role="tablist" aria-label="生成类型">
      <button :class="{ active: mode === 'key' }" type="button" @click="mode = 'key'"><KeyRound :size="16" />密钥对</button>
      <button :class="{ active: mode === 'csr' }" type="button" @click="mode = 'csr'"><FileKey2 :size="16" />CSR 签发</button>
      <button :class="{ active: mode === 'cert' }" type="button" @click="mode = 'cert'"><BadgeCheck :size="16" />证书签发</button>
    </div>

    <div class="generator-layout">
      <section class="form-pane">
        <div v-if="mode === 'key'" class="form-section">
          <label>算法<select v-model="algorithm"><option>SM2</option><option>RSA-2048</option><option>RSA-3072</option><option>P-256</option><option>P-384</option></select></label>
          <div class="inline-alert info">SM2 固定使用 sm2p256v1；RSA 与通用 ECC 使用浏览器 WebCrypto。</div>
        </div>
        <div v-else class="form-section two-column-form">
          <label class="span-2">证书算法<select v-model="algorithm"><option v-for="item in certificateAlgorithms" :key="item">{{ item }}</option></select></label>
          <div class="span-2 key-source-control"><span>密钥来源</span><div class="segmented compact-segmented"><button type="button" :class="{ active: keySource === 'auto' }" @click="keySource = 'auto'"><RefreshCw :size="15" />自动生成</button><button type="button" :class="{ active: keySource === 'manual' }" @click="keySource = 'manual'"><Keyboard :size="15" />填写密钥</button></div></div>
          <template v-if="keySource === 'manual'">
            <template v-if="algorithm === 'SM2'">
              <label class="span-2">公钥 X <textarea v-model="sm2X" rows="2" class="mono" placeholder="32 字节 X 坐标（64 位 Hex）" /></label>
              <label class="span-2">公钥 Y <textarea v-model="sm2Y" rows="2" class="mono" placeholder="32 字节 Y 坐标（64 位 Hex）" /></label>
              <label class="span-2">私钥 D <textarea v-model="sm2D" rows="3" class="mono" placeholder="32 字节私钥标量 D（64 位 Hex）" /></label>
              <div class="span-2 inline-alert info"><span>输入 X、Y、D 后会本地推导公钥并校验三者是否属于同一 SM2 密钥对。</span></div>
            </template>
            <template v-else>
              <label class="span-2">RSA 私钥（PKCS#8 PEM）<textarea v-model="privateMaterial" rows="5" class="mono" placeholder="-----BEGIN PRIVATE KEY-----" /></label>
              <label class="span-2">RSA 公钥（PEM，可选）<textarea v-model="publicMaterial" rows="4" class="mono" placeholder="-----BEGIN PUBLIC KEY-----；留空时从私钥提取" /></label>
            </template>
            <div class="span-2 inline-alert warn"><TriangleAlert :size="17" /><span>填写的私钥仅在本次页面内用于签发，不会上传或持久化。请仅使用测试或受控环境中的密钥。</span></div>
          </template>
          <label>通用名称（CN）<input v-model="subject.commonName" /></label>
          <label>国家或地区（C）<input v-model="subject.country" maxlength="2" /></label>
          <label>组织（O）<input v-model="subject.organization" /></label>
          <label>组织单位（OU）<input v-model="subject.organizationalUnit" /></label>
          <label class="span-2">邮箱<input v-model="subject.email" type="email" /></label>
          <label class="span-2">主体备用名称（SAN）<textarea v-model="sanText" rows="4" placeholder="每行一个 DNS、IP、邮箱或 URI" /></label>
          <template v-if="mode === 'cert'">
            <label>有效天数<input v-model.number="days" type="number" min="1" max="3650" /></label>
            <label>证书层级<select v-model="certificateType" @change="certificateType === 'end-entity' ? (keyUsages = ['digitalSignature', 'keyEncipherment']) : (keyUsages = ['keyCertSign', 'cRLSign'])"><option value="root">自签根 CA</option><option value="intermediate">下级 CA</option><option value="end-entity">终端证书</option></select></label>
            <label>序列号（Hex，可留空）<input v-model="serialHex" class="mono" placeholder="自动生成 128 位随机序列号" /></label>
            <label v-if="certificateType !== 'end-entity'">pathLen<input v-model.number="pathLen" type="number" min="0" max="16" /></label>
            <fieldset class="span-2 compact-fieldset"><legend>Key Usage</legend><label v-for="item in [{v:'digitalSignature',l:'数字签名'},{v:'contentCommitment',l:'不可否认'},{v:'keyEncipherment',l:'密钥加密'},{v:'dataEncipherment',l:'数据加密'},{v:'keyAgreement',l:'密钥协商'},{v:'keyCertSign',l:'证书签发'},{v:'cRLSign',l:'CRL 签名'}]" :key="item.v" class="check-label"><input v-model="keyUsages" type="checkbox" :value="item.v" />{{ item.l }}</label></fieldset>
            <fieldset v-if="certificateType === 'end-entity'" class="span-2 compact-fieldset"><legend>Extended Key Usage</legend><label class="check-label"><input v-model="extendedKeyUsages" type="checkbox" value="1.3.6.1.5.5.7.3.1" />TLS 服务端</label><label class="check-label"><input v-model="extendedKeyUsages" type="checkbox" value="1.3.6.1.5.5.7.3.2" />TLS 客户端</label><label class="check-label"><input v-model="extendedKeyUsages" type="checkbox" value="1.3.6.1.5.5.7.3.3" />代码签名</label><label class="check-label"><input v-model="extendedKeyUsages" type="checkbox" value="1.3.6.1.5.5.7.3.4" />邮件保护</label></fieldset>
            <template v-if="certificateType !== 'root'">
              <div class="span-2 issuer-divider"><strong>签发者 CA</strong><span>AKI 将从 CA 公钥自动计算</span></div>
              <label class="span-2">CA 证书<textarea v-model="issuerCertificate" rows="5" class="mono" placeholder="-----BEGIN CERTIFICATE-----" /></label>
              <label>CA 私钥算法<select v-model="issuerAlgorithm"><option value="SM2">SM2</option><option value="RSA">RSA</option></select></label>
              <template v-if="issuerAlgorithm === 'SM2'"><label class="span-2">CA 公钥 X<textarea v-model="issuerX" rows="2" class="mono" /></label><label class="span-2">CA 公钥 Y<textarea v-model="issuerY" rows="2" class="mono" /></label><label class="span-2">CA 私钥 D<textarea v-model="issuerD" rows="2" class="mono" /></label></template>
              <label v-else class="span-2">CA 私钥（PKCS#8 PEM）<textarea v-model="issuerPrivate" rows="5" class="mono" placeholder="-----BEGIN PRIVATE KEY-----" /></label>
              <div class="span-2 inline-alert warn"><TriangleAlert :size="16" /><span>签发者私钥仅在本页内使用。生产 CA 应在 HSM 或隔离签发系统中操作，不应粘贴到网页。</span></div>
            </template>
          </template>
        </div>
        <div v-if="mode === 'cert'" class="inline-alert warn"><TriangleAlert :size="17" /><span>根 CA 与本地签发链不会自动获得公网信任，仅用于开发、测试或受控私有 PKI。</span></div>
        <div v-if="materialError" class="inline-alert fail">{{ materialError }}</div>
        <button class="button primary wide" type="button" :disabled="busy || (mode !== 'key' && !subject.commonName)" @click="generate"><RefreshCw :size="17" :class="{ spinning: busy }" />{{ busy ? '正在生成' : mode === 'key' ? '生成密钥对' : mode === 'csr' ? `生成 ${algorithm} CSR` : `签发 ${algorithm} ${certificateType === 'root' ? '根 CA' : certificateType === 'intermediate' ? '下级 CA' : '终端证书'}` }}</button>
      </section>

      <section class="generator-output">
        <div v-if="generatedKey" class="output-block sensitive-block">
          <div class="output-title"><div><span class="type-badge">{{ generatedKey.algorithm }}</span><strong>私钥</strong></div><div><button class="icon-button compact" type="button" :title="revealPrivate ? '隐藏私钥' : '显示私钥'" @click="revealPrivate = !revealPrivate"><EyeOff v-if="revealPrivate" :size="16" /><Eye v-else :size="16" /></button><button class="icon-button compact" type="button" title="复制私钥" @click="copyText(generatedKey.privatePem)"><Copy :size="16" /></button><button class="icon-button compact" type="button" title="下载私钥" @click="downloadText(generatedKey.privatePem, 'private-key.pem')"><Download :size="16" /></button></div></div>
          <div class="inline-alert warn private-key-warning"><TriangleAlert :size="16" /><span>私钥可通过查看按钮展示。请勿截图、粘贴到聊天工具或提交到代码仓库；离开此页面后会从内存中清理。</span></div>
          <pre :class="{ blurred: !revealPrivate }">{{ generatedKey.privatePem }}</pre>
        </div>
        <div v-if="generatedKey" class="output-block">
          <div class="output-title"><strong>公钥</strong><div><button class="icon-button compact" type="button" title="复制公钥" @click="copyText(generatedKey.publicPem)"><Copy :size="16" /></button><button class="icon-button compact" type="button" title="下载公钥" @click="downloadText(generatedKey.publicPem, 'public-key.pem')"><Download :size="16" /></button></div></div>
          <pre>{{ generatedKey.publicPem }}</pre>
        </div>
        <div v-if="artifact" class="output-block artifact-block">
          <div class="output-title"><div><span class="type-badge accent">{{ artifact.type === 'csr' ? 'PKCS#10' : 'X.509 v3' }}</span><strong>{{ artifact.type === 'csr' ? '证书请求（CSR）' : certificateType === 'root' ? '自签根 CA 证书' : certificateType === 'intermediate' ? '下级 CA 证书' : '终端证书' }}</strong></div><div><button class="icon-button compact" type="button" title="复制" @click="copyText(artifact.pem)"><Copy :size="16" /></button><button class="icon-button compact" type="button" title="下载" @click="downloadText(artifact.pem, artifact.type === 'csr' ? 'request.csr.pem' : 'certificate.pem')"><Download :size="16" /></button></div></div>
          <pre>{{ artifact.pem }}</pre>
        </div>
        <div v-if="!generatedKey && !artifact" class="empty-state neutral tall"><KeyRound :size="27" /><strong>结果保留在当前页面</strong><p>离开页面后，私钥缓冲区会被清理。</p></div>
      </section>
    </div>
  </div>
</template>
