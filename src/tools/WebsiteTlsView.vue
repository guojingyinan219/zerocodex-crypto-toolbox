<script setup lang="ts">
import { computed, ref } from 'vue'
import {
  Activity, AlertTriangle, CheckCircle2, FileStack, Globe2, KeyRound,
  Network, Play, ShieldAlert, ShieldCheck, XCircle
} from '@lucide/vue'

type Check = { level: 'pass' | 'warn' | 'fail'; title: string; detail: string }
type Certificate = {
  subject: string
  issuer: string
  notBefore: string
  notAfter: string
  serialNumber: string
  dnsNames: string[]
  publicKeyAlgorithm: string
  publicKeySize: number
  signatureAlgorithm: string
  fingerprintSha256: string
}
type ProtocolProbe = { name: string; supported: boolean; cipherSuite: string; alpn: string; message: string }
type CertificateVariant = {
  supported: boolean
  publicKeyAlgorithm: string
  subject: string
  fingerprintSha256: string
  cipherSuite: string
}
type Report = {
  host: string
  address: string
  protocol: string
  cipherSuite: string
  certificate: Certificate
  chain: Certificate[]
  validation: { trusted: boolean; message: string }
  ocspStapled: boolean
  algorithmFamily: 'standard' | 'gm' | 'dual' | 'unknown'
  checks: Check[]
  riskChecks: Check[]
  protocols: ProtocolProbe[]
  dns: { addresses: string[]; caa: string[]; message: string }
  web: { reachable: boolean; statusCode: number; httpVersion: string; alpn: string; hsts: string; message: string }
  dualCertificate: { rsa: CertificateVariant; ecc: CertificateVariant; dual: boolean; message: string }
  gmProbe: {
    available: boolean
    attempted: boolean
    supported: boolean
    protocol: string
    cipherSuite: string
    certificateCount: number
    dualCertificate: boolean
    message: string
  }
}
type TabId = 'overview' | 'chain' | 'protocols' | 'web' | 'gm' | 'risks'

const tabs: { id: TabId; label: string; icon: typeof ShieldCheck }[] = [
  { id: 'overview', label: '检测总览', icon: Activity },
  { id: 'chain', label: '证书链', icon: FileStack },
  { id: 'protocols', label: '协议套件', icon: KeyRound },
  { id: 'web', label: 'Web 安全策略', icon: Globe2 },
  { id: 'gm', label: '国密 TLCP', icon: ShieldCheck },
  { id: 'risks', label: '风险检查', icon: ShieldAlert }
]

const host = ref('')
const loading = ref(false)
const error = ref('')
const report = ref<Report | null>(null)
const activeTab = ref<TabId>('overview')
const statusIcon = { pass: CheckCircle2, warn: AlertTriangle, fail: XCircle }
const familyLabel = computed(() => {
  if (report.value?.algorithmFamily === 'dual') return '通用 TLS + 国密 TLCP'
  if (report.value?.algorithmFamily === 'gm') return '国密算法'
  if (report.value?.algorithmFamily === 'standard') return '通用 TLS'
  return '待识别'
})
const issueCount = computed(() => report.value?.riskChecks.filter(item => item.level !== 'pass').length ?? 0)

async function inspect() {
  if (!host.value.trim() || loading.value) return
  loading.value = true
  error.value = ''
  report.value = null
  activeTab.value = 'overview'
  try {
    const response = await fetch('/api/tls-check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host: host.value.trim() })
    })
    const payload = await response.json() as Report | { error?: string }
    if (!response.ok || !('certificate' in payload)) {
      throw new Error('error' in payload && payload.error ? payload.error : '检测服务暂时不可用。')
    }
    report.value = payload
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : '检测失败，请稍后重试。'
  } finally {
    loading.value = false
  }
}

function display(value: string | number | undefined, fallback = '未检测到') {
  return value === undefined || value === '' ? fallback : String(value)
}
</script>

<template>
  <section class="tls-tool-shell">
    <div class="tls-command-bar">
      <div class="tool-context">
        <Globe2 :size="21" />
        <div><strong>网站安全检测</strong><span>证书、协议、Web 策略与国密能力的一站式检查</span></div>
      </div>
      <label class="tls-host-field">
        <span class="visually-hidden">网站域名</span>
        <input v-model="host" type="text" inputmode="url" autocomplete="url" placeholder="例如 example.com" @keydown.enter.prevent="inspect" />
      </label>
      <button class="button primary" type="button" :disabled="loading || !host.trim()" @click="inspect">
        <Play v-if="!loading" :size="16" /><span v-else class="spinner small-spinner" />{{ loading ? '检测中' : '开始检测' }}
      </button>
    </div>

    <div v-if="error" class="inline-alert fail tls-alert"><ShieldAlert :size="18" /><span>{{ error }}</span></div>

    <div v-else-if="report" class="tls-report">
      <section class="tls-summary" :class="report.validation.trusted ? 'trusted' : 'untrusted'">
        <div class="tls-summary-status">
          <component :is="report.validation.trusted ? ShieldCheck : ShieldAlert" :size="25" />
          <div><p class="eyebrow">{{ familyLabel }}</p><h2>{{ report.validation.trusted ? '证书验证通过' : '证书存在风险' }}</h2><p>{{ report.validation.message }}</p></div>
        </div>
        <div class="tls-summary-metrics">
          <div><span>协议</span><strong>{{ report.protocol }}</strong></div>
          <div><span>证书链</span><strong>{{ report.chain.length }} 张</strong></div>
          <div><span>待关注</span><strong :class="issueCount ? 'attention' : ''">{{ issueCount }} 项</strong></div>
          <div><span>国密 TLCP</span><strong>{{ report.gmProbe.supported ? '支持' : '未确认' }}</strong></div>
        </div>
      </section>

      <nav class="tls-tabs" aria-label="网站安全检测结果">
        <button v-for="tab in tabs" :key="tab.id" type="button" :class="{ active: activeTab === tab.id }" @click="activeTab = tab.id">
          <component :is="tab.icon" :size="16" /><span>{{ tab.label }}</span>
        </button>
      </nav>

      <section v-if="activeTab === 'overview'" class="tls-tab-panel">
        <div class="tls-info-grid">
          <article class="tls-detail-card">
            <h3>连接概况</h3>
            <dl>
              <div><dt>检测域名</dt><dd>{{ report.host }}</dd></div>
              <div><dt>连接地址</dt><dd class="mono">{{ report.address }}:443</dd></div>
              <div><dt>密码套件</dt><dd class="mono">{{ report.cipherSuite }}</dd></div>
              <div><dt>HTTP 协议</dt><dd>{{ display(report.web.httpVersion) }}</dd></div>
            </dl>
          </article>
          <article class="tls-detail-card">
            <h3>服务器证书</h3>
            <dl>
              <div><dt>主体</dt><dd>{{ report.certificate.subject }}</dd></div>
              <div><dt>签发者</dt><dd>{{ report.certificate.issuer }}</dd></div>
              <div><dt>有效期至</dt><dd>{{ report.certificate.notAfter }}</dd></div>
              <div><dt>公钥</dt><dd>{{ report.certificate.publicKeyAlgorithm }} {{ report.certificate.publicKeySize || '' }} bit</dd></div>
            </dl>
          </article>
        </div>
        <div class="tls-check-grid">
          <article v-for="check in report.checks" :key="check.title" :class="`tls-check ${check.level}`">
            <component :is="statusIcon[check.level]" :size="18" /><div><strong>{{ check.title }}</strong><p>{{ check.detail }}</p></div>
          </article>
        </div>
      </section>

      <section v-else-if="activeTab === 'chain'" class="tls-tab-panel">
        <div class="tls-chain-list">
          <article v-for="(cert, index) in report.chain" :key="cert.fingerprintSha256" class="tls-detail-card tls-certificate-card">
            <header><span>{{ index === 0 ? '服务器证书' : index === report.chain.length - 1 ? '链顶证书' : `中间证书 ${index}` }}</span><strong>{{ cert.publicKeyAlgorithm }} {{ cert.publicKeySize || '' }} bit</strong></header>
            <dl>
              <div><dt>主体</dt><dd>{{ cert.subject }}</dd></div>
              <div><dt>签发者</dt><dd>{{ cert.issuer }}</dd></div>
              <div><dt>有效期</dt><dd>{{ cert.notBefore }} 至 {{ cert.notAfter }}</dd></div>
              <div><dt>签名算法</dt><dd>{{ cert.signatureAlgorithm }}</dd></div>
              <div><dt>序列号</dt><dd class="mono">{{ cert.serialNumber }}</dd></div>
              <div><dt>SHA-256 指纹</dt><dd class="mono">{{ cert.fingerprintSha256 }}</dd></div>
              <div v-if="cert.dnsNames.length"><dt>证书域名</dt><dd>{{ cert.dnsNames.join('、') }}</dd></div>
            </dl>
          </article>
        </div>
      </section>

      <section v-else-if="activeTab === 'protocols'" class="tls-tab-panel">
        <div class="tls-protocol-grid">
          <article v-for="item in report.protocols" :key="item.name" :class="['tls-protocol-card', { supported: item.supported }]">
            <div><component :is="item.supported ? CheckCircle2 : XCircle" :size="18" /><strong>{{ item.name }}</strong></div>
            <span>{{ item.supported ? '支持' : '不支持' }}</span>
            <p class="mono">{{ display(item.cipherSuite, item.message) }}</p>
            <small>ALPN：{{ display(item.alpn) }}</small>
          </article>
        </div>
        <article class="tls-detail-card tls-dual-card">
          <header><h3>RSA / ECC 双证书</h3><span>{{ report.dualCertificate.message }}</span></header>
          <div class="tls-variant-grid">
            <div v-for="item in [{ label: 'RSA', value: report.dualCertificate.rsa }, { label: 'ECC', value: report.dualCertificate.ecc }]" :key="item.label">
              <strong>{{ item.label }} <small>{{ item.value.supported ? '已检测到' : '未检测到' }}</small></strong>
              <p>{{ display(item.value.subject) }}</p>
              <span class="mono">{{ display(item.value.cipherSuite) }}</span>
            </div>
          </div>
        </article>
      </section>

      <section v-else-if="activeTab === 'web'" class="tls-tab-panel">
        <div class="tls-info-grid">
          <article class="tls-detail-card">
            <h3>HTTPS 与安全响应头</h3>
            <dl>
              <div><dt>访问状态</dt><dd>{{ report.web.reachable ? `HTTP ${report.web.statusCode}` : '访问失败' }}</dd></div>
              <div><dt>HTTP 版本</dt><dd>{{ display(report.web.httpVersion) }}</dd></div>
              <div><dt>ALPN</dt><dd>{{ display(report.web.alpn) }}</dd></div>
              <div><dt>HTTP/2</dt><dd>{{ report.web.httpVersion === 'HTTP/2.0' ? '已启用' : '未检测到' }}</dd></div>
              <div><dt>HSTS</dt><dd class="mono">{{ display(report.web.hsts, '未配置') }}</dd></div>
            </dl>
          </article>
          <article class="tls-detail-card">
            <h3>DNS 与证书颁发限制</h3>
            <dl>
              <div><dt>解析地址</dt><dd class="mono">{{ report.dns.addresses.join('、') }}</dd></div>
              <div><dt>CAA 状态</dt><dd>{{ report.dns.message }}</dd></div>
              <div><dt>CAA 记录</dt><dd class="mono">{{ report.dns.caa.join('；') || '未配置' }}</dd></div>
              <div><dt>OCSP 装订</dt><dd>{{ report.ocspStapled ? '已提供' : '未提供' }}</dd></div>
            </dl>
          </article>
        </div>
      </section>

      <section v-else-if="activeTab === 'gm'" class="tls-tab-panel">
        <article class="tls-detail-card tls-gm-card">
          <div class="tls-gm-heading"><ShieldCheck :size="25" /><div><p class="eyebrow">TLCP / 国密双证书</p><h3>{{ report.gmProbe.supported ? '已检测到国密服务能力' : '尚未确认国密服务能力' }}</h3><p>{{ report.gmProbe.message }}</p></div></div>
          <dl>
            <div><dt>专用探针</dt><dd>{{ report.gmProbe.available ? '已安装' : '服务端未配置' }}</dd></div>
            <div><dt>执行状态</dt><dd>{{ report.gmProbe.attempted ? '已执行' : '未执行' }}</dd></div>
            <div><dt>协议</dt><dd>{{ display(report.gmProbe.protocol) }}</dd></div>
            <div><dt>密码套件</dt><dd class="mono">{{ display(report.gmProbe.cipherSuite) }}</dd></div>
            <div><dt>证书数量</dt><dd>{{ report.gmProbe.certificateCount || 0 }} 张</dd></div>
            <div><dt>国密双证书</dt><dd>{{ report.gmProbe.dualCertificate ? '签名证书 + 加密证书' : '未确认' }}</dd></div>
          </dl>
        </article>
        <div class="inline-alert info tls-scope-note"><AlertTriangle :size="17" /><span>国密结果来自服务端 GmSSL/Tongsuo 专用握手探针。探针未安装或未成功协商时只标记“未确认”，不等同于网站不支持国密。</span></div>
      </section>

      <section v-else class="tls-tab-panel">
        <div class="tls-check-grid risk-grid">
          <article v-for="check in report.riskChecks" :key="check.title" :class="`tls-check ${check.level}`">
            <component :is="statusIcon[check.level]" :size="18" /><div><strong>{{ check.title }}</strong><p>{{ check.detail }}</p></div>
          </article>
        </div>
        <div class="inline-alert warn tls-scope-note"><ShieldAlert :size="17" /><span><strong>非侵入式检测：</strong>结果来自握手、证书、DNS 与响应头分析，没有向目标发送漏洞利用载荷；未主动验证的漏洞不会显示为“安全”。</span></div>
      </section>
    </div>

    <div v-else class="empty-state tall tls-empty">
      <div class="empty-mark"><Network :size="25" /></div>
      <strong>输入网站域名开始安全检测</strong>
      <p>检查证书链、TLS 版本、密码套件、HSTS、HTTP/2、CAA、RSA/ECC 双证书与国密 TLCP 能力。</p>
      <small>仅接受公开域名并固定连接 443 端口，不跟随跳转，不保存检测记录。</small>
    </div>
  </section>
</template>
