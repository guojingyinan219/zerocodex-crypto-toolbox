<script setup lang="ts">
import { ref } from 'vue'
import { GitBranch, RefreshCw } from '@lucide/vue'
import ResultPanel from '../components/ResultPanel.vue'
import type { ParseReport } from '../types'
import { validateCertificateChain } from '../core/chain-validation'

const chain = ref('')
const roots = ref('')
const crls = ref('')
const ocsps = ref('')
const hostname = ref('')
const purpose = ref<'any' | 'serverAuth' | 'clientAuth' | 'codeSigning' | 'emailProtection'>('serverAuth')
const checkDate = ref(new Date().toISOString().slice(0, 16))
const report = ref<ParseReport>()
const error = ref('')
const busy = ref(false)

async function verify() {
  busy.value = true; error.value = ''; report.value = undefined
  try { report.value = await validateCertificateChain({ chain: chain.value, roots: roots.value, crls: crls.value, ocsps: ocsps.value, hostname: hostname.value, purpose: purpose.value, checkDate: new Date(checkDate.value) }) }
  catch (cause) { error.value = cause instanceof Error ? cause.message : '证书链验证失败。' }
  finally { busy.value = false }
}
</script>

<template>
  <div class="generator-layout chain-layout">
    <section class="form-pane">
      <div class="form-section">
        <label>终端证书与中间证书链<textarea v-model="chain" rows="7" class="mono" placeholder="先粘贴终端证书，再粘贴中间 CA 证书" /></label>
        <label>自定义信任根<textarea v-model="roots" rows="5" class="mono" placeholder="-----BEGIN CERTIFICATE-----" /></label>
        <label>本地 CRL（可选）<textarea v-model="crls" rows="3" class="mono" placeholder="-----BEGIN X509 CRL-----" /></label>
        <label>OCSP 响应（可选）<textarea v-model="ocsps" rows="3" class="mono" placeholder="粘贴 DER 的 Base64 或 PEM" /></label>
        <div class="two-column-form"><label>验证用途<select v-model="purpose"><option value="any">任意用途</option><option value="serverAuth">TLS 服务端</option><option value="clientAuth">TLS 客户端</option><option value="codeSigning">代码签名</option><option value="emailProtection">邮件保护</option></select></label><label>验证时间<input v-model="checkDate" type="datetime-local" /></label></div>
        <label>目标域名（可选）<input v-model="hostname" placeholder="www.example.com" /></label>
        <button class="button primary wide" type="button" :disabled="busy || !chain || !roots" @click="verify"><RefreshCw :size="16" :class="{ spinning: busy }" />{{ busy ? '正在验证' : '验证证书链' }}</button>
        <div class="inline-alert info">AIA、OCSP 网络请求默认关闭，避免访问证书中不可信 URL 引发隐私泄露或 SSRF。可粘贴 CRL 离线验证。</div>
      </div>
    </section>
    <section class="generator-output">
      <div v-if="error" class="error-state"><strong>验证未完成</strong><p>{{ error }}</p></div>
      <ResultPanel v-else-if="report" :report="report" />
      <div v-else class="empty-state neutral tall"><GitBranch :size="28" /><strong>等待证书链</strong><p>使用指定信任根、用途、域名与时间执行 RFC 5280 路径验证。</p></div>
    </section>
  </div>
</template>
