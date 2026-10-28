<script setup lang="ts">
import { computed, ref } from 'vue'
import { CheckCircle2, AlertTriangle, XCircle, KeyRound, FileKey2, BadgeCheck } from '@lucide/vue'
import { compareReports, parseMaterial } from '../core/pki'
import type { Finding, ParseReport, Status } from '../types'

const certificate = ref('')
const csr = ref('')
const privateKey = ref('')
const reports = ref<{ cert?: ParseReport; csr?: ParseReport; key?: ParseReport }>({})
const comparisons = ref<Array<{ title: string; findings: Finding[] }>>([])
const error = ref('')
const busy = ref(false)
const icons: Record<Status, typeof CheckCircle2> = { pass: CheckCircle2, warn: AlertTriangle, fail: XCircle, info: AlertTriangle }
const canVerify = computed(() => [certificate.value, csr.value, privateKey.value].filter((value) => value.trim()).length >= 2)

async function verify() {
  busy.value = true
  error.value = ''
  comparisons.value = []
  try {
    const parsed: typeof reports.value = {}
    if (certificate.value.trim()) parsed.cert = await parseMaterial(certificate.value)
    if (csr.value.trim()) parsed.csr = await parseMaterial(csr.value)
    if (privateKey.value.trim()) parsed.key = await parseMaterial(privateKey.value)
    reports.value = parsed
    if (parsed.cert && parsed.key) comparisons.value.push({ title: '证书 ↔ 私钥', findings: compareReports(parsed.cert, parsed.key) })
    if (parsed.csr && parsed.key) comparisons.value.push({ title: 'CSR ↔ 私钥', findings: compareReports(parsed.csr, parsed.key) })
    if (parsed.csr && parsed.cert) comparisons.value.push({ title: 'CSR ↔ 证书', findings: compareReports(parsed.csr, parsed.cert) })
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : '校验失败'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="tool-view">
    <header class="page-header compact-header">
      <div><p class="eyebrow">F7 · 三件套匹配校验</p><h1>一次核对证书、CSR 与私钥</h1><p>比对实际公钥值；算法不一致时给出独立错误。</p></div>
    </header>
    <section class="material-grid">
      <label class="material-input"><span><BadgeCheck :size="17" />证书</span><textarea v-model="certificate" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----" /></label>
      <label class="material-input"><span><FileKey2 :size="17" />证书请求（CSR）</span><textarea v-model="csr" spellcheck="false" placeholder="-----BEGIN CERTIFICATE REQUEST-----" /></label>
      <label class="material-input sensitive-input"><span><KeyRound :size="17" />私钥 · 默认不持久化</span><textarea v-model="privateKey" spellcheck="false" placeholder="-----BEGIN PRIVATE KEY-----" /></label>
    </section>
    <div class="command-bar"><button class="button primary" type="button" :disabled="!canVerify || busy" @click="verify"><span v-if="busy" class="spinner small-spinner" />{{ busy ? '正在校验' : '开始校验' }}</button><span>至少提供任意两份材料</span></div>
    <div v-if="error" class="inline-alert fail">{{ error }}</div>
    <section v-if="comparisons.length" class="comparison-results">
      <article v-for="comparison in comparisons" :key="comparison.title" class="comparison-row" :class="`status-${comparison.findings[0].status}`">
        <component :is="icons[comparison.findings[0].status]" :size="22" />
        <div><p class="eyebrow">{{ comparison.title }}</p><h2>{{ comparison.findings[0].title }}</h2><p>{{ comparison.findings[0].detail }}</p><p v-if="comparison.findings[0].fix" class="fix">建议：{{ comparison.findings[0].fix }}</p></div>
      </article>
    </section>
    <div v-else class="empty-state neutral short"><KeyRound :size="25" /><strong>等待比对</strong><p>校验只在当前页面内存中完成。</p></div>
  </div>
</template>
