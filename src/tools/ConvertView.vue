<script setup lang="ts">
import { computed, ref } from 'vue'
import { ArrowRightLeft, Copy, Download, Eye, EyeOff, KeyRound, Trash2, TriangleAlert } from '@lucide/vue'
import { decodeFlexibleInput } from '../core/codec'
import type { Sm2KeyFormats } from '../core/pki'
import { downloadBytes, encodeOutput, formatSm2KeyComponents, textToBytes } from '../core/pki'

type ConvertMode = 'general' | 'sm2'

const mode = ref<ConvertMode>('general')
const input = ref('')
const outputMode = ref<'PEM' | 'Base64' | 'Hex'>('PEM')
const pemLabel = ref('DATA')
const lineWidth = ref(64)
const output = ref('')
const bytes = ref<Uint8Array<ArrayBufferLike>>(new Uint8Array())
const error = ref('')
const detected = ref('')
const sm2X = ref('')
const sm2Y = ref('')
const sm2D = ref('')
const sm2Result = ref<Sm2KeyFormats>()
const revealD = ref(false)
const revealPrivatePem = ref(false)
const canConvert = computed(() => Boolean(input.value.trim()))
const canConvertSm2 = computed(() => Boolean(sm2X.value.trim() && sm2Y.value.trim()))

function wrap(value: string) {
  if (outputMode.value === 'Hex' || lineWidth.value === 0) return value
  if (outputMode.value === 'PEM') return value
  return value.match(new RegExp(`.{1,${lineWidth.value}}`, 'g'))?.join('\n') ?? value
}

function convert() {
  error.value = ''
  try {
    const decoded = decodeFlexibleInput(input.value)
    bytes.value = decoded.bytes
    detected.value = decoded.kind
    output.value = wrap(encodeOutput(decoded.bytes, outputMode.value, pemLabel.value || 'DATA'))
  } catch (cause) {
    output.value = ''
    error.value = cause instanceof Error ? cause.message : '转换失败'
  }
}

function convertSm2() {
  error.value = ''
  revealPrivatePem.value = false
  try {
    sm2Result.value = formatSm2KeyComponents(sm2X.value, sm2Y.value, sm2D.value)
  } catch (cause) {
    sm2Result.value = undefined
    error.value = cause instanceof Error ? cause.message : 'SM2 密钥转换失败'
  }
}

function download() {
  if (outputMode.value === 'PEM') downloadBytes(textToBytes(output.value), 'converted.pem', 'application/x-pem-file')
  else if (outputMode.value === 'Base64') downloadBytes(textToBytes(output.value), 'converted.b64', 'text/plain')
  else downloadBytes(textToBytes(output.value), 'converted.hex', 'text/plain')
}

function downloadPem(value: string, filename: string) {
  downloadBytes(textToBytes(value), filename, 'application/x-pem-file')
}

async function copy(value: string) {
  await navigator.clipboard.writeText(value)
}
</script>

<template>
  <div class="tool-view">
    <header class="page-header compact-header"><div><p class="eyebrow">F11 · 编码转换</p><h1>编码与密钥格式转换</h1><p>处理 PEM、DER、Base64、Hex，以及 SM2 X/Y/D 密钥分量。</p></div></header>

    <div class="segmented" role="tablist" aria-label="转换类型">
      <button type="button" :class="{ active: mode === 'general' }" @click="mode = 'general'"><ArrowRightLeft :size="16" />通用编码</button>
      <button type="button" :class="{ active: mode === 'sm2' }" @click="mode = 'sm2'"><KeyRound :size="16" />SM2 密钥</button>
    </div>

    <template v-if="mode === 'general'">
      <div class="convert-toolbar">
        <div class="segmented compact-segmented"><button v-for="item in ['PEM', 'Base64', 'Hex'] as const" :key="item" :class="{ active: outputMode === item }" type="button" @click="outputMode = item">{{ item }}</button></div>
        <label v-if="outputMode === 'PEM'">PEM 标签<input v-model="pemLabel" /></label>
        <label v-if="outputMode !== 'Hex'">行宽<select v-model.number="lineWidth"><option :value="64">64</option><option :value="76">76</option><option :value="0">不换行</option></select></label>
        <button class="button primary" type="button" :disabled="!canConvert" @click="convert"><ArrowRightLeft :size="16" />转换</button>
      </div>
      <div class="convert-workspace">
        <section>
          <div class="pane-toolbar"><strong>输入</strong><button class="icon-button" type="button" title="清空" @click="input = ''; output = ''"><Trash2 :size="17" /></button></div>
          <textarea v-model="input" spellcheck="false" placeholder="粘贴 PEM、Base64 或 Hex" />
        </section>
        <section>
          <div class="pane-toolbar"><div><strong>输出</strong><span v-if="detected" class="subtle-label">识别：{{ detected }} · {{ bytes.length }} B</span></div><div><button class="icon-button" type="button" title="复制" :disabled="!output" @click="copy(output)"><Copy :size="17" /></button><button class="icon-button" type="button" title="下载" :disabled="!output" @click="download"><Download :size="17" /></button></div></div>
          <textarea :value="output" readonly spellcheck="false" placeholder="转换结果" />
        </section>
      </div>
    </template>

    <div v-else class="generator-layout sm2-converter">
      <section class="form-pane">
        <div class="form-section">
          <div class="sm2-convert-heading"><p class="eyebrow">SM2 密钥分量</p><h2>X、Y、D 转标准 PEM</h2><p>D 可留空；仅转换公钥时只生成 SPKI 公钥 PEM。</p></div>
          <label>公钥 X<input v-model="sm2X" class="mono" spellcheck="false" placeholder="64 位 Hex" /></label>
          <label>公钥 Y<input v-model="sm2Y" class="mono" spellcheck="false" placeholder="64 位 Hex" /></label>
          <label>私钥 D（可选）
            <span class="secret-input">
              <input v-model="sm2D" :type="revealD ? 'text' : 'password'" class="mono" spellcheck="false" placeholder="64 位 Hex" />
              <button class="icon-button compact" type="button" :title="revealD ? '隐藏私钥 D' : '显示私钥 D'" @click="revealD = !revealD"><EyeOff v-if="revealD" :size="16" /><Eye v-else :size="16" /></button>
            </span>
          </label>
          <div class="inline-alert warn"><TriangleAlert :size="17" /><span>若填写 D，会校验 X、Y、D 是否属于同一密钥对；私钥 PEM 默认遮挡，所有转换仅在本机内存中完成。</span></div>
          <button class="button primary wide" type="button" :disabled="!canConvertSm2" @click="convertSm2"><ArrowRightLeft :size="16" />生成 PEM</button>
        </div>
      </section>

      <section class="generator-output">
        <div v-if="sm2Result" class="output-block">
          <div class="output-title"><div><span class="type-badge">SPKI</span><strong>SM2 公钥 PEM</strong></div><div><button class="icon-button compact" type="button" title="复制公钥 PEM" @click="copy(sm2Result.publicPem)"><Copy :size="16" /></button><button class="icon-button compact" type="button" title="下载公钥 PEM" @click="downloadPem(sm2Result.publicPem, 'sm2-public-key.pem')"><Download :size="16" /></button></div></div>
          <pre>{{ sm2Result.publicPem }}</pre>
        </div>
        <div v-if="sm2Result?.privatePem" class="output-block sensitive-block">
          <div class="output-title"><div><span class="type-badge">PKCS#8</span><strong>SM2 私钥 PEM</strong></div><div><button class="icon-button compact" type="button" :title="revealPrivatePem ? '隐藏私钥 PEM' : '显示私钥 PEM'" @click="revealPrivatePem = !revealPrivatePem"><EyeOff v-if="revealPrivatePem" :size="16" /><Eye v-else :size="16" /></button><button class="icon-button compact" type="button" title="复制私钥 PEM" @click="copy(sm2Result.privatePem!)"><Copy :size="16" /></button><button class="icon-button compact" type="button" title="下载私钥 PEM" @click="downloadPem(sm2Result.privatePem!, 'sm2-private-key.pem')"><Download :size="16" /></button></div></div>
          <pre :class="{ blurred: !revealPrivatePem }">{{ sm2Result.privatePem }}</pre>
        </div>
        <div v-if="!sm2Result" class="empty-state neutral tall"><KeyRound :size="27" /><strong>等待密钥分量</strong><p>转换后分别显示标准公钥 PEM 与私钥 PEM。</p></div>
      </section>
    </div>

    <div v-if="error" class="inline-alert fail convert-error">{{ error }}</div>
  </div>
</template>
