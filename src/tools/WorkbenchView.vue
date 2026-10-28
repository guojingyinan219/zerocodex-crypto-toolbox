<script setup lang="ts">
import { defineAsyncComponent, nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import { Upload, Trash2, WandSparkles, ScanSearch, ShieldCheck, XCircle, Archive, GitBranch } from '@lucide/vue'
import ResultPanel from '../components/ResultPanel.vue'
import type { ParseReport } from '../types'
import { extractPemBlocks } from '../core/codec'
import { generateKeyPair, generateSm2Certificate, parseMaterial } from '../core/pki'

const ContainerView = defineAsyncComponent(() => import('./ContainerView.vue'))
const ChainValidationView = defineAsyncComponent(() => import('./ChainValidationView.vue'))

const props = defineProps<{ initialInput?: string }>()
const emit = defineEmits<{
  openAsn1: [payload: { report: ParseReport; text: string }]
  openDoctor: [text: string]
}>()

const input = ref(props.initialInput ?? '')
const reports = ref<ParseReport[]>([])
const busy = ref(false)
const error = ref('')
const isDragging = ref(false)
const fileInput = ref<HTMLInputElement>()
const workspace = ref<'material' | 'container' | 'chain'>('material')
let timer: number | undefined

async function analyze() {
  if (!input.value.trim()) {
    reports.value = []
    error.value = ''
    return
  }
  busy.value = true
  error.value = ''
  try {
    const blocks = extractPemBlocks(input.value)
    if (blocks.length > 1) reports.value = await Promise.all(blocks.map((block) => parseMaterial(block.text)))
    else reports.value = [await parseMaterial(input.value)]
    await nextTick()
  } catch (cause) {
    reports.value = []
    error.value = cause instanceof Error ? cause.message : '解析失败'
  } finally {
    busy.value = false
  }
}

function scheduleAnalyze() {
  window.clearTimeout(timer)
  timer = window.setTimeout(analyze, 220)
}

async function loadFile(file?: File) {
  if (!file) return
  if (file.size > 5 * 1024 * 1024) {
    error.value = '单个文件不能超过 5 MB。'
    return
  }
  const buffer = new Uint8Array(await file.arrayBuffer())
  const isText = file.type.startsWith('text/') || buffer.subarray(0, 32).every((byte) => byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte < 127))
  input.value = isText ? new TextDecoder().decode(buffer) : btoa(String.fromCharCode(...buffer))
  await analyze()
}

async function loadExample() {
  busy.value = true
  const key = await generateKeyPair('SM2')
  const certificate = await generateSm2Certificate(key, { commonName: 'demo.gm.local', organization: '国密工具箱', country: 'CN' }, ['demo.gm.local', '127.0.0.1'], 365, false)
  input.value = certificate.pem
  await analyze()
}

function clearAll() {
  input.value = ''
  reports.value = []
  error.value = ''
}

function onDrop(event: DragEvent) {
  isDragging.value = false
  loadFile(event.dataTransfer?.files[0])
}

onMounted(() => {
  if (input.value.trim()) analyze()
})

onBeforeUnmount(() => {
  window.clearTimeout(timer)
  input.value = ''
  reports.value = []
})
</script>

<template>
  <div class="tool-view workbench-view">
    <header class="page-header">
      <div>
        <p class="eyebrow">统一入口</p>
        <h1>粘贴材料，直接看结论</h1>
        <p>自动识别证书、CSR、私钥、公钥与常见 PKCS 容器。</p>
      </div>
      <div class="local-only"><ShieldCheck :size="17" />全程在浏览器内计算 · 内容不会上传</div>
    </header>

    <div class="segmented" role="tablist" aria-label="证书工作台模式">
      <button type="button" :class="{ active: workspace === 'material' }" @click="workspace = 'material'"><ScanSearch :size="16" />材料解析</button>
      <button type="button" :class="{ active: workspace === 'container' }" @click="workspace = 'container'"><Archive :size="16" />容器解密</button>
      <button type="button" :class="{ active: workspace === 'chain' }" @click="workspace = 'chain'"><GitBranch :size="16" />证书链验证</button>
    </div>

    <div v-if="workspace === 'material'" class="split-workspace">
      <section class="input-pane">
        <div class="pane-toolbar">
          <strong>输入材料</strong>
          <div>
            <button class="icon-button" type="button" title="载入示例" @click="loadExample"><WandSparkles :size="17" /></button>
            <button class="icon-button" type="button" title="格式体检" :disabled="!input" @click="emit('openDoctor', input)"><ScanSearch :size="17" /></button>
            <button class="icon-button" type="button" title="清空" :disabled="!input" @click="clearAll"><Trash2 :size="17" /></button>
          </div>
        </div>
        <div class="drop-zone" :class="{ dragging: isDragging }" @dragover.prevent="isDragging = true" @dragleave.prevent="isDragging = false" @drop.prevent="onDrop">
          <textarea v-model="input" spellcheck="false" aria-label="证书或密钥材料" placeholder="粘贴 PEM、Base64、Hex，或拖入 .pem / .cer / .csr / .key 文件" @input="scheduleAnalyze" @paste="scheduleAnalyze" />
          <div v-if="!input" class="drop-hint" aria-hidden="true">
            <Upload :size="22" />
            <span>拖放文件到这里</span>
          </div>
        </div>
        <input ref="fileInput" class="visually-hidden" type="file" @change="loadFile(($event.target as HTMLInputElement).files?.[0])" />
        <div class="input-footer">
          <button class="button secondary" type="button" @click="fileInput?.click()"><Upload :size="16" />选择文件</button>
          <span>{{ input.length.toLocaleString() }} 字符 · 上限 5 MB</span>
        </div>
      </section>

      <section class="output-pane" aria-live="polite">
        <div v-if="busy" class="empty-state"><span class="spinner" />正在本地识别材料…</div>
        <div v-else-if="error" class="error-state">
          <XCircle :size="22" />
          <div><strong>暂未识别成功</strong><p>{{ error }}</p><button class="button secondary small" type="button" @click="emit('openDoctor', input)">打开格式体检</button></div>
        </div>
        <div v-else-if="reports.length" class="report-stack">
          <ResultPanel v-for="(report, index) in reports" :key="`${report.kind}-${index}`" :report="report" @inspect-asn1="emit('openAsn1', { report: $event, text: input })" />
        </div>
        <div v-else class="empty-state neutral">
          <div class="empty-mark"><ScanSearch :size="27" /></div>
          <strong>等待材料</strong>
          <p>识别结果、合规结论与下一步动作会显示在这里。</p>
        </div>
      </section>
    </div>
    <ContainerView v-else-if="workspace === 'container'" />
    <ChainValidationView v-else />
  </div>
</template>
