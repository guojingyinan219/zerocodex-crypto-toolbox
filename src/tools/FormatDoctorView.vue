<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { CheckCircle2, AlertTriangle, XCircle, Info, Wand2, Copy, Trash2 } from '@lucide/vue'
import { auditText, repairText } from '../core/codec'
import type { Finding, Status } from '../types'

const props = defineProps<{ initialInput?: string; embedded?: boolean }>()
const input = ref(props.initialInput ?? '')
const findings = ref<Finding[]>(input.value ? auditText(input.value) : [])
const statusIcons: Record<Status, typeof CheckCircle2> = { pass: CheckCircle2, warn: AlertTriangle, fail: XCircle, info: Info }
const summary = computed(() => ({
  pass: findings.value.filter((item) => item.status === 'pass').length,
  warn: findings.value.filter((item) => item.status === 'warn').length,
  fail: findings.value.filter((item) => item.status === 'fail').length
}))

let timer: number | undefined
watch(input, () => {
  window.clearTimeout(timer)
  timer = window.setTimeout(() => { findings.value = input.value.trim() ? auditText(input.value) : [] }, 160)
})

function repair() {
  input.value = repairText(input.value)
  findings.value = auditText(input.value)
}

async function copyInput() {
  await navigator.clipboard.writeText(input.value)
}
</script>

<template>
  <div :class="embedded ? 'doctor-embedded' : 'tool-view'">
    <header v-if="!embedded" class="page-header compact-header">
      <div><p class="eyebrow">F6 · 文本格式体检</p><h1>先检查文本，再排查算法</h1><p>定位 PEM 标签、Base64、换行、BOM、HTML 转义和 DER 长度问题。</p></div>
    </header>
    <div class="split-workspace doctor-workspace">
      <section class="input-pane">
        <div class="pane-toolbar"><strong>待检查文本</strong><button class="icon-button" type="button" title="清空" @click="input = ''"><Trash2 :size="17" /></button></div>
        <textarea v-model="input" class="large-textarea" spellcheck="false" placeholder="粘贴 PEM 或 Base64 内容" />
        <div class="input-footer">
          <button class="button primary" type="button" :disabled="!input" @click="repair"><Wand2 :size="16" />一键规范化</button>
          <button class="button secondary" type="button" :disabled="!input" @click="copyInput"><Copy :size="16" />复制</button>
        </div>
      </section>
      <section class="output-pane">
        <div v-if="findings.length" class="doctor-report">
          <div class="metric-strip">
            <div><span>通过</span><strong class="text-pass">{{ summary.pass }}</strong></div>
            <div><span>告警</span><strong class="text-warn">{{ summary.warn }}</strong></div>
            <div><span>失败</span><strong class="text-fail">{{ summary.fail }}</strong></div>
          </div>
          <article v-for="finding in findings" :key="finding.id" class="audit-item">
            <component :is="statusIcons[finding.status]" :size="19" :class="`text-${finding.status}`" />
            <div><div class="finding-title"><strong>{{ finding.title }}</strong><code>{{ finding.id }}</code></div><p>{{ finding.detail }}</p><p v-if="finding.fix" class="fix">修复：{{ finding.fix }}</p></div>
          </article>
        </div>
        <div v-else class="empty-state neutral"><Info :size="25" /><strong>等待输入</strong><p>检查项会逐条给出通过、告警或失败结论。</p></div>
      </section>
    </div>
  </div>
</template>
