<script setup lang="ts">
import { computed, ref } from 'vue'
import { CheckCircle2, AlertTriangle, XCircle, Info, Copy, Eye, EyeOff } from '@lucide/vue'
import type { ParseReport, Status } from '../types'

const props = defineProps<{ report: ParseReport }>()
const emit = defineEmits<{ inspectAsn1: [report: ParseReport] }>()
const revealed = ref(new Set<string>())

const statusMeta: Record<Status, { label: string; icon: typeof CheckCircle2 }> = {
  pass: { label: '通过', icon: CheckCircle2 },
  warn: { label: '告警', icon: AlertTriangle },
  fail: { label: '失败', icon: XCircle },
  info: { label: '信息', icon: Info }
}

const headlineFinding = computed(() => {
  if (props.report.status === 'fail') return props.report.findings.find((item) => item.status === 'fail')
  if (props.report.status === 'warn') return props.report.findings.find((item) => item.status === 'warn')
  return props.report.findings[0]
})
const headline = computed(() => headlineFinding.value?.title ?? props.report.summary)
const isPrivateMaterial = computed(() => props.report.kind === 'private-key' || props.report.kind === 'encrypted-private-key')

function toggleSensitive(key: string) {
  const next = new Set(revealed.value)
  next.has(key) ? next.delete(key) : next.add(key)
  revealed.value = next
}

async function copy(value: string) {
  await navigator.clipboard.writeText(value)
}
</script>

<template>
  <section class="result-panel">
    <div class="result-heading">
      <div>
        <div class="result-kicker">
          <span class="type-badge">{{ report.algorithm }}</span>
          <span>{{ report.label }}</span>
        </div>
        <h2>{{ report.summary }}</h2>
      </div>
      <button class="button secondary small" type="button" @click="emit('inspectAsn1', report)">
        查看 ASN.1
      </button>
    </div>

    <div class="conclusion" :class="`status-${report.status}`">
      <component :is="statusMeta[report.status].icon" :size="20" aria-hidden="true" />
      <div>
        <strong>{{ statusMeta[report.status].label }} · {{ headline }}</strong>
        <span>{{ headlineFinding?.detail }}</span>
      </div>
    </div>

    <div v-if="isPrivateMaterial" class="inline-alert warn private-key-warning"><AlertTriangle :size="17" /><span>检测到私钥材料。敏感字段默认遮挡，点击眼睛图标可在当前页面临时查看；请勿在共享屏幕、日志或非受控环境中展示。</span></div>

    <div class="finding-list" aria-label="检查结论">
      <article v-for="finding in report.findings" :key="finding.id" class="finding-row">
        <component :is="statusMeta[finding.status].icon" :size="17" :class="`text-${finding.status}`" aria-hidden="true" />
        <div>
          <div class="finding-title"><strong>{{ finding.title }}</strong><code>{{ finding.id }}</code></div>
          <p>{{ finding.detail }}</p>
          <p v-if="finding.fix" class="fix">建议：{{ finding.fix }}</p>
        </div>
      </article>
    </div>

    <details v-for="group in report.groups" :key="group.title" class="field-group" open>
      <summary>{{ group.title }}<span>{{ group.items.length }} 项</span></summary>
      <dl>
        <template v-for="(item, index) in group.items" :key="`${group.title}-${item.label}-${index}`">
          <dt>{{ item.label }}</dt>
          <dd :class="{ mono: item.mono, masked: item.sensitive && !revealed.has(`${group.title}-${index}`) }">
            <span>{{ item.sensitive && !revealed.has(`${group.title}-${index}`) ? '••••••••••••••••••••••••••••••••' : item.value }}</span>
            <span class="field-actions">
              <button v-if="item.sensitive" class="icon-button compact" type="button" :title="revealed.has(`${group.title}-${index}`) ? '隐藏敏感值' : '显示敏感值'" @click="toggleSensitive(`${group.title}-${index}`)">
                <EyeOff v-if="revealed.has(`${group.title}-${index}`)" :size="15" />
                <Eye v-else :size="15" />
              </button>
              <button class="icon-button compact" type="button" title="复制" @click="copy(item.value)"><Copy :size="15" /></button>
            </span>
          </dd>
        </template>
      </dl>
    </details>
  </section>
</template>
