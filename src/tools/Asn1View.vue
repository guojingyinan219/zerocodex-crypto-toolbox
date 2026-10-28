<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { Braces, Upload, Trash2 } from '@lucide/vue'
import Asn1Node from '../components/Asn1Node.vue'
import { decodeFlexibleInput } from '../core/codec'
import { parseAsn1Tree } from '../core/asn1'
import type { Asn1TreeNode } from '../types'

const props = defineProps<{ initialInput?: string }>()
const input = ref(props.initialInput ?? '')
const bytes = ref<Uint8Array<ArrayBufferLike>>(new Uint8Array())
const root = ref<Asn1TreeNode>()
const selected = ref<Asn1TreeNode>()
const error = ref('')
const fileInput = ref<HTMLInputElement>()

const rows = computed(() => {
  const output: Array<{ offset: number; values: number[]; ascii: string }> = []
  for (let offset = 0; offset < bytes.value.length; offset += 16) {
    const chunk = Array.from(bytes.value.subarray(offset, offset + 16))
    output.push({ offset, values: chunk, ascii: chunk.map((byte) => byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.').join('') })
  }
  return output
})

function isSelected(offset: number) {
  if (!selected.value) return false
  return offset >= selected.value.offset && offset < selected.value.offset + selected.value.length
}

function parse() {
  error.value = ''
  root.value = undefined
  selected.value = undefined
  if (!input.value.trim()) {
    bytes.value = new Uint8Array()
    return
  }
  try {
    bytes.value = decodeFlexibleInput(input.value).bytes
    root.value = parseAsn1Tree(bytes.value)
    selected.value = root.value
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : 'ASN.1 解析失败'
  }
}

let timer: number | undefined
watch(input, () => {
  window.clearTimeout(timer)
  timer = window.setTimeout(parse, 180)
})

async function loadFile(file?: File) {
  if (!file) return
  const raw = new Uint8Array(await file.arrayBuffer())
  const looksText = raw.subarray(0, 40).every((byte) => byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte < 127))
  input.value = looksText ? new TextDecoder().decode(raw) : btoa(String.fromCharCode(...raw))
  parse()
}

if (input.value) parse()
</script>

<template>
  <div class="tool-view">
    <header class="page-header compact-header">
      <div><p class="eyebrow">F5 · ASN.1 / DER</p><h1>结构树与字节联动查看</h1><p>节点类型、长度、偏移和解码值一屏对照。</p></div>
    </header>
    <section class="asn-input-band">
      <textarea v-model="input" spellcheck="false" placeholder="粘贴 PEM、Base64 或 Hex" aria-label="ASN.1 输入" />
      <div class="vertical-actions">
        <input ref="fileInput" class="visually-hidden" type="file" @change="loadFile(($event.target as HTMLInputElement).files?.[0])" />
        <button class="button secondary" type="button" @click="fileInput?.click()"><Upload :size="16" />文件</button>
        <button class="icon-button" type="button" title="清空" @click="input = ''"><Trash2 :size="17" /></button>
      </div>
    </section>
    <div v-if="error" class="inline-alert fail"><strong>解析停在当前数据：</strong>{{ error }}</div>
    <div v-if="root" class="asn-workspace">
      <section class="asn-tree-pane">
        <div class="pane-title"><strong>结构树</strong><span>{{ bytes.length.toLocaleString() }} 字节</span></div>
        <ul class="asn-tree"><Asn1Node :node="root" :selected="selected?.id" @select="selected = $event" /></ul>
      </section>
      <section class="hex-pane">
        <div class="pane-title"><strong>十六进制</strong><span v-if="selected">已选 0x{{ selected.offset.toString(16) }} · {{ selected.length }} B</span></div>
        <div class="hex-scroll" role="region" aria-label="十六进制内容">
          <div v-for="row in rows" :key="row.offset" class="hex-row">
            <span class="hex-offset">{{ row.offset.toString(16).padStart(8, '0') }}</span>
            <span class="hex-values"><span v-for="(byte, index) in row.values" :key="index" :class="{ active: isSelected(row.offset + index) }">{{ byte.toString(16).padStart(2, '0') }}</span></span>
            <span class="hex-ascii">{{ row.ascii }}</span>
          </div>
        </div>
        <div v-if="selected" class="node-inspector"><Braces :size="18" /><div><strong>{{ selected.type }}</strong><p>{{ selected.value || '构造类型，包含子节点' }}</p><code>offset=0x{{ selected.offset.toString(16) }} length={{ selected.length }}</code></div></div>
      </section>
    </div>
    <div v-else-if="!error" class="empty-state neutral tall"><Braces :size="27" /><strong>等待 ASN.1 材料</strong><p>选择树节点后，对应字节会在右侧高亮。</p></div>
  </div>
</template>
