<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import {
  ArrowRightLeft,
  Binary,
  Braces,
  Check,
  Copy,
  Dices,
  Fingerprint,
  Hash,
  Link2,
  Play,
  RefreshCw,
  Stethoscope,
  ShieldCheck,
  Trash2
} from '@lucide/vue'
import FormatDoctorView from './FormatDoctorView.vue'
import WebsiteTlsView from './WebsiteTlsView.vue'
import {
  createUuid,
  decodeBase64Text,
  decodeHexText,
  decodeUrlText,
  digestText,
  encodeBase64Text,
  encodeHexText,
  encodeUrlText,
  formatJson,
  generateSecureIntegers,
  generateSecureRandomBytes,
  generateSecureRandomStrings,
  type RandomByteFormat,
  type DigestAlgorithm
} from '../core/common'
import type { CommonToolId } from '../seo'

type Direction = 'encode' | 'decode'
type RandomKind = 'string' | 'integer' | 'bytes'

const modes = [
  { id: 'base64' as const, label: 'Base64', eyebrow: '编码转换', title: 'Base64 编码与解码', description: 'UTF-8 文本与 Base64、Base64URL 互转，内容仅在当前浏览器中处理。', icon: Binary },
  { id: 'url' as const, label: 'URL 编码', eyebrow: '编码转换', title: 'URL 组件编码与解码', description: '转换中文、特殊字符和百分号转义，适合参数与回调地址排查。', icon: Link2 },
  { id: 'hex' as const, label: '文本 / Hex', eyebrow: '编码转换', title: 'UTF-8 文本与十六进制互转', description: '支持连续 Hex，以及带空格、冒号和换行的十六进制数据。', icon: Hash },
  { id: 'json' as const, label: 'JSON', eyebrow: '数据处理', title: 'JSON 格式化、校验与压缩', description: '快速美化或压缩 JSON，并在格式无效时给出错误位置。', icon: Braces },
  { id: 'digest' as const, label: '摘要计算', eyebrow: '哈希与摘要', title: 'SM3、SHA 与 MD5 摘要计算', description: '计算 SM3、SHA-1/2、MD4 和 MD5 文本摘要，并标明兼容性算法风险。', icon: Fingerprint },
  { id: 'uuid' as const, label: 'UUID v4', eyebrow: '随机标识', title: 'UUID v4 生成器', description: '使用浏览器加密随机数生成 UUID，适合请求标识、测试数据和本地开发。', icon: Fingerprint },
  { id: 'random' as const, label: '安全随机数', eyebrow: '随机数据', title: '安全随机字符串与随机数生成器', description: '生成指定长度的字母、数字、特殊字符组合，也支持随机整数和随机字节。', icon: Dices },
  { id: 'doctor' as const, label: '格式体检', eyebrow: '证书材料诊断', title: 'PEM、Base64 与 Hex 格式体检', description: '定位标签、换行、BOM、HTML 转义和 DER 长度问题，并提供规范化处理。', icon: Stethoscope },
  { id: 'tls' as const, label: '网站安全', eyebrow: '网站安全诊断', title: '网站证书、协议与安全策略检测', description: '集中检查证书链、TLS 协议、Web 安全策略、常见风险和国密 TLCP 能力。', icon: ShieldCheck }
]

const props = defineProps<{ mode: CommonToolId; initialInput?: string }>()
const active = computed(() => props.mode)
const direction = ref<Direction>('encode')
const jsonCompact = ref(false)
const digestAlgorithm = ref<DigestAlgorithm>('SM3')
const input = ref(props.initialInput ?? '')
const output = ref('')
const error = ref('')
const copied = ref<'output' | 'uuid' | 'random' | ''>('')
const processing = ref(false)
const uuid = ref(createUuid())
const randomKind = ref<RandomKind>('string')
const randomStringLength = ref(32)
const randomStringCount = ref(4)
const randomUseLowercase = ref(true)
const randomUseUppercase = ref(true)
const randomUseNumbers = ref(true)
const randomUseSpecial = ref(true)
const randomSpecialCharacters = ref('!@#$%^&*()-_=+[]{};:,.?/|~')
const randomMinimum = ref(0)
const randomMaximum = ref(999999)
const randomIntegerCount = ref(10)
const randomByteLength = ref(16)
const randomByteCount = ref(4)
const randomByteFormat = ref<RandomByteFormat>('hex')
const randomOutput = ref('')
const randomError = ref('')
const randomCharacterSets = computed(() => [
  randomUseLowercase.value ? 'abcdefghijklmnopqrstuvwxyz' : '',
  randomUseUppercase.value ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' : '',
  randomUseNumbers.value ? '0123456789' : '',
  randomUseSpecial.value ? randomSpecialCharacters.value : ''
].filter(Boolean))
const randomPoolSize = computed(() => new Set(randomCharacterSets.value.flatMap((set) => Array.from(set))).size)
const randomEntropyBits = computed(() => randomPoolSize.value > 1 ? Math.round(randomStringLength.value * Math.log2(randomPoolSize.value)) : 0)

const activeMeta = computed(() => modes.find((mode) => mode.id === active.value)!)
const inputPlaceholder = computed(() => {
  if (active.value === 'base64') return direction.value === 'encode' ? '输入需要编码的 UTF-8 文本' : '粘贴 Base64 或 Base64URL 文本'
  if (active.value === 'url') return direction.value === 'encode' ? '输入 URL 参数或任意文本' : '粘贴含 % 转义的 URL 编码文本'
  if (active.value === 'hex') return direction.value === 'encode' ? '输入需要转换的 UTF-8 文本' : '粘贴 Hex；允许空格、冒号和换行'
  if (active.value === 'json') return '粘贴 JSON 文本，例如 {"name":"gmssl"}'
  return '输入需要计算摘要的文本'
})
const actionLabel = computed(() => {
  if (active.value === 'json') return jsonCompact.value ? '压缩 JSON' : '格式化 JSON'
  if (active.value === 'digest') return `计算 ${digestAlgorithm.value}`
  return direction.value === 'encode' ? '编码' : '解码'
})

watch(() => props.mode, () => {
  output.value = ''
  error.value = ''
  direction.value = 'encode'
})

async function run() {
  error.value = ''
  processing.value = true
  try {
    if (active.value === 'base64') output.value = direction.value === 'encode' ? encodeBase64Text(input.value) : decodeBase64Text(input.value)
    if (active.value === 'url') output.value = direction.value === 'encode' ? encodeUrlText(input.value) : decodeUrlText(input.value)
    if (active.value === 'hex') output.value = direction.value === 'encode' ? encodeHexText(input.value) : decodeHexText(input.value)
    if (active.value === 'json') output.value = formatJson(input.value, jsonCompact.value)
    if (active.value === 'digest') output.value = await digestText(input.value, digestAlgorithm.value)
  } catch (cause) {
    output.value = ''
    error.value = cause instanceof Error ? cause.message : '处理失败，请检查输入。'
  } finally {
    processing.value = false
  }
}

function swap() {
  if (!output.value || active.value === 'digest') return
  input.value = output.value
  output.value = ''
  if (active.value !== 'json') direction.value = direction.value === 'encode' ? 'decode' : 'encode'
}

function loadExample() {
  if (active.value === 'base64') input.value = '国密工具箱 GMSSL Workbench'
  if (active.value === 'url') input.value = 'https://example.com/callback?name=国密工具箱&mode=test'
  if (active.value === 'hex') input.value = 'SM2 / SM3 / SM4 国密算法'
  if (active.value === 'json') input.value = '{"algorithm":"SM2","digest":"SM3","enabled":true,"usages":["sign","verify"]}'
  if (active.value === 'digest') input.value = 'abc'
  output.value = ''
  error.value = ''
}

function clearAll() {
  input.value = ''
  output.value = ''
  error.value = ''
}

function generateRandom() {
  randomError.value = ''
  try {
    if (randomKind.value === 'string') randomOutput.value = generateSecureRandomStrings(randomStringLength.value, randomStringCount.value, randomCharacterSets.value).join('\n')
    if (randomKind.value === 'integer') randomOutput.value = generateSecureIntegers(randomMinimum.value, randomMaximum.value, randomIntegerCount.value).join('\n')
    if (randomKind.value === 'bytes') randomOutput.value = generateSecureRandomBytes(randomByteLength.value, randomByteCount.value, randomByteFormat.value).join('\n')
  } catch (cause) {
    randomOutput.value = ''
    randomError.value = cause instanceof Error ? cause.message : '随机数据生成失败。'
  }
}

async function copy(value: string, target: 'output' | 'uuid' | 'random') {
  await navigator.clipboard.writeText(value)
  copied.value = target
  window.setTimeout(() => {
    if (copied.value === target) copied.value = ''
  }, 1400)
}
</script>

<template>
  <div class="tool-view common-tools-view">
    <header class="page-header compact-header">
      <div><p class="eyebrow">{{ activeMeta.eyebrow }}</p><h1>{{ activeMeta.title }}</h1><p>{{ activeMeta.description }}</p></div>
    </header>

    <FormatDoctorView v-if="active === 'doctor'" :initial-input="props.initialInput" embedded />
    <WebsiteTlsView v-else-if="active === 'tls'" />
    <section v-else-if="active === 'random'" class="random-tool-shell">
      <div class="random-tool-bar">
        <div class="uuid-tool-heading"><Dices :size="24" /><div><strong>Web Crypto 安全随机源</strong><span>结果仅在当前浏览器中生成</span></div></div>
        <div class="segmented compact-segmented" aria-label="随机数据类型">
          <button type="button" :class="{ active: randomKind === 'string' }" @click="randomKind = 'string'; randomOutput = ''; randomError = ''">随机字符串</button>
          <button type="button" :class="{ active: randomKind === 'integer' }" @click="randomKind = 'integer'; randomOutput = ''; randomError = ''">随机整数</button>
          <button type="button" :class="{ active: randomKind === 'bytes' }" @click="randomKind = 'bytes'; randomOutput = ''; randomError = ''">随机字节</button>
        </div>
      </div>
      <div class="random-tool-body">
        <form class="random-settings" @submit.prevent="generateRandom">
          <template v-if="randomKind === 'string'">
            <div class="random-field-grid">
              <label><span>字符串长度</span><input v-model.number="randomStringLength" type="number" min="1" max="4096" step="1" /></label>
              <label><span>生成数量</span><input v-model.number="randomStringCount" type="number" min="1" max="100" step="1" /></label>
              <label class="random-symbol-field"><span>特殊字符</span><input v-model="randomSpecialCharacters" type="text" :disabled="!randomUseSpecial" spellcheck="false" /></label>
            </div>
            <fieldset class="random-character-sets"><legend>字符组成</legend><div><label><input v-model="randomUseLowercase" type="checkbox" />小写字母</label><label><input v-model="randomUseUppercase" type="checkbox" />大写字母</label><label><input v-model="randomUseNumbers" type="checkbox" />数字</label><label><input v-model="randomUseSpecial" type="checkbox" />特殊字符</label></div></fieldset>
          </template>
          <div v-else-if="randomKind === 'integer'" class="random-field-grid">
            <label><span>最小值</span><input v-model.number="randomMinimum" type="number" step="1" /></label>
            <label><span>最大值</span><input v-model.number="randomMaximum" type="number" step="1" /></label>
            <label><span>生成数量</span><input v-model.number="randomIntegerCount" type="number" min="1" max="1000" step="1" /></label>
          </div>
          <div v-else class="random-field-grid">
            <label><span>字节长度</span><input v-model.number="randomByteLength" type="number" min="1" max="4096" step="1" /></label>
            <label><span>生成数量</span><input v-model.number="randomByteCount" type="number" min="1" max="100" step="1" /></label>
            <label><span>输出格式</span><select v-model="randomByteFormat"><option value="hex">Hex</option><option value="base64">Base64</option><option value="base64url">Base64URL</option></select></label>
          </div>
          <div class="inline-alert info random-source-note"><ShieldCheck :size="17" /><span>{{ randomKind === 'string' ? `字符池 ${randomPoolSize} 个字符，单组估算熵值约 ${randomEntropyBits} bit。` : randomKind === 'integer' ? '采用无偏差拒绝采样；单次范围最大为 2^32。' : `每组包含 ${randomByteLength * 8} bit 随机数据。` }}</span></div>
          <button class="button primary" type="submit"><RefreshCw :size="17" />{{ randomKind === 'string' ? '生成随机字符串' : randomKind === 'integer' ? '生成随机数' : '生成随机字节' }}</button>
        </form>
        <section class="random-result">
          <div class="pane-toolbar"><div><strong>生成结果</strong><span v-if="randomOutput" class="subtle-label">{{ randomOutput.split('\n').length }} 组</span></div><button class="icon-button" type="button" title="复制随机数据" :disabled="!randomOutput" @click="copy(randomOutput, 'random')"><Check v-if="copied === 'random'" :size="18" /><Copy v-else :size="18" /></button></div>
          <textarea :value="randomOutput" readonly :placeholder="randomKind === 'string' ? '随机字符串将逐行显示' : randomKind === 'integer' ? '随机整数将逐行显示' : '随机字节将逐行显示'" spellcheck="false" />
        </section>
      </div>
      <div v-if="randomError" class="inline-alert fail common-error"><strong>无法生成：</strong><span>{{ randomError }}</span></div>
    </section>
    <section v-else-if="active === 'uuid'" class="uuid-tool-shell">
      <div class="uuid-tool-heading"><Fingerprint :size="24" /><div><strong>当前 UUID v4</strong><span>由 Web Crypto 安全随机源生成</span></div></div>
      <code>{{ uuid }}</code>
      <div class="quick-actions"><button class="button secondary" type="button" @click="uuid = createUuid()"><RefreshCw :size="18" />重新生成</button><button class="button primary" type="button" @click="copy(uuid, 'uuid')"><Check v-if="copied === 'uuid'" :size="17" /><Copy v-else :size="17" />{{ copied === 'uuid' ? '已复制' : '复制 UUID' }}</button></div>
    </section>
    <section v-else class="common-tool-shell">
      <div class="common-command-bar">
        <div class="tool-context"><component :is="activeMeta.icon" :size="21" /><div><strong>{{ activeMeta.label }}</strong><span>{{ activeMeta.description }}</span></div></div>

        <div v-if="active !== 'json' && active !== 'digest'" class="segmented compact-segmented" aria-label="转换方向">
          <button type="button" :class="{ active: direction === 'encode' }" @click="direction = 'encode'">编码</button>
          <button type="button" :class="{ active: direction === 'decode' }" @click="direction = 'decode'">解码</button>
        </div>
        <div v-else-if="active === 'json'" class="segmented compact-segmented" aria-label="JSON 操作">
          <button type="button" :class="{ active: !jsonCompact }" @click="jsonCompact = false">格式化</button>
          <button type="button" :class="{ active: jsonCompact }" @click="jsonCompact = true">压缩</button>
        </div>
        <div v-else class="digest-pills" aria-label="摘要算法"><button v-for="item in ['SM3', 'MD4', 'MD5', 'SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512'] as DigestAlgorithm[]" :key="item" type="button" :class="{ active: digestAlgorithm === item }" @click="digestAlgorithm = item">{{ item }}</button></div>

        <button class="button primary" type="button" :disabled="processing || !input" @click="run"><Play :size="16" />{{ actionLabel }}</button>
      </div>

      <div class="common-workspace">
        <section>
          <div class="pane-toolbar"><div><strong>输入</strong><span class="subtle-label">{{ input.length }} 字符</span></div><div><button class="button small secondary" type="button" @click="loadExample">载入示例</button><button class="icon-button" type="button" title="清空输入和输出" @click="clearAll"><Trash2 :size="18" /></button></div></div>
          <textarea v-model="input" :placeholder="inputPlaceholder" spellcheck="false" />
        </section>
        <section>
          <div class="pane-toolbar"><div><strong>结果</strong><span v-if="output" class="subtle-label">{{ output.length }} 字符</span></div><div><button v-if="active !== 'digest'" class="icon-button" type="button" title="把结果移到输入区" :disabled="!output" @click="swap"><ArrowRightLeft :size="18" /></button><button class="icon-button" type="button" title="复制结果" :disabled="!output" @click="copy(output, 'output')"><Check v-if="copied === 'output'" :size="18" /><Copy v-else :size="18" /></button></div></div>
          <textarea :value="output" readonly placeholder="处理结果将显示在这里" spellcheck="false" />
        </section>
      </div>
      <div v-if="error" class="inline-alert fail common-error"><strong>无法处理：</strong><span>{{ error }}</span></div>
      <div v-if="active === 'digest' && ['MD4', 'MD5', 'SHA-1'].includes(digestAlgorithm)" class="inline-alert warn common-error"><strong>兼容性摘要：</strong><span>MD4、MD5 和 SHA-1 仅适合旧系统校验，不应用于新签名、口令存储或安全校验。</span></div>
    </section>

  </div>
</template>
