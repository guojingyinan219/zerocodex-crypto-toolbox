<script setup lang="ts">
import { computed, ref } from 'vue'
import { BadgeCheck, Check, Copy, KeyRound, RefreshCw, ShieldCheck, Trash2 } from '@lucide/vue'
import {
  cbcMac,
  cipherHex,
  keyCheckValue,
  type CipherMode,
  type LegacyCipher,
  type SymmetricCipher,
  type Padding,
  x919Mac,
  xorBlockCheck,
  xorHex
} from '../core/symmetric'

const cipher = ref<SymmetricCipher>('3DES-2K')
const mode = ref<CipherMode>('CBC')
const padding = ref<Padding>('PKCS7')
const key = ref('0123456789ABCDEFFEDCBA9876543210')
const iv = ref('0000000000000000')
const data = ref('0123456789ABCDEF')
const data1 = ref('')
const result = ref('')
const resultTitle = ref('等待操作')
const resultDetail = ref('选择操作后，结果会以大写 Hex 显示。')
const error = ref('')
const copied = ref(false)

const cipherOptions: Array<{ id: SymmetricCipher; label: string; caption: string; key: string }> = [
  { id: 'DES', label: 'DES', caption: '单长度密钥', key: '8 B' },
  { id: '3DES-2K', label: '3DES 双长度', caption: 'K1 / K2', key: '16 B' },
  { id: '3DES-3K', label: '3DES 三长度', caption: 'K1 / K2 / K3', key: '24 B' },
  { id: 'SM4', label: 'SM4', caption: '国密分组密码', key: '16 B' },
  { id: 'AES-128', label: 'AES-128', caption: '通用分组密码', key: '16 B' },
  { id: 'AES-192', label: 'AES-192', caption: '通用分组密码', key: '24 B' },
  { id: 'AES-256', label: 'AES-256', caption: '通用分组密码', key: '32 B' }
]

const activeCipher = computed(() => cipherOptions.find((item) => item.id === cipher.value)!)
const keyHint = computed(() => `${activeCipher.value.key} · ${Number.parseInt(activeCipher.value.key, 10) * 2} 位 Hex`)
const isLegacyCipher = computed(() => ['DES', '3DES-2K', '3DES-3K'].includes(cipher.value))
const isRetailMacCipher = computed(() => cipher.value === '3DES-2K' || cipher.value === '3DES-3K')
const isStreamMode = computed(() => mode.value === 'CFB' || mode.value === 'OFB')
const ivHint = computed(() => isLegacyCipher.value ? '8 B' : '16 B')
const inputBytes = computed(() => data.value.replace(/[\s:,-]/g, '').length / 2 || 0)
const resultBytes = computed(() => result.value.length / 2 || 0)

function setCipher(next: SymmetricCipher) {
  cipher.value = next
  key.value = next === 'DES' ? '133457799BBCDFF1' : next === '3DES-2K' ? '0123456789ABCDEFFEDCBA9876543210' : next === '3DES-3K' ? '0123456789ABCDEFFEDCBA98765432100011223344556677' : next === 'SM4' ? '0123456789ABCDEFFEDCBA9876543210' : next === 'AES-128' ? '00112233445566778899AABBCCDDEEFF' : next === 'AES-192' ? '00112233445566778899AABBCCDDEEFF0001020304050607' : '00112233445566778899AABBCCDDEEFF00010203040506070008090A0B0C0D0E0F'
  iv.value = next.startsWith('AES') || next === 'SM4' ? '00000000000000000000000000000000' : '0000000000000000'
  clearResult()
}

function setMode(next: CipherMode) {
  mode.value = next
  if (next === 'CFB' || next === 'OFB') padding.value = 'NONE'
  clearResult()
}

function run(title: string, detail: string, action: () => string) {
  error.value = ''
  copied.value = false
  try {
    result.value = action()
    resultTitle.value = title
    resultDetail.value = detail
  } catch (cause) {
    result.value = ''
    error.value = cause instanceof Error ? cause.message : '处理失败，请检查输入。'
  }
}

function encrypt() {
  run(`${mode.value} 加密结果`, `${cipher.value} · ${padding.value === 'NONE' ? '无填充' : padding.value === 'PKCS7' ? 'PKCS#7 填充' : '零填充'} · ${inputBytes.value} B 输入`, () => cipherHex({ cipher: cipher.value, mode: mode.value, padding: padding.value, key: key.value, iv: iv.value, data: data.value }))
}

function decrypt() {
  run(`${mode.value} 解密结果`, `${cipher.value} · 解密后以 Hex 显示`, () => cipherHex({ cipher: cipher.value, mode: mode.value, padding: padding.value, key: key.value, iv: iv.value, data: data.value, decrypt: true }))
}

function kcv() {
  run('密钥校验值 KCV', '使用 ECB 无填充加密 8 字节全零块；常用校验值取前 3 字节。', () => {
    const value = keyCheckValue(cipher.value, key.value)
    return `完整 8 B：${value.full}\n常用前 3 B：${value.short}`
  })
}

function retailMac() {
  run('ANSI X9.19 Retail MAC', '数据尾部以 00 补齐至 8 字节；MAC 为 8 字节。', () => x919Mac(key.value, data.value))
}

function mac() {
  run(`${cipher.value} CBC-MAC`, `使用 ${cipher.value}、全零 IV 和零填充，输出最后一个密文分组。`, () => cbcMac(cipher.value, key.value, data.value))
}

function xorData() {
  run('数据异或结果', '数据与数据 1 按字节异或，两个输入长度必须一致。', () => xorHex(data.value, data1.value))
}

function dataCheck() {
  run('数据块 XOR 校验', '按 8 字节分组异或；最后一个不完整分组以 00 补齐。', () => xorBlockCheck(data.value))
}

function clearResult() {
  result.value = ''
  error.value = ''
  resultTitle.value = '等待操作'
  resultDetail.value = '选择操作后，结果会以大写 Hex 显示。'
}

function reset() {
  setCipher(cipher.value)
  data.value = '0123456789ABCDEF'
  data1.value = ''
  clearResult()
}

async function copy() {
  if (!result.value) return
  await navigator.clipboard.writeText(result.value)
  copied.value = true
  window.setTimeout(() => { copied.value = false }, 1400)
}
</script>

<template>
  <div class="tool-view symmetric-view">
    <header class="page-header compact-header">
      <div><p class="eyebrow">对称密码与金融兼容工具</p><h1>SM4、AES、DES / 3DES 与校验值</h1><p>用于国密与通用系统联调、金融报文排查和密钥材料核验。输入输出均为 Hex，所有计算仅在当前浏览器内完成。</p></div>
      <div class="local-only"><ShieldCheck :size="18" />本地处理 · 不上传密钥</div>
    </header>

    <section class="symmetric-shell">
      <div class="cipher-selector" role="radiogroup" aria-label="算法选择">
        <button v-for="item in cipherOptions" :key="item.id" type="button" role="radio" :aria-checked="cipher === item.id" :class="{ active: cipher === item.id }" @click="setCipher(item.id)"><KeyRound :size="19" /><span><strong>{{ item.label }}</strong><small>{{ item.caption }}</small></span><em>{{ item.key }}</em></button>
      </div>

      <div class="symmetric-layout">
        <section class="symmetric-form">
          <div class="symmetric-section-title"><div><h2>输入材料</h2><p>Hex 可包含空格、冒号或换行，会在计算时自动忽略。</p></div><button class="icon-button" type="button" title="恢复示例" @click="reset"><RefreshCw :size="18" /></button></div>

          <div class="symmetric-controls">
            <label>工作模式<div class="segmented compact-segmented"><button v-for="item in ['ECB', 'CBC', 'CFB', 'OFB'] as CipherMode[]" :key="item" type="button" :class="{ active: mode === item }" @click="setMode(item)">{{ item }}</button></div></label>
            <label>填充规则<select v-model="padding" :disabled="isStreamMode"><option value="PKCS7">PKCS#7</option><option value="ZERO">零填充</option><option value="NONE">无填充</option></select><small v-if="isStreamMode">{{ mode }} 为流式模式，固定使用无填充</small></label>
          </div>

          <label class="symmetric-field"><span>密钥 <small>{{ keyHint }}</small></span><input v-model="key" class="mono" spellcheck="false" /></label>
          <label class="symmetric-field" :class="{ muted: mode === 'ECB' }"><span>初始化向量 IV <small>{{ mode === 'ECB' ? 'ECB 模式不使用 IV' : ivHint }}</small></span><input v-model="iv" class="mono" :disabled="mode === 'ECB'" spellcheck="false" /></label>
          <label class="symmetric-field"><span>数据 <small>{{ inputBytes }} B</small></span><textarea v-model="data" class="mono" spellcheck="false" placeholder="输入待加密、解密或计算 MAC 的 Hex 数据" /></label>
          <label class="symmetric-field compact-data"><span>数据 1 <small>仅“数据异或”使用</small></span><textarea v-model="data1" class="mono" spellcheck="false" placeholder="输入与数据等长的 Hex" /></label>
        </section>

        <section class="symmetric-result">
          <div class="symmetric-section-title"><div><p class="eyebrow">计算结果</p><h2>{{ resultTitle }}</h2><span>{{ resultDetail }}</span></div><button class="icon-button" type="button" title="复制结果" :disabled="!result" @click="copy"><Check v-if="copied" :size="18" /><Copy v-else :size="18" /></button></div>
          <pre :class="{ empty: !result }">{{ result || '结果将在这里显示' }}</pre>
          <div class="result-meta"><span>{{ resultBytes }} B 输出</span><span>{{ result ? 'Hex' : '等待输入' }}</span></div>
          <div v-if="error" class="inline-alert fail"><BadgeCheck :size="18" /><span>{{ error }}</span></div>
        </section>
      </div>

      <section class="symmetric-actions">
        <div class="action-group"><span>密码运算</span><div><button class="button primary" type="button" @click="encrypt">{{ mode }} 加密</button><button class="button secondary" type="button" @click="decrypt">{{ mode }} 解密</button></div></div>
        <div class="action-group"><span>MAC 与校验</span><div><button v-if="isRetailMacCipher" class="button secondary" type="button" @click="retailMac">X9.19 MAC</button><button class="button secondary" type="button" @click="mac">CBC-MAC</button><button v-if="isLegacyCipher" class="button secondary" type="button" @click="dataCheck">数据块校验</button><button class="button secondary" type="button" @click="kcv">密钥 KCV</button></div></div>
        <div class="action-group"><span>辅助操作</span><div><button class="button secondary" type="button" @click="xorData">数据 XOR 数据 1</button><button class="button secondary" type="button" @click="clearResult"><Trash2 :size="16" />清空结果</button></div></div>
      </section>
    </section>
  </div>
</template>
