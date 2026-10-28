<script setup lang="ts">
import { ref } from 'vue'
import { Archive, Eye, EyeOff, LockKeyhole, RefreshCw, Upload } from '@lucide/vue'
import ResultPanel from '../components/ResultPanel.vue'
import type { ParseReport } from '../types'
import { bytesToBase64, decodeFlexibleInput } from '../core/codec'
import { decryptPkcs8, inspectContainer, reencryptPkcs8 } from '../core/containers'

type ContainerKind = 'auto' | 'pkcs12' | 'pkcs7' | 'jks' | 'encrypted-private-key'
const input = ref('')
const kind = ref<ContainerKind>('auto')
const password = ref('')
const newPassword = ref('')
const revealPassword = ref(false)
const report = ref<ParseReport>()
const reencryptedPem = ref('')
const busy = ref(false)
const error = ref('')
const fileInput = ref<HTMLInputElement>()

async function loadFile(file?: File) {
  if (!file) return
  if (file.size > 10 * 1024 * 1024) { error.value = '容器文件不能超过 10 MB。'; return }
  input.value = bytesToBase64(new Uint8Array(await file.arrayBuffer()))
  const name = file.name.toLowerCase()
  if (/\.(p12|pfx)$/.test(name)) kind.value = 'pkcs12'
  else if (/\.(jks|keystore)$/.test(name)) kind.value = 'jks'
  else if (/\.(p7b|p7c|p7s)$/.test(name)) kind.value = 'pkcs7'
  else if (/\.(key|pk8)$/.test(name)) kind.value = 'encrypted-private-key'
}

async function inspect() {
  busy.value = true; error.value = ''; report.value = undefined; reencryptedPem.value = ''
  try { report.value = await inspectContainer(input.value, kind.value, password.value) }
  catch (cause) { error.value = cause instanceof Error ? cause.message : '容器解析失败。' }
  finally { busy.value = false }
}

function reencrypt() {
  error.value = ''
  try {
    const source = decodeFlexibleInput(input.value).bytes
    const decrypted = decryptPkcs8(source, password.value)
    reencryptedPem.value = reencryptPkcs8(decrypted.privatePem, newPassword.value)
  } catch (cause) { error.value = cause instanceof Error ? cause.message : '私钥重加密失败。' }
}
</script>

<template>
  <div class="generator-layout container-layout">
    <section class="form-pane">
      <div class="form-section">
        <label>容器格式<select v-model="kind"><option value="auto">自动识别</option><option value="pkcs12">PKCS#12 / PFX</option><option value="jks">JKS</option><option value="pkcs7">CMS / PKCS#7</option><option value="encrypted-private-key">加密 PKCS#8</option></select></label>
        <label>容器内容<textarea v-model="input" rows="9" class="mono" placeholder="粘贴 PEM、Base64，或选择二进制容器文件" /></label>
        <input ref="fileInput" class="visually-hidden" type="file" accept=".p12,.pfx,.jks,.keystore,.p7b,.p7c,.p7s,.key,.pk8,.pem" @change="loadFile(($event.target as HTMLInputElement).files?.[0])" />
        <button class="button secondary wide" type="button" @click="fileInput?.click()"><Upload :size="16" />选择容器文件</button>
        <label v-if="kind !== 'pkcs7'">口令<div class="password-field"><input v-model="password" :type="revealPassword ? 'text' : 'password'" autocomplete="off" /><button class="icon-button compact" type="button" :title="revealPassword ? '隐藏口令' : '显示口令'" @click="revealPassword = !revealPassword"><EyeOff v-if="revealPassword" :size="16" /><Eye v-else :size="16" /></button></div></label>
        <button class="button primary wide" type="button" :disabled="busy || !input.trim()" @click="inspect"><RefreshCw :size="16" :class="{ spinning: busy }" />{{ busy ? '正在本地解析' : '解密并解析' }}</button>
      </div>
      <div v-if="kind === 'encrypted-private-key'" class="form-section reencrypt-section">
        <strong>口令重加密</strong>
        <label>新口令<input v-model="newPassword" type="password" autocomplete="new-password" placeholder="至少 8 个字符" /></label>
        <button class="button secondary wide" type="button" :disabled="!input || !password || !newPassword" @click="reencrypt"><LockKeyhole :size="16" />PBES2 / AES-256 重加密</button>
      </div>
      <div class="inline-alert warn">容器和口令仅在本浏览器内处理。解析私钥后请避免截图、复制到聊天工具或长期留在页面。</div>
    </section>
    <section class="generator-output">
      <div v-if="error" class="error-state"><strong>解析失败</strong><p>{{ error }}</p></div>
      <ResultPanel v-else-if="report" :report="report" />
      <div v-if="reencryptedPem" class="output-block sensitive-block"><div class="output-title"><strong>重加密私钥</strong></div><pre>{{ reencryptedPem }}</pre></div>
      <div v-if="!error && !report && !reencryptedPem" class="empty-state neutral tall"><Archive :size="28" /><strong>等待容器</strong><p>支持 PFX、JKS、CMS / PKCS#7 与加密 PKCS#8。</p></div>
    </section>
  </div>
</template>
