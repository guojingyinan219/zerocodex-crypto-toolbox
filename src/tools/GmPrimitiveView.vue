<script setup lang="ts">
import { computed, ref } from 'vue'
import { CheckCircle2, Copy, KeyRound, Play, RefreshCw, ShieldCheck, TriangleAlert } from '@lucide/vue'
import { sm2GenerateKeyPair } from 'gmkitx'
import {
  decryptSm2,
  decryptSm4Advanced,
  encryptSm2,
  encryptSm4Advanced,
  hmacSm3,
  signSm2,
  sm2Kdf,
  sm4Cmac,
  sm4Gmac,
  verifySm2,
  type DataEncoding,
  type Sm2CipherOrder,
  type Sm2SignatureEncoding,
  type Sm4AdvancedMode
} from '../core/gm-primitives'

type Tool = 'signature' | 'cipher' | 'sm3' | 'sm4'
const tool = ref<Tool>('signature')
const operation = ref<'create' | 'verify'>('create')
const privateKey = ref('')
const publicKey = ref('')
const message = ref('国密工具箱')
const dataEncoding = ref<DataEncoding>('utf8')
const userId = ref('1234567812345678')
const signatureFormat = ref<Sm2SignatureEncoding>('der')
const signature = ref('')
const cipherOrder = ref<Sm2CipherOrder>('C1C3C2')
const ciphertext = ref('')
const result = ref('')
const error = ref('')
const verification = ref<boolean>()
const copied = ref(false)

const hmacKey = ref('secret-key')
const hmacKeyEncoding = ref<DataEncoding>('utf8')
const kdfZ = ref('00112233445566778899AABBCCDDEEFF')
const kdfLength = ref(32)
const digestMode = ref<'hmac' | 'kdf'>('hmac')

const sm4Operation = ref<'encrypt' | 'decrypt' | 'cmac' | 'gmac'>('encrypt')
const sm4Mode = ref<Sm4AdvancedMode>('GCM')
const sm4Key = ref('0123456789ABCDEFFEDCBA9876543210')
const sm4Iv = ref('00112233445566778899AABB')
const sm4Data = ref('authenticated data')
const sm4DataEncoding = ref<DataEncoding>('utf8')
const sm4Aad = ref('header')
const sm4AadEncoding = ref<DataEncoding>('utf8')
const sm4Tag = ref('')
const tagLength = ref(16)

const title = computed(() => tool.value === 'signature' ? 'SM2 签名与验签' : tool.value === 'cipher' ? 'SM2 加密与解密' : tool.value === 'sm3' ? 'HMAC-SM3 与 SM2 KDF' : 'SM4 认证加密与 MAC')

function clearState() { result.value = ''; error.value = ''; verification.value = undefined; copied.value = false }
function generateKeys() { const key = sm2GenerateKeyPair(); privateKey.value = key.privateKey.toUpperCase(); publicKey.value = key.publicKey.toUpperCase(); clearState() }

function run() {
  clearState()
  try {
    if (tool.value === 'signature') {
      if (operation.value === 'create') {
        signature.value = signSm2({ privateKey: privateKey.value, message: message.value, encoding: dataEncoding.value, format: signatureFormat.value, userId: userId.value })
        result.value = signature.value
      } else {
        verification.value = verifySm2({ publicKey: publicKey.value, message: message.value, encoding: dataEncoding.value, signature: signature.value, format: signatureFormat.value, userId: userId.value })
        result.value = verification.value ? '签名有效：消息、用户 ID 与公钥匹配。' : '签名无效：请检查消息、公钥、用户 ID 和签名格式。'
      }
    } else if (tool.value === 'cipher') {
      if (operation.value === 'create') {
        ciphertext.value = encryptSm2({ publicKey: publicKey.value, message: message.value, encoding: dataEncoding.value, order: cipherOrder.value })
        result.value = ciphertext.value
      } else result.value = decryptSm2({ privateKey: privateKey.value, ciphertext: ciphertext.value, order: cipherOrder.value, output: dataEncoding.value })
    } else if (tool.value === 'sm3') {
      result.value = digestMode.value === 'hmac'
        ? hmacSm3(hmacKey.value, message.value, hmacKeyEncoding.value, dataEncoding.value)
        : sm2Kdf(kdfZ.value, kdfLength.value)
    } else if (sm4Operation.value === 'cmac') result.value = sm4Cmac(sm4Key.value, sm4DataEncoding.value === 'hex' ? sm4Data.value : Array.from(new TextEncoder().encode(sm4Data.value), (item) => item.toString(16).padStart(2, '0')).join(''))
    else if (sm4Operation.value === 'gmac') result.value = sm4Gmac(sm4Key.value, sm4Iv.value, sm4Aad.value, sm4AadEncoding.value, tagLength.value)
    else if (sm4Operation.value === 'encrypt') {
      const encrypted = encryptSm4Advanced({ mode: sm4Mode.value, key: sm4Key.value, iv: sm4Iv.value, data: sm4Data.value, encoding: sm4DataEncoding.value, aad: sm4Aad.value, aadEncoding: sm4AadEncoding.value, tagLength: tagLength.value })
      sm4Tag.value = encrypted.tag
      result.value = encrypted.ciphertext
    } else result.value = decryptSm4Advanced({ mode: sm4Mode.value, key: sm4Key.value, iv: sm4Iv.value, ciphertext: sm4Data.value, aad: sm4Aad.value, aadEncoding: sm4AadEncoding.value, tag: sm4Tag.value, tagLength: tagLength.value, output: sm4DataEncoding.value })
  } catch (cause) { error.value = cause instanceof Error ? cause.message : '国密运算失败。' }
}

function setTool(value: Tool) { tool.value = value; operation.value = 'create'; clearState() }
function setSm4Mode(value: Sm4AdvancedMode) { sm4Mode.value = value; sm4Iv.value = value === 'CTR' ? '00000000000000000000000000000001' : '00112233445566778899AABB'; clearState() }
async function copyResult() { if (!result.value) return; await navigator.clipboard.writeText(result.value); copied.value = true; window.setTimeout(() => { copied.value = false }, 1200) }
</script>

<template>
  <section class="gm-primitive-shell">
    <div class="cipher-selector gm-primitive-selector" role="tablist" aria-label="国密基础运算">
      <button type="button" :class="{ active: tool === 'signature' }" @click="setTool('signature')"><ShieldCheck :size="18" /><span><strong>SM2 签验签</strong><small>RAW / DER · 用户 ID</small></span></button>
      <button type="button" :class="{ active: tool === 'cipher' }" @click="setTool('cipher')"><KeyRound :size="18" /><span><strong>SM2 加解密</strong><small>C1C3C2 / C1C2C3</small></span></button>
      <button type="button" :class="{ active: tool === 'sm3' }" @click="setTool('sm3')"><RefreshCw :size="18" /><span><strong>SM3 派生</strong><small>HMAC / SM2 KDF</small></span></button>
      <button type="button" :class="{ active: tool === 'sm4' }" @click="setTool('sm4')"><ShieldCheck :size="18" /><span><strong>SM4 AEAD / MAC</strong><small>CTR / GCM / CCM</small></span></button>
    </div>

    <div class="generator-layout gm-primitive-layout">
      <section class="form-pane">
        <div class="form-section">
          <div class="sm2-convert-heading"><p class="eyebrow">核心国密能力</p><h2>{{ title }}</h2></div>

          <template v-if="tool === 'signature' || tool === 'cipher'">
            <div class="segmented compact-segmented gm-full-segmented"><button type="button" :class="{ active: operation === 'create' }" @click="operation = 'create'; clearState()">{{ tool === 'signature' ? '签名' : '加密' }}</button><button type="button" :class="{ active: operation === 'verify' }" @click="operation = 'verify'; clearState()">{{ tool === 'signature' ? '验签' : '解密' }}</button></div>
            <button class="button secondary" type="button" @click="generateKeys"><KeyRound :size="15" />生成测试密钥对</button>
            <label v-if="operation === 'create' && tool === 'signature' || operation === 'verify' && tool === 'cipher'">私钥 D<input v-model="privateKey" class="mono" type="password" autocomplete="off" placeholder="64 位 Hex" /></label>
            <label v-else>公钥<input v-model="publicKey" class="mono" spellcheck="false" placeholder="04 || X || Y" /></label>
            <label v-if="!(tool === 'cipher' && operation === 'verify')">消息<span class="inline-field-control textarea-control"><textarea v-model="message" rows="4" class="mono" /><select v-model="dataEncoding"><option value="utf8">文本</option><option value="hex">Hex</option></select></span></label>
            <template v-if="tool === 'signature'">
              <label>用户 ID<input v-model="userId" class="mono" /></label>
              <label>签名格式<select v-model="signatureFormat"><option value="der">ASN.1 DER</option><option value="raw">RAW（r || s）</option></select></label>
              <label v-if="operation === 'verify'">待验证签名<textarea v-model="signature" rows="4" class="mono" /></label>
            </template>
            <template v-else>
              <label>密文顺序<select v-model="cipherOrder"><option>C1C3C2</option><option>C1C2C3</option></select></label>
              <label v-if="operation === 'verify'">待解密密文<textarea v-model="ciphertext" rows="5" class="mono" /></label>
            </template>
          </template>

          <template v-else-if="tool === 'sm3'">
            <div class="segmented compact-segmented gm-full-segmented"><button type="button" :class="{ active: digestMode === 'hmac' }" @click="digestMode = 'hmac'; clearState()">HMAC-SM3</button><button type="button" :class="{ active: digestMode === 'kdf' }" @click="digestMode = 'kdf'; clearState()">SM2 KDF</button></div>
            <template v-if="digestMode === 'hmac'"><label>认证密钥<span class="inline-field-control"><input v-model="hmacKey" class="mono" /><select v-model="hmacKeyEncoding"><option value="utf8">文本</option><option value="hex">Hex</option></select></span></label><label>消息<span class="inline-field-control textarea-control"><textarea v-model="message" rows="5" class="mono" /><select v-model="dataEncoding"><option value="utf8">文本</option><option value="hex">Hex</option></select></span></label></template>
            <template v-else><label>共享秘密 Z<textarea v-model="kdfZ" rows="4" class="mono" /></label><label>输出长度（字节）<input v-model.number="kdfLength" type="number" min="1" max="8192" /></label></template>
          </template>

          <template v-else>
            <div class="segmented compact-segmented gm-full-segmented"><button v-for="item in ['encrypt','decrypt','cmac','gmac'] as const" :key="item" type="button" :class="{ active: sm4Operation === item }" @click="sm4Operation = item; clearState()">{{ { encrypt:'加密', decrypt:'解密', cmac:'CMAC', gmac:'GMAC' }[item] }}</button></div>
            <div v-if="sm4Operation === 'encrypt' || sm4Operation === 'decrypt'" class="segmented compact-segmented gm-full-segmented"><button v-for="item in ['CTR','GCM','CCM'] as Sm4AdvancedMode[]" :key="item" type="button" :class="{ active: sm4Mode === item }" @click="setSm4Mode(item)">{{ item }}</button></div>
            <label>SM4 密钥<input v-model="sm4Key" class="mono" /></label>
            <label v-if="sm4Operation !== 'cmac'">IV / Nonce<input v-model="sm4Iv" class="mono" /></label>
            <label v-if="sm4Operation === 'encrypt' || sm4Operation === 'decrypt' || sm4Operation === 'cmac'">{{ sm4Operation === 'decrypt' ? '密文' : '数据' }}<span class="inline-field-control textarea-control"><textarea v-model="sm4Data" rows="4" class="mono" /><select v-model="sm4DataEncoding"><option value="utf8">文本</option><option value="hex">Hex</option></select></span></label>
            <label v-if="sm4Operation === 'gmac' || sm4Mode !== 'CTR'">附加认证数据 AAD<span class="inline-field-control"><input v-model="sm4Aad" class="mono" /><select v-model="sm4AadEncoding"><option value="utf8">文本</option><option value="hex">Hex</option></select></span></label>
            <label v-if="sm4Operation === 'decrypt' && sm4Mode !== 'CTR'">认证标签<input v-model="sm4Tag" class="mono" /></label>
          </template>

          <div class="inline-alert warn"><TriangleAlert :size="16" /><span>私钥、认证密钥与明文仅在当前页面内存中处理。生产密钥应由 HSM、密码机或受控密钥系统管理。</span></div>
          <button class="button primary wide" type="button" @click="run"><Play :size="16" />执行运算</button>
          <div v-if="error" class="inline-alert fail">{{ error }}</div>
        </div>
      </section>

      <section class="generator-output">
        <article v-if="result" class="output-block artifact-block"><div class="output-title"><div><span class="type-badge accent">RESULT</span><strong>{{ verification === undefined ? '运算结果' : verification ? '验签通过' : '验签失败' }}</strong></div><button class="icon-button compact" type="button" title="复制结果" @click="copyResult"><CheckCircle2 v-if="copied" :size="16" /><Copy v-else :size="16" /></button></div><pre>{{ result }}</pre><div v-if="sm4Tag && tool === 'sm4'" class="output-title"><strong>认证标签 Tag</strong><code>{{ sm4Tag }}</code></div></article>
        <div v-else class="empty-state neutral tall"><ShieldCheck :size="28" /><strong>等待国密运算</strong><p>结果默认使用大写 Hex；验签会给出明确的通过或失败结论。</p></div>
      </section>
    </div>
  </section>
</template>
