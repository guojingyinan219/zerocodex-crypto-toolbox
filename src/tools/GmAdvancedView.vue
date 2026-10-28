<script setup lang="ts">
import { computed, onBeforeUnmount, reactive, ref } from 'vue'
import {
  AlertTriangle,
  Check,
  Copy,
  Eye,
  EyeOff,
  Fingerprint,
  KeyRound,
  Play,
  RefreshCw,
  ShieldCheck,
  UsersRound
} from '@lucide/vue'
import {
  deriveSm2PublicComponents,
  digestSm3,
  generateSm2PartyMaterial,
  runSm2KeyAgreement,
  sm2SignaturePrehash,
  type DataEncoding,
  type Sm2AgreementOutput,
  type Sm2PartyMaterial
} from '../core/gm-advanced'
import GmPrimitiveView from './GmPrimitiveView.vue'

type Mode = 'primitive' | 'sm3' | 'agreement'
type Sm3Mode = 'digest' | 'prehash'

const mode = ref<Mode>('primitive')
const sm3Mode = ref<Sm3Mode>('digest')
const dataEncoding = ref<DataEncoding>('hex')
const userIdEncoding = ref<DataEncoding>('text')
const publicX = ref('')
const publicY = ref('')
const userId = ref('1234567812345678')
const data = ref('616263')
const sm3Result = ref<{ za?: string; digest: string }>()
const sm3Error = ref('')

const self = reactive<Sm2PartyMaterial>({
  privateKey: '',
  publicX: '',
  publicY: '',
  tempPrivateKey: '',
  tempPublicX: '',
  tempPublicY: ''
})
const peer = reactive({ publicX: '', publicY: '', tempPublicX: '', tempPublicY: '' })
const isInitiator = ref(true)
const selfId = ref('Alice')
const peerId = ref('Bob')
const keyLength = ref(16)
const agreementResult = ref<Sm2AgreementOutput>()
const agreementError = ref('')
const revealPrivate = ref(false)
const revealSharedKey = ref(false)
const copied = ref('')

const selfRole = computed(() => isInitiator.value ? 'A · 发起方' : 'B · 响应方')
const peerRole = computed(() => isInitiator.value ? 'B · 响应方' : 'A · 发起方')
const receiveLabel = computed(() => isInitiator.value ? '接收确认值 S1 / SB' : '接收确认值 S2 / SA')
const sendLabel = computed(() => isInitiator.value ? '发送确认值 S2 / SA' : '发送确认值 S1 / SB')
const receiveValue = computed(() => isInitiator.value ? agreementResult.value?.s1 : agreementResult.value?.s2)
const sendValue = computed(() => isInitiator.value ? agreementResult.value?.s2 : agreementResult.value?.s1)

function runSm3() {
  sm3Error.value = ''
  try {
    if (sm3Mode.value === 'digest') {
      sm3Result.value = { digest: digestSm3(data.value, dataEncoding.value) }
      return
    }
    sm3Result.value = sm2SignaturePrehash({
      publicX: publicX.value,
      publicY: publicY.value,
      userId: userId.value,
      userIdEncoding: userIdEncoding.value,
      data: data.value,
      dataEncoding: dataEncoding.value
    })
  } catch (cause) {
    sm3Result.value = undefined
    sm3Error.value = cause instanceof Error ? cause.message : '摘要计算失败。'
  }
}

function loadSm3Example() {
  dataEncoding.value = 'hex'
  data.value = '616263'
  if (sm3Mode.value === 'prehash') {
    const material = generateSm2PartyMaterial()
    publicX.value = material.publicX
    publicY.value = material.publicY
    userId.value = '1234567812345678'
    userIdEncoding.value = 'text'
  }
  sm3Result.value = undefined
  sm3Error.value = ''
}

function applySelf(material: Sm2PartyMaterial) {
  Object.assign(self, material)
}

function generateSelf() {
  applySelf(generateSm2PartyMaterial())
  agreementResult.value = undefined
  agreementError.value = ''
}

function generatePeer() {
  const material = generateSm2PartyMaterial()
  peer.publicX = material.publicX
  peer.publicY = material.publicY
  peer.tempPublicX = material.tempPublicX
  peer.tempPublicY = material.tempPublicY
  agreementResult.value = undefined
  agreementError.value = ''
}

function generateAgreementExample() {
  generateSelf()
  generatePeer()
}

function setRole(initiator: boolean) {
  isInitiator.value = initiator
  agreementResult.value = undefined
  agreementError.value = ''
}

function runAgreement() {
  agreementError.value = ''
  revealSharedKey.value = false
  try {
    const result = runSm2KeyAgreement({
      privateKey: self.privateKey,
      tempPrivateKey: self.tempPrivateKey,
      peerPublicX: peer.publicX,
      peerPublicY: peer.publicY,
      peerTempPublicX: peer.tempPublicX,
      peerTempPublicY: peer.tempPublicY,
      userId: selfId.value,
      peerUserId: peerId.value,
      isInitiator: isInitiator.value,
      keyLength: keyLength.value
    })
    Object.assign(self, {
      publicX: result.selfPublicX,
      publicY: result.selfPublicY,
      tempPublicX: result.selfTempPublicX,
      tempPublicY: result.selfTempPublicY
    })
    agreementResult.value = result
  } catch (cause) {
    agreementResult.value = undefined
    agreementError.value = cause instanceof Error ? cause.message : 'SM2 密钥协商失败。'
  }
}

function refreshDerivedPublicKeys() {
  agreementError.value = ''
  try {
    if (self.privateKey.trim()) {
      const permanent = deriveSm2PublicComponents(self.privateKey)
      self.publicX = permanent.x
      self.publicY = permanent.y
    }
    if (self.tempPrivateKey.trim()) {
      const temporary = deriveSm2PublicComponents(self.tempPrivateKey)
      self.tempPublicX = temporary.x
      self.tempPublicY = temporary.y
    }
  } catch (cause) {
    agreementError.value = cause instanceof Error ? cause.message : '无法推导公钥。'
  }
}

async function copy(value: string | undefined, target: string) {
  if (!value) return
  await navigator.clipboard.writeText(value)
  copied.value = target
  window.setTimeout(() => {
    if (copied.value === target) copied.value = ''
  }, 1400)
}

onBeforeUnmount(() => {
  self.privateKey = ''.padStart(self.privateKey.length, '0')
  self.tempPrivateKey = ''.padStart(self.tempPrivateKey.length, '0')
  agreementResult.value = undefined
})
</script>

<template>
  <div class="tool-view gm-advanced-view">
    <header class="page-header compact-header">
      <div><p class="eyebrow">国密算法与协议</p><h1>SM2、SM3、SM4 核心运算</h1><p>覆盖签名、加密、认证摘要、密钥派生、认证加密和双方密钥协商。</p></div>
      <div class="local-only"><ShieldCheck :size="18" />私钥仅在当前页面内存中使用</div>
    </header>

    <div class="segmented gm-mode-tabs" role="tablist" aria-label="国密运算类型">
      <button type="button" :class="{ active: mode === 'primitive' }" @click="mode = 'primitive'"><ShieldCheck :size="17" />核心运算</button>
      <button type="button" :class="{ active: mode === 'sm3' }" @click="mode = 'sm3'"><Fingerprint :size="17" />SM3 与签名摘要</button>
      <button type="button" :class="{ active: mode === 'agreement' }" @click="mode = 'agreement'"><UsersRound :size="17" />SM2 密钥协商</button>
    </div>

    <GmPrimitiveView v-if="mode === 'primitive'" />

    <div v-else-if="mode === 'sm3'" class="generator-layout gm-digest-layout">
      <section class="form-pane">
        <div class="form-section">
          <div class="sm2-convert-heading"><p class="eyebrow">摘要模式</p><h2>{{ sm3Mode === 'digest' ? 'SM3 普通摘要' : 'SM2 签名前置摘要' }}</h2><p>{{ sm3Mode === 'digest' ? '直接计算 SM3(M)。' : '计算 ZA = SM3(ENTL || ID || a || b || Gx || Gy || X || Y)，再计算 SM3(ZA || M)。' }}</p></div>
          <div class="segmented compact-segmented gm-full-segmented">
            <button type="button" :class="{ active: sm3Mode === 'digest' }" @click="sm3Mode = 'digest'; sm3Result = undefined">普通 SM3</button>
            <button type="button" :class="{ active: sm3Mode === 'prehash' }" @click="sm3Mode = 'prehash'; sm3Result = undefined">SM2 签名摘要</button>
          </div>
          <template v-if="sm3Mode === 'prehash'">
            <label>公钥 X<input v-model="publicX" class="mono" spellcheck="false" placeholder="64 位 Hex" /></label>
            <label>公钥 Y<input v-model="publicY" class="mono" spellcheck="false" placeholder="64 位 Hex" /></label>
            <label>用户 ID
              <span class="inline-field-control"><input v-model="userId" class="mono" spellcheck="false" /><select v-model="userIdEncoding"><option value="text">文本</option><option value="hex">Hex</option></select></span>
            </label>
          </template>
          <label>数据 M
            <span class="inline-field-control textarea-control"><textarea v-model="data" rows="6" class="mono" spellcheck="false" placeholder="输入待摘要数据" /><select v-model="dataEncoding"><option value="hex">Hex</option><option value="text">文本</option></select></span>
          </label>
          <div class="gm-form-actions"><button class="button secondary" type="button" @click="loadSm3Example"><RefreshCw :size="16" />载入示例</button><button class="button primary" type="button" @click="runSm3"><Play :size="16" />计算摘要</button></div>
          <div v-if="sm3Error" class="inline-alert fail">{{ sm3Error }}</div>
        </div>
      </section>

      <section class="generator-output">
        <div v-if="sm3Result?.za" class="output-block">
          <div class="output-title"><div><span class="type-badge">ZA</span><strong>用户身份摘要</strong></div><button class="icon-button compact" type="button" title="复制 ZA" @click="copy(sm3Result.za, 'za')"><Check v-if="copied === 'za'" :size="16" /><Copy v-else :size="16" /></button></div>
          <pre>{{ sm3Result.za }}</pre>
        </div>
        <div v-if="sm3Result" class="output-block artifact-block">
          <div class="output-title"><div><span class="type-badge accent">SM3</span><strong>{{ sm3Result.za ? '签名摘要 e = SM3(ZA || M)' : 'SM3 摘要' }}</strong></div><button class="icon-button compact" type="button" title="复制摘要" @click="copy(sm3Result.digest, 'digest')"><Check v-if="copied === 'digest'" :size="16" /><Copy v-else :size="16" /></button></div>
          <pre>{{ sm3Result.digest }}</pre>
        </div>
        <div v-if="!sm3Result" class="empty-state neutral tall"><Fingerprint :size="28" /><strong>等待摘要计算</strong><p>结果以 32 字节大写 Hex 显示。</p></div>
      </section>
    </div>

    <section v-else-if="mode === 'agreement'" class="agreement-shell">
      <div class="agreement-toolbar">
        <div><p class="eyebrow">GM/T 0003.3</p><h2>双方认证密钥协商</h2></div>
        <div class="segmented compact-segmented" aria-label="己方角色"><button type="button" :class="{ active: isInitiator }" @click="setRole(true)">作为 A 发起</button><button type="button" :class="{ active: !isInitiator }" @click="setRole(false)">作为 B 响应</button></div>
        <button class="button secondary" type="button" @click="generateAgreementExample"><RefreshCw :size="16" />生成完整示例</button>
      </div>

      <div class="agreement-parties">
        <section class="agreement-party-pane">
          <div class="party-heading"><div><span class="type-badge">SELF</span><strong>己方 {{ selfRole }}</strong></div><div><button class="icon-button compact" type="button" :title="revealPrivate ? '隐藏己方私钥' : '显示己方私钥'" @click="revealPrivate = !revealPrivate"><EyeOff v-if="revealPrivate" :size="16" /><Eye v-else :size="16" /></button><button class="button small secondary" type="button" @click="generateSelf"><KeyRound :size="15" />生成己方密钥</button></div></div>
          <div class="agreement-fields">
            <label class="span-2">长期私钥 D<input v-model="self.privateKey" :type="revealPrivate ? 'text' : 'password'" class="mono" spellcheck="false" @blur="refreshDerivedPublicKeys" /></label>
            <label>长期公钥 X<input v-model="self.publicX" class="mono" readonly /></label>
            <label>长期公钥 Y<input v-model="self.publicY" class="mono" readonly /></label>
            <label class="span-2">临时私钥 r<input v-model="self.tempPrivateKey" :type="revealPrivate ? 'text' : 'password'" class="mono" spellcheck="false" @blur="refreshDerivedPublicKeys" /></label>
            <label>临时公钥 Rx<input v-model="self.tempPublicX" class="mono" readonly /></label>
            <label>临时公钥 Ry<input v-model="self.tempPublicY" class="mono" readonly /></label>
          </div>
        </section>

        <section class="agreement-party-pane peer-pane">
          <div class="party-heading"><div><span class="type-badge accent">PEER</span><strong>对方 {{ peerRole }}</strong></div><button class="button small secondary" type="button" @click="generatePeer"><KeyRound :size="15" />生成测试公钥</button></div>
          <div class="agreement-fields">
            <label>长期公钥 X<input v-model="peer.publicX" class="mono" spellcheck="false" /></label>
            <label>长期公钥 Y<input v-model="peer.publicY" class="mono" spellcheck="false" /></label>
            <label>临时公钥 Rx<input v-model="peer.tempPublicX" class="mono" spellcheck="false" /></label>
            <label>临时公钥 Ry<input v-model="peer.tempPublicY" class="mono" spellcheck="false" /></label>
            <div class="span-2 inline-alert info"><span>对方私钥不应传输。协商只需要对方的长期公钥和本次会话临时公钥。</span></div>
          </div>
        </section>
      </div>

      <div class="agreement-settings">
        <label>己方用户 ID<input v-model="selfId" /></label>
        <label>对方用户 ID<input v-model="peerId" /></label>
        <label>密钥长度（字节）<input v-model.number="keyLength" type="number" min="1" max="1024" /></label>
        <button class="button primary" type="button" @click="runAgreement"><Play :size="16" />执行 {{ isInitiator ? 'A' : 'B' }} 方协商</button>
      </div>
      <div v-if="agreementError" class="inline-alert fail agreement-error">{{ agreementError }}</div>

      <div v-if="agreementResult" class="agreement-results">
        <article class="output-block sensitive-block">
          <div class="output-title"><div><span class="type-badge">K</span><strong>派生共享密钥</strong></div><div><button class="icon-button compact" type="button" :title="revealSharedKey ? '隐藏共享密钥' : '显示共享密钥'" @click="revealSharedKey = !revealSharedKey"><EyeOff v-if="revealSharedKey" :size="16" /><Eye v-else :size="16" /></button><button class="icon-button compact" type="button" title="复制共享密钥" @click="copy(agreementResult.sharedKey, 'shared')"><Check v-if="copied === 'shared'" :size="16" /><Copy v-else :size="16" /></button></div></div>
          <pre :class="{ blurred: !revealSharedKey }">{{ agreementResult.sharedKey }}</pre>
        </article>
        <article class="output-block">
          <div class="output-title"><strong>{{ receiveLabel }}</strong><button class="icon-button compact" type="button" title="复制接收确认值" @click="copy(receiveValue, 'receive')"><Check v-if="copied === 'receive'" :size="16" /><Copy v-else :size="16" /></button></div>
          <pre>{{ receiveValue }}</pre>
        </article>
        <article class="output-block">
          <div class="output-title"><strong>{{ sendLabel }}</strong><button class="icon-button compact" type="button" title="复制发送确认值" @click="copy(sendValue, 'send')"><Check v-if="copied === 'send'" :size="16" /><Copy v-else :size="16" /></button></div>
          <pre>{{ sendValue }}</pre>
        </article>
      </div>
      <div v-else class="agreement-empty"><AlertTriangle :size="20" /><span>请先准备双方长期密钥与临时密钥。使用“生成完整示例”可以快速验证 A/B 协商流程。</span></div>
    </section>
  </div>
</template>
