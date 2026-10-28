<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import {
  ShieldCheck,
  ScanSearch,
  Braces,
  BadgeCheck,
  KeyRound,
  Lock,
  ArrowRightLeft,
  UsersRound,
  Wrench,
  BookOpen,
  Info,
  LockKeyhole,
  House,
  Dices
} from '@lucide/vue'
import OverviewView from './tools/OverviewView.vue'
import WorkbenchView from './tools/WorkbenchView.vue'
import Asn1View from './tools/Asn1View.vue'
import MatchView from './tools/MatchView.vue'
import GenerateView from './tools/GenerateView.vue'
import ConvertView from './tools/ConvertView.vue'
import GmAdvancedView from './tools/GmAdvancedView.vue'
import CommonToolsView from './tools/CommonToolsView.vue'
import SymmetricView from './tools/SymmetricView.vue'
import OidView from './tools/OidView.vue'
import AboutView from './tools/AboutView.vue'
import { commonToolIds, getToolHref, getToolIdFromPath, isToolId, updateSeoMetadata, type CommonToolId, type ToolId } from './seo'
import type { ParseReport } from './types'

const toolItems = [
  { id: 'home' as const, label: '首页', caption: '全部能力', icon: House },
  { id: 'workbench' as const, label: '证书工作台', caption: '国密 / RSA 识别', icon: ScanSearch },
  { id: 'asn1' as const, label: 'ASN.1 查看器', caption: 'DER 结构树', icon: Braces },
  { id: 'match' as const, label: '匹配校验', caption: '证书 / CSR / 私钥', icon: BadgeCheck },
  { id: 'generate' as const, label: '证书生成', caption: 'SM2 / RSA · CSR', icon: KeyRound },
  { id: 'convert' as const, label: '编码转换', caption: 'PEM / DER / X·Y·D', icon: ArrowRightLeft },
  { id: 'gm' as const, label: '国密运算', caption: 'SM3 / SM2 协商', icon: UsersRound },
  { id: 'symmetric' as const, label: '对称密码', caption: 'SM4 / AES / DES', icon: Lock },
  { id: 'base64' as const, label: 'Base64', caption: 'UTF-8 / Base64', icon: Wrench },
  { id: 'url' as const, label: 'URL 编码', caption: '转义 / 还原', icon: Wrench },
  { id: 'hex' as const, label: '文本 / Hex', caption: '文本 / 十六进制', icon: Wrench },
  { id: 'json' as const, label: 'JSON 工具', caption: '格式化 / 校验 / 压缩', icon: Braces },
  { id: 'digest' as const, label: '摘要计算', caption: 'SM3 / SHA / MD5', icon: Wrench },
  { id: 'uuid' as const, label: 'UUID 生成', caption: 'UUID v4', icon: Wrench },
  { id: 'random' as const, label: '随机数生成', caption: '字符串 / 整数 / 字节', icon: Dices },
  { id: 'doctor' as const, label: '格式体检', caption: 'PEM / Base64 规范化', icon: Wrench },
  { id: 'tls' as const, label: '网站安全检测', caption: 'TLS / Web / TLCP', icon: ShieldCheck },
  { id: 'oids' as const, label: 'OID 字典', caption: '国密 / RSA / ECC / PKI', icon: BookOpen },
  { id: 'about' as const, label: '关于', caption: '隐私与边界', icon: Info }
]

const active = ref<ToolId>('home')
const sharedInput = ref('')
const activeMeta = computed(() => toolItems.find((item) => item.id === active.value) ?? toolItems[0])
const toolCategories: Partial<Record<ToolId, string>> = {
  workbench: '证书与密钥',
  asn1: '证书与密钥',
  match: '证书与密钥',
  generate: '证书与密钥',
  convert: '证书与密钥',
  gm: '国密与密码',
  symmetric: '国密与密码',
  base64: '开发与编码',
  url: '开发与编码',
  hex: '开发与编码',
  json: '开发与编码',
  digest: '开发与编码',
  uuid: '开发与编码',
  random: '开发与编码',
  common: '开发与编码',
  doctor: '诊断与标准',
  tls: '诊断与标准',
  oids: '诊断与标准'
}
const activeCategory = computed(() => toolCategories[active.value])
const isCommonTool = computed(() => commonToolIds.includes(active.value as CommonToolId))
const commonMode = computed<CommonToolId>(() => commonToolIds.includes(active.value as CommonToolId) ? active.value as CommonToolId : 'base64')

function navigate(id: ToolId, input?: string) {
  const target = id === 'common' ? 'base64' : id
  active.value = target
  if (input !== undefined) sharedInput.value = input
  window.history.pushState({ tool: target }, '', getToolHref(target))
  window.scrollTo({ top: 0, behavior: 'smooth' })
}

function inspectAsn1(payload: { report: ParseReport; text: string }) {
  const text = payload.report.pemLabel ? payload.text : btoa(String.fromCharCode(...payload.report.bytes))
  navigate('asn1', text)
}

function syncLocation() {
  const queryId = new URLSearchParams(window.location.search).get('tool')
  const hashId = window.location.hash.replace('#', '')
  const pathId = getToolIdFromPath(window.location.pathname)
  const requested = pathId ?? (isToolId(queryId) ? queryId : isToolId(hashId) ? hashId : 'home')
  const id = requested === 'common' ? 'base64' : requested
  active.value = id

  if (!pathId && (isToolId(queryId) || isToolId(hashId))) {
    window.history.replaceState({ tool: id }, '', getToolHref(id))
  }
}

onMounted(() => {
  syncLocation()
  window.addEventListener('hashchange', syncLocation)
  window.addEventListener('popstate', syncLocation)
})

onUnmounted(() => {
  window.removeEventListener('hashchange', syncLocation)
  window.removeEventListener('popstate', syncLocation)
})

watch(active, updateSeoMetadata, { immediate: true })
</script>

<template>
  <div class="app-shell">
    <header class="app-nav">
      <a class="brand-row" :href="getToolHref('home')" aria-label="返回全部工具" @click.prevent="navigate('home')">
        <div class="brand-mark"><ShieldCheck :size="23" /></div>
        <div class="brand-copy"><strong>密码与证书工具箱</strong><span>ZeroCodeX Crypto Toolkit</span></div>
      </a>
      <div class="top-actions">
        <a class="top-action" :class="{ active: active === 'home' }" :href="getToolHref('home')" :aria-current="active === 'home' ? 'page' : undefined" @click.prevent="navigate('home')">
          <House :size="17" />
          <span>全部工具</span>
        </a>
        <div class="nav-security" title="证书、私钥和密码材料默认仅在当前浏览器中处理">
          <LockKeyhole :size="17" />
          <span><strong>本地处理</strong><small>敏感材料不上传</small></span>
        </div>
        <a class="top-action" :class="{ active: active === 'about' }" :href="getToolHref('about')" :aria-current="active === 'about' ? 'page' : undefined" @click.prevent="navigate('about')">
          <Info :size="17" />
          <span>关于</span>
        </a>
      </div>
    </header>

    <main class="app-main">
      <OverviewView v-if="active === 'home'" @open="navigate" />
      <nav v-else class="view-breadcrumb" aria-label="面包屑导航">
        <a :href="getToolHref('home')" @click.prevent="navigate('home')">首页</a>
        <span aria-hidden="true">/</span>
        <span v-if="activeCategory">{{ activeCategory }}</span>
        <span v-if="activeCategory" aria-hidden="true">/</span>
        <strong aria-current="page">{{ activeMeta.label }}</strong>
      </nav>
      <KeepAlive>
        <WorkbenchView v-if="active === 'workbench'" :initial-input="sharedInput" @open-asn1="inspectAsn1" @open-doctor="navigate('doctor', $event)" />
      </KeepAlive>
      <Asn1View v-if="active === 'asn1'" :key="`asn1-${sharedInput.length}`" :initial-input="sharedInput" />
      <MatchView v-if="active === 'match'" />
      <GenerateView v-if="active === 'generate'" />
      <ConvertView v-if="active === 'convert'" />
      <GmAdvancedView v-if="active === 'gm'" />
      <SymmetricView v-if="active === 'symmetric'" />
      <CommonToolsView v-if="isCommonTool" :mode="commonMode" :initial-input="sharedInput" />
      <OidView v-if="active === 'oids'" />
      <AboutView v-if="active === 'about'" />
      <footer class="product-footer" aria-label="网站归属与备案信息">
        <div class="product-owner">
          <span>© 2026</span>
          <a href="https://www.zerocodex.top/" target="_blank" rel="noopener noreferrer">零码工作室旗下产品</a>
        </div>
        <div class="product-legal">
          <span>零码密码与证书工具箱</span>
          <a href="https://beian.miit.gov.cn/" target="_blank" rel="noopener noreferrer">苏ICP备2026080292号-1</a>
        </div>
      </footer>
    </main>
  </div>
</template>
