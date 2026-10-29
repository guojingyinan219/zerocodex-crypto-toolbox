<script setup lang="ts">
import {
  ArrowRight,
  ArrowRightLeft,
  BadgeCheck,
  Binary,
  BookOpen,
  Braces,
  FileCheck2,
  Fingerprint,
  Globe2,
  Hash,
  KeyRound,
  Link2,
  Lock,
  ScanSearch,
  Sparkles,
  Dices,
} from '@lucide/vue'
import { getToolHref, type ToolId } from '../seo'

type ToolCard = {
  id: ToolId
  title: string
  description: string
  meta: string
  icon: typeof ScanSearch
  tone: 'green' | 'blue' | 'amber' | 'ink'
  featured?: boolean
  label?: string
}

defineEmits<{ open: [id: ToolId] }>()

const certificateTools: ToolCard[] = [
  { id: 'workbench', title: '证书工作台', description: '识别并解析 X.509 证书、CSR、公钥与私钥，集中查看算法、指纹和密钥材料。', meta: 'SM2 / RSA / ECC', icon: ScanSearch, tone: 'green', featured: true, label: '核心入口' },
  { id: 'generate', title: '证书与密钥生成', description: '生成密钥对、CSR、自签证书及完整 CA 签发链。', meta: 'CSR / CA / PKCS#8', icon: KeyRound, tone: 'blue' },
  { id: 'match', title: '证书与密钥匹配检查', description: '检查证书、CSR、公钥和私钥是否相互配套。', meta: '证书 / CSR / 公钥 / 私钥', icon: BadgeCheck, tone: 'amber' },
  { id: 'asn1', title: 'ASN.1 查看器', description: '逐层检查 DER 节点、长度、偏移与原始字节。', meta: 'DER / TLV / Hex', icon: Braces, tone: 'ink' },
  { id: 'convert', title: '密钥格式转换', description: '在 PEM、DER、Base64、Hex 与 SM2 X/Y/D 之间转换。', meta: 'PEM / DER / X·Y·D', icon: ArrowRightLeft, tone: 'green' }
]

const cryptoTools: ToolCard[] = [
  { id: 'gm', title: '国密核心运算', description: '覆盖 SM2 签验签与加解密、SM3、SM4 AEAD/MAC、HMAC、KDF 和密钥协商。', meta: 'SM2 / SM3 / SM4', icon: Fingerprint, tone: 'green', label: '完整能力' },
  { id: 'symmetric', title: '对称密码工作台', description: '统一完成 SM4、AES、DES、3DES 加解密和常用 MAC 运算。', meta: '加密 / 解密 / MAC', icon: Lock, tone: 'blue' }
]

const developmentTools: ToolCard[] = [
  { id: 'base64', title: 'Base64 转换', description: 'UTF-8 文本与 Base64、Base64URL 编码互转。', meta: '编码 / 解码', icon: Binary, tone: 'green' },
  { id: 'url', title: 'URL 编码', description: '处理 URL 参数中的中文、特殊字符和百分号转义。', meta: '转义 / 还原', icon: Link2, tone: 'blue' },
  { id: 'hex', title: '文本与 Hex', description: 'UTF-8 文本与十六进制数据双向转换。', meta: 'UTF-8 / Hex', icon: Hash, tone: 'amber' },
  { id: 'json', title: 'JSON 工具', description: '格式化、校验或压缩 JSON 数据。', meta: '格式化 / 校验 / 压缩', icon: Braces, tone: 'ink' },
  { id: 'digest', title: '摘要计算', description: '计算 SM3、SHA 系列、MD4 与 MD5 文本摘要。', meta: 'SM3 / SHA / MD5', icon: Fingerprint, tone: 'green' },
  { id: 'uuid', title: 'UUID v4', description: '使用浏览器加密随机源生成标准 UUID。', meta: '随机标识 / 本地生成', icon: Sparkles, tone: 'blue' },
  { id: 'random', title: '安全随机数', description: '生成 32 位随机字符串、无偏差整数和编码随机字节。', meta: '字母 / 数字 / 特殊字符', icon: Dices, tone: 'green' }
]

const securityTools: ToolCard[] = [
  { id: 'tls', title: '网站安全检测', description: '集中检查证书链、TLS 协议、Web 策略和常见访问风险。', meta: 'TLS / HSTS / CAA / TLCP', icon: Globe2, tone: 'blue' },
  { id: 'doctor', title: '格式体检', description: '定位 PEM、Base64、Hex 的换行、标签与编码问题。', meta: '检查 / 规范化 / 修复', icon: FileCheck2, tone: 'amber' },
  { id: 'oids', title: '密码 OID 字典', description: '查询国密、RSA、ECC、PKCS、X.509 与后量子算法标识。', meta: '标准 / 算法 / PKI', icon: BookOpen, tone: 'ink' }
]
</script>

<template>
  <div class="overview-view">
    <section class="overview-section">
      <div class="overview-section-heading"><div><p class="eyebrow">CERTIFICATE &amp; KEY</p><h2>证书与密钥</h2></div><p>围绕材料全生命周期组织的核心工作流</p></div>
      <div class="tool-card-grid certificate-grid">
        <a v-for="tool in certificateTools" :key="tool.id" :href="getToolHref(tool.id)" class="tool-card" :class="[{ featured: tool.featured, labeled: tool.label }, `tone-${tool.tone}`]" @click.prevent="$emit('open', tool.id)">
          <div class="tool-card-heading"><div class="tool-card-icon"><component :is="tool.icon" :size="tool.featured ? 25 : 21" /></div><h3>{{ tool.title }}</h3></div>
          <span v-if="tool.label" class="tool-card-label">{{ tool.label }}</span>
          <div class="tool-card-copy"><p>{{ tool.description }}</p></div>
          <div class="tool-card-footer"><span>{{ tool.meta }}</span><ArrowRight :size="17" /></div>
        </a>
      </div>
    </section>

    <section class="overview-section">
      <div class="overview-section-heading"><div><p class="eyebrow">CRYPTOGRAPHY</p><h2>国密与密码算法</h2></div><p>覆盖常用标准算法、工作模式与协议运算</p></div>
      <div class="tool-card-grid crypto-grid">
        <a v-for="tool in cryptoTools" :key="tool.title" :href="getToolHref(tool.id)" class="tool-card" :class="[{ featured: tool.featured, labeled: tool.label }, `tone-${tool.tone}`]" @click.prevent="$emit('open', tool.id)">
          <div class="tool-card-heading"><div class="tool-card-icon"><component :is="tool.icon" :size="tool.featured ? 25 : 21" /></div><h3>{{ tool.title }}</h3></div>
          <span v-if="tool.label" class="tool-card-label">{{ tool.label }}</span>
          <div class="tool-card-copy"><p>{{ tool.description }}</p></div>
          <div class="tool-card-footer"><span>{{ tool.meta }}</span><ArrowRight :size="17" /></div>
        </a>
      </div>
    </section>

    <section class="overview-section">
      <div class="overview-section-heading"><div><p class="eyebrow">DEVELOPMENT &amp; ENCODING</p><h2>开发与编码</h2></div><p>每项能力独立进入，快速找到日常转换与数据处理工具</p></div>
      <div class="tool-card-grid developer-grid">
        <a v-for="tool in developmentTools" :key="tool.id" :href="getToolHref(tool.id)" class="tool-card compact-card" :class="`tone-${tool.tone}`" @click.prevent="$emit('open', tool.id)">
          <div class="tool-card-heading"><div class="tool-card-icon"><component :is="tool.icon" :size="20" /></div><h3>{{ tool.title }}</h3></div>
          <div class="tool-card-copy"><p>{{ tool.description }}</p></div>
          <div class="tool-card-footer"><span>{{ tool.meta }}</span><ArrowRight :size="17" /></div>
        </a>
      </div>
    </section>

    <section class="overview-section compact-section">
      <div class="overview-section-heading"><div><p class="eyebrow">SECURITY &amp; STANDARD</p><h2>诊断与标准</h2></div><p>把常见排错和标准查询放在触手可及的位置</p></div>
      <div class="tool-card-grid security-grid">
        <a v-for="tool in securityTools" :key="tool.title" :href="getToolHref(tool.id)" class="tool-card compact-card" :class="`tone-${tool.tone}`" @click.prevent="$emit('open', tool.id)">
          <div class="tool-card-heading"><div class="tool-card-icon"><component :is="tool.icon" :size="20" /></div><h3>{{ tool.title }}</h3></div>
          <div class="tool-card-copy"><p>{{ tool.description }}</p></div>
          <div class="tool-card-footer"><span>{{ tool.meta }}</span><ArrowRight :size="17" /></div>
        </a>
      </div>
    </section>
  </div>
</template>
