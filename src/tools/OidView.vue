<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { Search, Copy, BookOpen } from '@lucide/vue'
import { oidRecords } from '../data/oids'
import type { OidRecord } from '../types'

const query = ref('')
const scope = ref<'全部体系' | '国密体系' | '通用体系'>('全部体系')
const category = ref('全部分类')
const selected = ref<OidRecord>(oidRecords.find((item) => item.oid === '1.2.156.10197.1.501')!)
const categoryOrder = ['公钥算法', '密钥协商', '后量子算法', '椭圆曲线', '签名算法', '摘要算法', 'MAC 算法', '对称密码', '密钥封装', 'KDF / PBE', 'PKCS / CMS 容器', 'PKCS 属性', 'DN 属性', '证书扩展', '扩展密钥用途', 'PKIX 服务']
const isGmOid = (oid: string) => oid === '1.2.156.10197' || oid.startsWith('1.2.156.10197.')
const scopedRecords = computed(() => oidRecords.filter((record) => scope.value === '全部体系' || (scope.value === '国密体系' ? isGmOid(record.oid) : !isGmOid(record.oid))))
const categories = computed(() => ['全部分类', ...Array.from(new Set(scopedRecords.value.map((item) => item.category))).sort((a, b) => categoryOrder.indexOf(a) - categoryOrder.indexOf(b))])
const results = computed(() => {
  const needle = query.value.trim().toLowerCase()
  return scopedRecords.value.filter((record) => {
    const inCategory = category.value === '全部分类' || record.category === category.value
    const inSearch = !needle || [record.oid, record.name, record.english, record.standard, record.description].some((value) => value.toLowerCase().includes(needle))
    return inCategory && inSearch
  })
})

watch(scope, () => {
  if (!categories.value.includes(category.value)) category.value = '全部分类'
})

watch(results, (records) => {
  if (records.length && !records.some((record) => record.oid === selected.value.oid)) selected.value = records[0]
})

async function copyOid() {
  await navigator.clipboard.writeText(selected.value.oid)
}
</script>

<template>
  <div class="tool-view oid-view">
    <header class="page-header compact-header"><div><p class="eyebrow">F12 · 密码体系数据字典</p><h1>国密与通用密码 OID 查询</h1><p>覆盖 SM 系列、RSA、ECC、EdDSA、DH、AES、PKCS、X.509 与后量子算法。</p></div></header>
    <div class="reference-toolbar">
      <label class="search-field"><Search :size="17" /><input v-model="query" placeholder="搜索 OID、算法、标准或用途" /></label>
      <select v-model="scope" aria-label="密码体系"><option>全部体系</option><option>国密体系</option><option>通用体系</option></select>
      <select v-model="category" aria-label="OID 类别"><option v-for="item in categories" :key="item">{{ item }}</option></select>
      <span>{{ results.length }} / {{ oidRecords.length }} 条</span>
    </div>
    <div class="reference-layout">
      <section class="oid-table-wrap">
        <table class="oid-table"><thead><tr><th>OID</th><th>名称</th><th>类别</th><th>标准</th></tr></thead><tbody><tr v-for="record in results" :key="record.oid" :class="{ selected: selected.oid === record.oid }" tabindex="0" @click="selected = record" @keydown.enter="selected = record"><td><code>{{ record.oid }}</code></td><td><strong>{{ record.name }}</strong><span>{{ record.english }}</span></td><td>{{ record.category }}</td><td>{{ record.standard }}</td></tr></tbody></table>
      </section>
      <aside class="oid-detail">
        <BookOpen :size="22" />
        <p class="eyebrow">{{ isGmOid(selected.oid) ? '国密体系' : '通用体系' }} · {{ selected.category }}</p>
        <h2>{{ selected.name }}</h2>
        <div class="oid-code"><code>{{ selected.oid }}</code><button class="icon-button compact" type="button" title="复制 OID" @click="copyOid"><Copy :size="15" /></button></div>
        <dl><dt>英文名</dt><dd>{{ selected.english }}</dd><dt>所属标准</dt><dd>{{ selected.standard }}</dd><dt>说明</dt><dd>{{ selected.description }}</dd></dl>
      </aside>
    </div>
  </div>
</template>
