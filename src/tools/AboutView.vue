<script setup lang="ts">
import { ShieldCheck, WifiOff, Database, TriangleAlert, HeartHandshake, LockKeyhole } from '@lucide/vue'
</script>

<template>
  <div class="tool-view about-view">
    <header class="page-header compact-header"><div><p class="eyebrow">关于与隐私</p><h1>工具在本地运行，材料不出浏览器</h1><p>面向开发、运维与测试人员的国密、RSA 与通用 PKI 工作台。</p></div></header>
    <section class="principle-grid">
      <article><ShieldCheck :size="22" /><h2>不上传</h2><p>证书、CSR 和私钥不经过后端接口。</p></article>
      <article><Database :size="22" /><h2>不持久化</h2><p>不写入 localStorage、IndexedDB、Cookie 或分析日志。</p></article>
      <article><WifiOff :size="22" /><h2>可离线</h2><p>首次载入后，核心页面由 PWA 缓存供内网和断网环境使用。</p></article>
    </section>
    <section class="about-section">
      <h2>能力边界</h2>
      <div class="inline-alert warn"><TriangleAlert :size="18" /><span>当前版本使用浏览器端 TypeScript 国密内核，已实现 SM2/SM3 生成、签名和常用 ASN.1/PKI 操作。与 GmSSL 3.x / 铜锁的逐版本命令行互操作矩阵仍属于 M0 验证项，生产使用前应以目标运行环境复核。</span></div>
      <p>本工具可生成私有 PKI 测试链，但不提供公共 CA 服务，也不建立或代表任何信任关系。PFX、JKS、CMS、加密 PKCS#8 与证书链材料均在浏览器本地处理；网站 TLS/TLCP 探针只向本站服务端提交待检测域名。</p>
    </section>
    <section class="about-section legal-section" aria-labelledby="legal-title">
      <h2 id="legal-title">网站归属与备案</h2>
      <dl>
        <div><dt>产品归属</dt><dd><a href="https://www.zerocodex.top/" target="_blank" rel="noopener noreferrer">零码工作室</a></dd></div>
        <div><dt>网站域名</dt><dd class="mono">crypto.zerocodex.top</dd></div>
        <div><dt>ICP备案</dt><dd><a href="https://beian.miit.gov.cn/" target="_blank" rel="noopener noreferrer">苏ICP备2026080292号-1</a></dd></div>
        <div><dt>联系邮箱</dt><dd><a href="mailto:zero@zerocodex.top">zero@zerocodex.top</a></dd></div>
      </dl>
    </section>
    <section class="support-section" aria-labelledby="support-title">
      <div class="support-copy">
        <div class="support-mark" aria-hidden="true"><HeartHandshake :size="25" /></div>
        <p class="eyebrow">支持开源维护</p>
        <h2 id="support-title">喜欢这个工具，欢迎赞赏作者</h2>
        <p>每一份支持都会用于域名、服务器和工具的持续维护。赞赏完全自愿，不影响任何功能使用。</p>
        <div class="support-privacy"><LockKeyhole :size="17" /><span>请勿在付款备注中填写证书、私钥、口令等敏感信息。</span></div>
      </div>
      <figure class="support-qr-card">
        <div class="support-qr-frame">
          <img src="/support-author-qr.png" width="640" height="640" loading="lazy" alt="赞赏作者二维码" />
        </div>
        <figcaption><strong>扫码赞赏</strong><span>感谢你对零码工作室的支持</span></figcaption>
      </figure>
    </section>
  </div>
</template>
