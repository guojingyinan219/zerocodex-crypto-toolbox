import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { loadEnv } from 'vite'

const root = process.cwd()
const dist = resolve(root, 'dist')
const env = loadEnv('production', root, '')
const configuredUrl = String(process.env.SITE_URL || process.env.VITE_SITE_URL || env.VITE_SITE_URL || '').trim()
const entries = JSON.parse(await readFile(resolve(root, 'src/data/seo-pages.json'), 'utf8'))
const siteName = '零码密码与证书工具箱'

await mkdir(dist, { recursive: true })

if (!configuredUrl) {
  await writeFile(resolve(dist, 'robots.txt'), 'User-agent: *\nAllow: /\n', 'utf8')
  console.warn('SEO: VITE_SITE_URL is not set; static tool pages and sitemap.xml were not generated.')
  process.exit(0)
}

const siteUrl = new URL(configuredUrl.endsWith('/') ? configuredUrl : `${configuredUrl}/`)
if (!['http:', 'https:'].includes(siteUrl.protocol)) {
  throw new Error('VITE_SITE_URL must be an http:// or https:// URL.')
}

const escapeHtml = (value) => String(value)
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')

const escapeXml = (value) => String(value)
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')

const pageUrl = (entry) => new URL(entry.slug ? `tools/${entry.slug}/` : '', siteUrl).toString()
const indexHtml = await readFile(resolve(dist, 'index.html'), 'utf8')
const toolEntries = Object.entries(entries).filter(([id, entry]) => id !== 'home' && id !== 'common' && entry.slug)

function replaceMeta(html, attribute, key, content) {
  const pattern = new RegExp(`<meta\\s+${attribute}="${key}"\\s+content="[^"]*"\\s*\\/?>`)
  const tag = `<meta ${attribute}="${key}" content="${escapeHtml(content)}" />`
  return pattern.test(html) ? html.replace(pattern, tag) : html.replace('</head>', `    ${tag}\n  </head>`)
}

function schemaFor(id, entry, canonicalUrl) {
  const graph = [
    {
      '@type': 'Organization',
      '@id': 'https://www.zerocodex.top/#organization',
      name: '零码工作室',
      url: 'https://www.zerocodex.top/'
    },
    {
      '@type': 'WebSite',
      '@id': `${siteUrl}#website`,
      name: siteName,
      alternateName: ['密码证书工具箱', 'GMSSL 在线工具', '国密工具箱'],
      url: siteUrl.toString(),
      inLanguage: 'zh-CN',
      publisher: { '@id': 'https://www.zerocodex.top/#organization' }
    },
    {
      '@type': 'WebApplication',
      '@id': `${canonicalUrl}#application`,
      name: entry.title,
      url: canonicalUrl,
      description: entry.description,
      applicationCategory: 'SecurityApplication',
      operatingSystem: 'Any',
      browserRequirements: 'Requires JavaScript and a modern web browser',
      inLanguage: 'zh-CN',
      isAccessibleForFree: true,
      keywords: entry.keywords,
      creator: { '@id': 'https://www.zerocodex.top/#organization' },
      isPartOf: { '@id': `${siteUrl}#website` },
      offers: { '@type': 'Offer', price: '0', priceCurrency: 'CNY' }
    },
    {
      '@type': 'BreadcrumbList',
      '@id': `${canonicalUrl}#breadcrumb`,
      itemListElement: [
        { '@type': 'ListItem', position: 1, name: '全部工具', item: siteUrl.toString() },
        { '@type': 'ListItem', position: 2, name: entry.title, item: canonicalUrl }
      ]
    }
  ]
  return JSON.stringify({ '@context': 'https://schema.org', '@graph': graph })
}

function fallbackContent(entry) {
  const links = toolEntries
    .filter(([, item]) => item.slug !== entry.slug)
    .slice(0, 8)
    .map(([, item]) => `<a href="/tools/${escapeHtml(item.slug)}/">${escapeHtml(item.title)}</a>`)
    .join('\n          ')
  return `<div id="app">
      <main>
        <nav aria-label="面包屑"><a href="/">全部工具</a> / <span>${escapeHtml(entry.title)}</span></nav>
        <h1>${escapeHtml(entry.title)}</h1>
        <p>${escapeHtml(entry.description)}</p>
        <p>工具由零码工作室维护。证书、密钥和输入材料默认仅在当前浏览器本地处理。</p>
        <nav aria-label="相关密码与证书工具">
          ${links}
        </nav>
      </main>
    </div>`
}

for (const [id, entry] of toolEntries) {
  const canonicalUrl = pageUrl(entry)
  const fullTitle = `${entry.title} | ${siteName}`
  let html = indexHtml
  html = html.replace(/<title>[\s\S]*?<\/title>/, `<title>${escapeHtml(fullTitle)}</title>`)
  html = replaceMeta(html, 'name', 'description', entry.description)
  html = replaceMeta(html, 'name', 'keywords', entry.keywords)
  html = replaceMeta(html, 'property', 'og:title', fullTitle)
  html = replaceMeta(html, 'property', 'og:description', entry.description)
  html = replaceMeta(html, 'property', 'og:url', canonicalUrl)
  html = replaceMeta(html, 'name', 'twitter:title', fullTitle)
  html = replaceMeta(html, 'name', 'twitter:description', entry.description)
  html = html.replace(/<link rel="canonical" href="[^"]*"\s*\/>/, `<link rel="canonical" href="${canonicalUrl}" />`)
  html = html.replace(/<link rel="alternate" hreflang="zh-CN" href="[^"]*"\s*\/>/, `<link rel="alternate" hreflang="zh-CN" href="${canonicalUrl}" />`)
  html = html.replace(/<link rel="alternate" hreflang="x-default" href="[^"]*"\s*\/>/, `<link rel="alternate" hreflang="x-default" href="${canonicalUrl}" />`)
  html = html.replace(/<script id="seo-schema" type="application\/ld\+json">[\s\S]*?<\/script>/, `<script id="seo-schema" type="application/ld+json">${schemaFor(id, entry, canonicalUrl)}</script>`)
  html = html.replace(/<div id="app">[\s\S]*?<\/div>\s*<\/body>/, `${fallbackContent(entry)}\n  </body>`)
  const outputDirectory = resolve(dist, 'tools', entry.slug)
  await mkdir(outputDirectory, { recursive: true })
  await writeFile(resolve(outputDirectory, 'index.html'), html, 'utf8')
}

const pages = [
  { url: siteUrl.toString(), priority: '1.0', changefreq: 'weekly' },
  ...toolEntries.map(([, entry]) => ({
    url: pageUrl(entry),
    priority: ['certificate-parser', 'sm2-rsa-certificate-generator', 'gmssl-sm2-sm3-tools', 'ssl-tls-security-check'].includes(entry.slug) ? '0.9' : '0.8',
    changefreq: 'monthly'
  }))
]
const lastModified = new Date().toISOString().slice(0, 10)
const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${pages.map(({ url, priority, changefreq }) => `  <url>
    <loc>${escapeXml(url)}</loc>
    <lastmod>${lastModified}</lastmod>
    <changefreq>${changefreq}</changefreq>
    <priority>${priority}</priority>
  </url>`).join('\n')}
</urlset>
`

const llmsText = `# ${siteName}

> 免费在线国密、密码学、PKI、证书和网站 TLS 安全工具，由零码工作室维护。

${toolEntries.map(([, entry]) => `- [${entry.title}](${pageUrl(entry)}): ${entry.description}`).join('\n')}
`

await writeFile(resolve(dist, 'sitemap.xml'), sitemap, 'utf8')
await writeFile(resolve(dist, 'robots.txt'), `User-agent: *\nAllow: /\n\nSitemap: ${new URL('sitemap.xml', siteUrl)}\n`, 'utf8')
await writeFile(resolve(dist, 'llms.txt'), llmsText, 'utf8')
console.log(`SEO: generated ${toolEntries.length} static tool pages and sitemap.xml with ${pages.length} URLs.`)
