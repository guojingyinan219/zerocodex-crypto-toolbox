import seoData from './data/seo-pages.json'

export type CommonToolId = 'base64' | 'url' | 'hex' | 'json' | 'digest' | 'uuid' | 'random' | 'doctor' | 'tls'
export type ToolId = 'home' | 'workbench' | 'asn1' | 'match' | 'generate' | 'convert' | 'gm' | 'symmetric' | CommonToolId | 'common' | 'oids' | 'about'

type SeoEntry = {
  slug: string
  title: string
  description: string
  keywords: string
}

export const commonToolIds: CommonToolId[] = ['base64', 'url', 'hex', 'json', 'digest', 'uuid', 'random', 'doctor', 'tls']
export const toolIds: ToolId[] = ['home', 'workbench', 'asn1', 'match', 'generate', 'convert', 'gm', 'symmetric', ...commonToolIds, 'common', 'oids', 'about']
export const siteName = '零码密码与证书工具箱'
export const seoEntries = seoData as Record<ToolId, SeoEntry>

export function isToolId(value: string | null): value is ToolId {
  return Boolean(value && toolIds.includes(value as ToolId))
}

export function getToolHref(id: ToolId): string {
  const target = id === 'common' ? 'base64' : id
  const slug = seoEntries[target].slug
  return slug ? `/tools/${slug}/` : '/'
}

export function getToolIdFromPath(pathname: string): ToolId | null {
  const match = pathname.match(/^\/tools\/([^/]+)\/?$/)
  if (!match) return pathname === '/' ? 'home' : null
  const entry = Object.entries(seoEntries).find(([id, value]) => id !== 'common' && value.slug === match[1])
  return entry ? entry[0] as ToolId : null
}

function setMeta(selector: string, attribute: 'name' | 'property', key: string, content: string) {
  let element = document.head.querySelector<HTMLMetaElement>(selector)
  if (!element) {
    element = document.createElement('meta')
    element.setAttribute(attribute, key)
    document.head.appendChild(element)
  }
  element.content = content
}

function setLink(rel: string, href: string, hreflang?: string) {
  const selector = hreflang ? `link[rel="${rel}"][hreflang="${hreflang}"]` : `link[rel="${rel}"]`
  let element = document.head.querySelector<HTMLLinkElement>(selector)
  if (!element) {
    element = document.createElement('link')
    element.rel = rel
    if (hreflang) element.hreflang = hreflang
    document.head.appendChild(element)
  }
  element.href = href
}

function structuredData(entry: SeoEntry, canonicalUrl: string, homeUrl: string, id: ToolId) {
  const graph: Record<string, unknown>[] = [
    {
      '@type': 'Organization',
      '@id': 'https://www.zerocodex.top/#organization',
      name: '零码工作室',
      url: 'https://www.zerocodex.top/'
    },
    {
      '@type': 'WebSite',
      '@id': `${homeUrl}#website`,
      name: siteName,
      alternateName: ['密码证书工具箱', 'GMSSL 在线工具', '国密工具箱'],
      url: homeUrl,
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
      isPartOf: { '@id': `${homeUrl}#website` },
      offers: { '@type': 'Offer', price: '0', priceCurrency: 'CNY' }
    }
  ]
  if (id !== 'home') {
    graph.push({
      '@type': 'BreadcrumbList',
      '@id': `${canonicalUrl}#breadcrumb`,
      itemListElement: [
        { '@type': 'ListItem', position: 1, name: '全部工具', item: homeUrl },
        { '@type': 'ListItem', position: 2, name: entry.title, item: canonicalUrl }
      ]
    })
  }
  return { '@context': 'https://schema.org', '@graph': graph }
}

export function updateSeoMetadata(id: ToolId) {
  const target = id === 'common' ? 'base64' : id
  const entry = seoEntries[target]
  const configuredBase = String(import.meta.env.VITE_SITE_URL || '').trim()
  const homeUrl = new URL('/', configuredBase || window.location.origin).toString()
  const canonicalUrl = new URL(getToolHref(target), homeUrl).toString()
  const fullTitle = `${entry.title} | ${siteName}`
  document.title = fullTitle

  setMeta('meta[name="description"]', 'name', 'description', entry.description)
  setMeta('meta[name="keywords"]', 'name', 'keywords', entry.keywords)
  setMeta('meta[property="og:title"]', 'property', 'og:title', fullTitle)
  setMeta('meta[property="og:description"]', 'property', 'og:description', entry.description)
  setMeta('meta[property="og:url"]', 'property', 'og:url', canonicalUrl)
  setMeta('meta[property="og:site_name"]', 'property', 'og:site_name', siteName)
  setMeta('meta[property="og:type"]', 'property', 'og:type', 'website')
  setMeta('meta[name="twitter:title"]', 'name', 'twitter:title', fullTitle)
  setMeta('meta[name="twitter:description"]', 'name', 'twitter:description', entry.description)
  setMeta('meta[name="twitter:card"]', 'name', 'twitter:card', 'summary')
  setLink('canonical', canonicalUrl)
  setLink('alternate', canonicalUrl, 'zh-CN')
  setLink('alternate', canonicalUrl, 'x-default')

  let schemaElement = document.head.querySelector<HTMLScriptElement>('#seo-schema')
  if (!schemaElement) {
    schemaElement = document.createElement('script')
    schemaElement.id = 'seo-schema'
    schemaElement.type = 'application/ld+json'
    document.head.appendChild(schemaElement)
  }
  schemaElement.textContent = JSON.stringify(structuredData(entry, canonicalUrl, homeUrl, target))
}
