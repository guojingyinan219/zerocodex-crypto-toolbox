import { describe, expect, it } from 'vitest'
import { getToolHref, getToolIdFromPath, seoEntries, toolIds } from './seo'

describe('SEO routes', () => {
  it('uses stable clean paths for indexable tools', () => {
    const indexable = toolIds.filter((id) => id !== 'common')
    const hrefs = indexable.map(getToolHref)
    expect(new Set(hrefs).size).toBe(indexable.length)
    expect(getToolHref('home')).toBe('/')
    expect(getToolHref('tls')).toBe('/tools/ssl-tls-security-check/')
  })

  it('maps every generated tool path back to its tool id', () => {
    for (const id of toolIds.filter((value) => value !== 'common' && value !== 'home')) {
      expect(getToolIdFromPath(getToolHref(id))).toBe(id)
      expect(seoEntries[id].title.length).toBeGreaterThan(8)
      expect(seoEntries[id].description.length).toBeGreaterThan(30)
    }
  })

  it('does not treat unrelated paths as tools', () => {
    expect(getToolIdFromPath('/unknown/')).toBeNull()
    expect(getToolIdFromPath('/tools/not-a-tool/')).toBeNull()
  })
})
