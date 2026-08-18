/**
 * parse-directory.mjs — dshbase 插件目录抓取与解析（实时更新机制）。
 *
 * 用法：node parse-directory.mjs [url]
 *   - 默认抓取 https://dshbase.com/zh/plugins/directory/（1773+ 个插件）
 *   - 成功：更新 dshbase-directory.html（缓存）+ 重写 dshbase-directory.json
 *   - 失败（网络不可用）：回退到本地缓存的 HTML 重新解析，不丢数据
 *
 * 输出：dshbase-directory.json
 *   { fetchedAt, source, count, plugins: [{ name, slug, owner, category,
 *     stars, trust, verified, npm, cmd, ucs, updated, url, search }] }
 */
import { writeFileSync, readFileSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const SOURCE = process.argv[2] ?? 'https://dshbase.com/zh/plugins/directory/'
const htmlPath = join(__dirname, 'dshbase-directory.html')
const jsonPath = join(__dirname, 'dshbase-directory.json')

/* ---------- fetch ---------- */
let html, fetched = false
try {
  const res = await fetch(SOURCE, {
    headers: { 'user-agent': 'dshbase-directory-index/1.0 (local mirror)' },
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  html = await res.text()
  if (html.length < 100_000) throw new Error(`suspicious short page (${html.length})`)
  fetched = true
} catch (error) {
  console.error(`[warn] fetch failed (${error.message}); falling back to cached HTML`)
  if (!existsSync(htmlPath)) { console.error('no cached HTML either — aborting'); process.exit(1) }
  html = readFileSync(htmlPath, 'utf8')
}
if (fetched) writeFileSync(htmlPath, html, 'utf8')

/* ---------- parse ---------- */
const cards = [...html.matchAll(/<a class="card pcard"([\s\S]*?)<\/a>/g)]
const plugins = []
for (const [, card] of cards) {
  const open = card.slice(0, card.indexOf('>'))
  const attrs = {}
  for (const [, k, v] of open.matchAll(/data-([\w-]+)="([^"]*)"/g)) attrs[k] = v
  const grab = (re) => card.match(re)?.[1]?.trim() ?? ''
  const plugin = {
    name: attrs.name ?? '',
    slug: attrs.slug ?? attrs.name ?? '',
    owner: grab(/<span class="pcard-owner"[^>]*>@?([^<]*)<\/span>/).replace(/^@/, ''),
    category: attrs.cat ?? '',
    stars: Number(attrs.stars ?? 0) || 0,
    trust: grab(/<span class="pcard-trust t-([a-z]+)"/),
    verified: (attrs.test ?? '') !== '',
    npm: (attrs.npm ?? '') === '1',
    cmd: attrs.cmd ?? '',
    ucs: (attrs.ucs ?? '').split('|').filter(Boolean),
    updated: grab(/<span class="pcard-updated"[^>]*>\s*↻?\s*([^<]+)</).trim(),
    url: `https://dshbase.com${attrs.href ?? ''}`,
    search: attrs.search ?? '',
  }
  if (plugin.name) plugins.push(plugin)
}

/* ---------- dedupe: the page renders the full list plus a "hot" list,
   same plugin may appear twice. Keep the entry with a category (prefer the
   directory section) and the higher stars. ---------- */
const byName = new Map()
for (const p of plugins) {
  const prev = byName.get(p.name)
  if (!prev) { byName.set(p.name, p); continue }
  const prevScore = (prev.category ? 1 : 0) * 10 + prev.stars
  const curScore = (p.category ? 1 : 0) * 10 + p.stars
  if (curScore > prevScore) byName.set(p.name, p)
}
const deduped = [...byName.values()].sort((a, b) => b.stars - a.stars)

/* ---------- write ---------- */
const out = {
  fetchedAt: new Date().toISOString(),
  source: SOURCE,
  fetchedLive: fetched,
  rawCards: plugins.length,
  count: deduped.length,
  plugins: deduped,
}
writeFileSync(jsonPath, JSON.stringify(out, null, 2), 'utf8')
console.log(`parsed ${plugins.length} cards, deduped to ${deduped.length} plugins (live=${fetched})`)
console.log(`wrote ${jsonPath}`)
