// Help cross-link check (L5): every [[topic-id]] in src/pages/Help.jsx must name an article,
// and article ids must be unique. Runs before `npm run build` (prebuild); exits 1 on a problem.
// Offline, node built-ins only.
import { readFileSync } from 'node:fs'

const src = readFileSync(new URL('../src/pages/Help.jsx', import.meta.url), 'utf8')
const content = src.slice(0, src.indexOf('// ── Topic lookup'))   // CATEGORIES + FAQS, not the renderer

// Article ids sit at 8 spaces inside CATEGORIES[].articles[] (category ids at 4).
const ids = [...content.matchAll(/^ {8}id: '([a-z0-9-]+)'/gm)].map(m => m[1])
const seen = new Set(), dupes = new Set()
for (const id of ids) (seen.has(id) ? dupes : seen).add(id)

const dangling = []
content.split('\n').forEach((line, n) => {
  for (const m of line.matchAll(/\[\[([^\]]*)\]\]/g)) if (!seen.has(m[1])) dangling.push(`Help.jsx:${n + 1} [[${m[1]}]]`)
})

if (!ids.length) { console.error('check-help-links: no article ids found — has the Help.jsx layout changed?'); process.exit(1) }
if (dupes.size || dangling.length) {
  if (dupes.size) console.error(`check-help-links: duplicate article ids: ${[...dupes].join(', ')}`)
  for (const d of dangling) console.error(`check-help-links: dangling link ${d}`)
  process.exit(1)
}
console.log(`check-help-links: ${ids.length} topics, every [[link]] resolves`)
