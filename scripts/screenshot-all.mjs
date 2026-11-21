// Capture every console route and key interaction into ~/Desktop.
// Usage: node scripts/screenshot-all.mjs [outputDir]
import { chromium } from '/Users/z/work/hanzo/ide/node_modules/playwright/index.mjs'
import fs from 'node:fs'

const OUT = process.argv[2] || `${process.env.HOME}/Desktop/OpenCyber-Control-Screenshots`
const DEMO = process.env.OPENCYBER_DEMO_FILE || '/tmp/opencyber-demo.json'
const BASE = process.env.OPENCYBER_BASE_URL || 'http://127.0.0.1:8787'
const CHROME = process.env.PLAYWRIGHT_CHROME || '/Users/z/Library/Caches/ms-playwright/chromium_headless_shell-1243/chrome-headless-shell-mac-arm64/chrome-headless-shell'
const demo = JSON.parse(fs.readFileSync(DEMO, 'utf8'))
fs.mkdirSync(OUT, { recursive: true })

const browser = await chromium.launch({ headless: true, executablePath: CHROME })
const errors = []
const page = await browser.newPage({ viewport: { width: 1440, height: 960 }, deviceScaleFactor: 1 })
page.on('console', m => { if (m.type() === 'error') errors.push(m.text()) })
page.on('pageerror', e => errors.push(e.message))
await page.addInitScript((e) => {
  localStorage.setItem('opencyber.engagement', e)
  localStorage.setItem('opencyber.org', 'demo')
  localStorage.setItem('opencyber.user', 'demo@hanzo.ai')
}, demo.engagement_id)
await page.goto(`${BASE}/`, { waitUntil: 'networkidle' })

const go = async (hash) => { await page.evaluate(h => { location.hash = h }, '#' + hash); await page.waitForTimeout(500) }
const shot = async (name) => { await page.waitForTimeout(400); await page.screenshot({ path: `${OUT}/${name}.png`, fullPage: true }) }

const routes = [
  ['01-dashboard', '/'], ['02-chat', '/chat'], ['03-tasks', '/tasks'], ['04-findings', '/findings'],
  ['05-traffic', '/traffic'], ['05b-capture-scanner', '/scanner'], ['06-commands', '/commands'],
  ['07-llm-records', '/llm-records'], ['08-assets', '/assets'], ['09-sync', '/sync'],
  ['10-workspace', '/workspace'], ['11-templates', '/templates'], ['12-llm', '/llm'],
  ['13-agents', '/agents'], ['14-mcp', '/mcp'], ['15-skills', '/skills'], ['16-tools', '/tools'],
  ['17-notify', '/notify'], ['18-intercept', '/intercept'], ['19-blocked-targets', '/intercept/assets'],
  ['20-approvals', '/approvals'], ['21-logs', '/logs'], ['22-settings', '/settings'],
  ['23-cloud-sandbox', '/cloud'], ['23b-attack-checks', '/attack'], ['23c-course-of-action', '/coa'],
  ['23d-secret-scanning', '/security'], ['23e-sbom', '/sbom'], ['23f-linux-hardening', '/hardening'],
  ['23g-native-wiring', '/wiring'],
]
for (const [name, hash] of routes) { await go(hash); await shot(name) }

for (const tab of ['overview', 'sessions', 'graph', 'coverage', 'findings', 'assets', 'intents', 'broadcast', 'traffic', 'creds', 'goals', 'report']) {
  await go(`/tasks/${demo.task_id}?tab=${tab}`); await shot(`24-task-${tab}`)
}

const close = async () => { const b = page.locator('.drawer-head button').first(); if (await b.count()) await b.click(); await page.waitForTimeout(200) }
await go('/'); await page.getByText('New task', { exact: true }).first().click(); await shot('25a-dashboard-quick-create'); await close()
await go('/tasks'); await page.getByText('New task', { exact: true }).first().click(); await shot('25-create-task-drawer'); await close()
await go('/llm'); await page.getByText('New profile', { exact: true }).first().click(); await shot('30-llm-profile-drawer'); await close()
await go('/agents'); await page.getByText('New agent', { exact: true }).first().click(); await shot('31-agent-drawer'); await close()
await go('/assets'); await page.getByText('Add assets', { exact: true }).first().click(); await shot('32-assets-drawer'); await close()
await go('/intercept'); await page.getByText('Add rule', { exact: true }).first().click(); await shot('33-intercept-rule-drawer'); await close()
await go('/findings')
const finding = page.locator('a[style*="cursor: pointer"]').first()
if (await finding.count()) { await finding.click(); await shot('26-finding-detail-drawer'); await close() }
await go('/traffic'); const row = page.locator('.list-item').first(); if (await row.count()) { await row.click(); await shot('27-traffic-detail') }
await page.keyboard.press('Control+k'); await shot('28-capability-launcher'); await close()

await page.evaluate(() => localStorage.setItem('opencyber.theme', 'light'))
await page.reload({ waitUntil: 'networkidle' })
for (const [name, hash] of [['34-light-dashboard', '/'], ['34-light-chat', '/chat'], ['35-light-tasks', '/tasks'], ['36-light-cloud', '/cloud'], ['37-light-findings', '/findings']]) {
  await go(hash); await shot(name)
}

const files = fs.readdirSync(OUT).filter(f => f.endsWith('.png')).sort()
const rows = files.map(f => `<figure><a href="${f}"><img src="${f}" loading="lazy"></a><figcaption>${f.slice(0, -4)}</figcaption></figure>`).join('\n')
fs.writeFileSync(`${OUT}/index.html`, `<!doctype html><html><head><meta charset="utf-8"><title>Hanzo Cyber — final product screens</title><style>body{font:13px system-ui;background:#0a0a0a;color:#fafafa;margin:24px}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:18px}figure{margin:0;border:1px solid #27272a;border-radius:12px;overflow:hidden}img{width:100%;display:block}figcaption{padding:8px 10px;color:#a1a1aa}</style></head><body><h1>Hanzo Cyber — ${files.length} final product screens</h1><div class="grid">${rows}</div></body></html>`)
console.log(`screens ${files.length}, errors ${errors.length}`)
errors.slice(0, 5).forEach(e => console.log(' ', e))
await browser.close()
