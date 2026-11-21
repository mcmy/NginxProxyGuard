import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { test } from 'node:test'
import i18next from 'i18next'
import { exploitRuleText, ruleSeverityText, wafCategoryText, wafRuleText } from '../src/i18n/ruleText.ts'

function load(locale, namespace) {
  return JSON.parse(readFileSync(new URL(`../src/i18n/locales/${locale}/${namespace}.json`, import.meta.url), 'utf8'))
}

function verifyLocale(source, translation, path) {
  if (source && typeof source === 'object') {
    assert.deepEqual(Object.keys(translation).sort(), Object.keys(source).sort(), path)
    for (const [key, value] of Object.entries(source)) {
      verifyLocale(value, translation[key], `${path}.${key}`)
    }
    return
  }

  assert.equal(typeof translation, typeof source, path)
  if (typeof source === 'string') {
    const tokens = /\{\{[^{}]+\}\}|<\/?\d+\s*\/?>/g
    assert.deepEqual((translation.match(tokens) ?? []).sort(), (source.match(tokens) ?? []).sort(), path)
  }
}

test('Simplified Chinese covers the English resource keys and keeps interpolation tokens', () => {
  const localeDir = new URL('../src/i18n/locales/en/', import.meta.url)
  for (const file of readdirSync(localeDir).filter(name => name.endsWith('.json'))) {
    const namespace = file.slice(0, -5)
    verifyLocale(load('en', namespace), load('zh-CN', namespace), namespace)
  }
})

test('protocol labels and copyable configuration examples retain their original literals', () => {
  const settings = load('zh-CN', 'settings')
  const proxyHost = load('zh-CN', 'proxyHost')
  assert.equal(settings.errorPages.status['403'], 'Forbidden')
  assert.equal(settings.errorPages.status['502'], 'Bad Gateway')
  assert.equal(settings.errorPages.status['503'], 'Service Unavailable')
  assert.equal(settings.errorPages.status['504'], 'Gateway Timeout')
  assert.deepEqual(load('zh-CN', 'errors').http, load('en', 'errors').http)
  assert.equal(settings.system.systemlogs.exclude.placeholder, '^/health\nHEAD /')
  assert.equal(proxyHost.form.security.botFilter.customAllowedPlaceholder, load('en', 'proxyHost').form.security.botFilter.customAllowedPlaceholder)
  assert.equal(proxyHost.form.advanced.config.placeholder.split('\n')[1], 'proxy_set_header X-Custom-Header value;')
  assert.match(settings.global.fields.resolver.description, /8\.8\.8\.8 8\.8\.4\.4 valid=300s/)
})

test('Chinese settings and logs use the same terms for products and bot categories', () => {
  const settings = load('zh-CN', 'settings')
  const proxyHost = load('zh-CN', 'proxyHost')
  const logs = load('zh-CN', 'logs')
  const certificates = load('zh-CN', 'certificates')
  const botFilter = settings.system.botfilter
  const badBot = logs.bots.badBot

  assert.equal(settings.captcha.provider.turnstile, 'Cloudflare Turnstile')
  assert.equal(proxyHost.form.basic.dockerBrowseShort, 'Docker')
  assert.equal(certificates.providers.cloudflare, 'Cloudflare')
  assert.equal(certificates.dnsProviders.types.cloudflare, 'Cloudflare')
  assert.equal(proxyHost.form.security.fail2banSettings, 'Fail2ban 设置')
  assert.equal(badBot, '恶意机器人')
  assert.equal(logs.botFilter.categories.badBot, badBot)
  assert.equal(botFilter.lists.badBots.label, `${badBot}列表`)
  assert.ok(botFilter.lists.badBots.description.includes(badBot))
  assert.equal(botFilter.options.blockBadBots.label, `拦截${badBot}`)
  assert.equal(proxyHost.form.security.botFilter.blockBadBots, `拦截${badBot}`)
})

test('public error pages show the same Chinese explanations and HTTP labels as settings', () => {
  const { status, statusDetails } = load('zh-CN', 'settings').errorPages
  for (const [code, title] of Object.entries(status)) {
    const template = readFileSync(new URL(`../../nginx/html/${code}.html`, import.meta.url), 'utf8')
    assert.ok(template.includes(`<div class="error-title" data-lang="en zh-CN">${title}</div>`), code)
    assert.ok(template.includes(statusDetails[code]), code)
    assert.ok(template.includes('id="btn-zh-CN">简体中文</button>'), code)
  }
})

test('certificate algorithms, sort directions, and HTTPS switches use consistent Chinese labels', () => {
  const certificates = load('zh-CN', 'certificates')
  const proxyHost = load('zh-CN', 'proxyHost')
  const redirectHost = load('zh-CN', 'redirectHost')

  assert.equal(certificates.form.keyType, '密钥类型')
  assert.deepEqual(certificates.keyTypes, load('en', 'certificates').keyTypes)
  assert.equal(certificates.list.sort.domainAsc, '域名（A-Z）')
  assert.equal(certificates.list.sort.domainDesc, '域名（Z-A）')
  assert.equal(proxyHost.list.sort.nameAsc, '名称（A-Z）')
  assert.equal(proxyHost.list.sort.nameDesc, '名称（Z-A）')
  assert.equal(proxyHost.list.sort.createdAsc, '最早创建')
  assert.equal(certificates.list.sort.createdAsc, proxyHost.list.sort.createdAsc)
  assert.equal(proxyHost.list.sort.updatedAsc, '最早更新')
  assert.equal(proxyHost.form.ssl.forceHttps, '强制 HTTPS')
  assert.equal(redirectHost.form.forceHttps, proxyHost.form.ssl.forceHttps)
})

test('Chinese Nginx controls describe connection scope, request bodies, and unmatched hosts', () => {
  const settings = load('zh-CN', 'settings')
  const proxyHost = load('zh-CN', 'proxyHost')
  const { worker_connections, multi_accept, client_max_body_size } = settings.global.fields
  const directIp = settings.global.advanced.directIpAccess

  assert.match(worker_connections.description, /客户端连接.*上游服务器的连接/)
  assert.equal(multi_accept.label, '批量接收新连接')
  assert.equal(client_max_body_size.label, '请求体大小上限')
  assert.equal(proxyHost.form.performance.proxySettings.clientMaxBodySize, client_max_body_size.label)
  assert.equal(proxyHost.help.performance.clientMaxBodySize, settings.help.global.client_max_body_size)
  assert.match(settings.help.global.client_max_body_size, /413.*0 可停用 Nginx 的请求体大小检查/)
  assert.match(directIp.description, /服务器 IP 地址或未配置的域名/)
  assert.match(directIp.options.block444.description, /客户端收不到 HTTP 响应/)
  assert.match(directIp.note.description, /SNI.*握手拒绝/)
})

test('rule labels localize known IDs and preserve descriptions for unknown ones', () => {
  const source = 'SQL Injection Attack Detected via libinjection'
  assert.equal(wafCategoryText('zh-CN', 'SQLI'), 'SQL 注入')
  assert.match(wafRuleText('zh-CN', 942100, source), /SQL 注入/)
  assert.equal(wafRuleText('en', 942100, source), source)
  assert.equal(wafRuleText('zh-CN', 999000, 'Local policy description'), 'Local policy description')
  assert.equal(wafRuleText('zh-CN', 999000, 'Section marker'), '规则段落标记')
  assert.equal(ruleSeverityText('zh-CN', 'critical'), '严重')
})

test('built-in exploit names localize across namespaces', async () => {
  const i18n = i18next.createInstance()
  await i18n.init({
    lng: 'zh-CN',
    resources: { 'zh-CN': { exploitRules: load('zh-CN', 'exploitRules') } },
  })

  const t = i18n.getFixedT('zh-CN', 'exploitLogs')
  assert.equal(exploitRuleText(t, 'Dotenv File Access'), '.env 文件访问')
  assert.match(exploitRuleText(t, 'Dotenv File Access', 'description'), /\.env\.production/)
  assert.equal(exploitRuleText(t, 'Local rule'), 'Local rule')
})
