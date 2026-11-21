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
  assert.equal(settings.errorPages.status['502'], 'Bad Gateway')
  assert.equal(settings.errorPages.status['503'], 'Service Unavailable')
  assert.equal(settings.errorPages.status['504'], 'Gateway Timeout')
  assert.deepEqual(load('zh-CN', 'errors').http, load('en', 'errors').http)
  assert.equal(settings.system.systemlogs.exclude.placeholder, '^/health\nHEAD /')
  assert.equal(proxyHost.form.security.botFilter.customAllowedPlaceholder, load('en', 'proxyHost').form.security.botFilter.customAllowedPlaceholder)
  assert.equal(proxyHost.form.advanced.config.placeholder.split('\n')[1], 'proxy_set_header X-Custom-Header value;')
  assert.match(settings.global.fields.resolver.description, /8\.8\.8\.8 8\.8\.4\.4 valid=300s/)
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
