import type { TFunction } from 'i18next'
import crsRules from './zh-CN-crs-rules.json' with { type: 'json' }

// Rule messages from the CRS version pinned in nginx/Dockerfile and the ModSecurity internal rules.
const crsDescriptions: Readonly<Record<string, string>> = crsRules

const crsCategories: Readonly<Record<string, string>> = {
  'MODSEC-INTERNAL': 'ModSecurity 内部规则',
  METHOD: 'HTTP 方法检查',
  SCANNER: '扫描器检测',
  PROTOCOL: 'HTTP 协议合规检查',
  'PROTOCOL-ATTACK': 'HTTP 协议攻击',
  MULTIPART: 'multipart 请求攻击',
  LFI: '本地文件包含',
  RFI: '远程文件包含',
  RCE: '远程代码执行',
  PHP: 'PHP 注入攻击',
  GENERIC: '通用应用攻击',
  XSS: '跨站脚本攻击',
  SQLI: 'SQL 注入',
  SESSION: '会话固定攻击',
  JAVA: 'Java 应用攻击',
  'DATA-LEAK': '数据泄露',
  'DATA-LEAK-SQL': 'SQL 数据泄露',
  'DATA-LEAK-JAVA': 'Java 数据泄露',
  'DATA-LEAK-PHP': 'PHP 数据泄露',
  'DATA-LEAK-IIS': 'IIS 数据泄露',
  'WEB-SHELL': 'WebShell 检测',
}

// Messages synthesized by the API for rules whose SecRule has no msg field.
const generatedDescriptions: Readonly<Record<string, string>> = {
  'Paranoia level control rule (skip to end)': '检测严格级别控制规则（跳至本节末尾）',
  'Control rule (skip condition)': '流程控制规则（满足条件时跳过）',
  'Variable initialization rule': '变量初始化规则',
  'Section marker': '规则段落标记',
  'Paranoia level gate rule': '检测严格级别门控规则',
  'Chained rule (part of multi-condition check)': '链式规则（多条件检查的一部分）',
  'ModSecurity rule': 'ModSecurity 规则',
}

export function wafCategoryText(language: string, category: string): string {
  if (language !== 'zh-CN' || !Object.prototype.hasOwnProperty.call(crsCategories, category)) return category
  return crsCategories[category]
}

export function wafRuleText(language: string, id: number | string | undefined, source?: string): string {
  if (language !== 'zh-CN') return source ?? ''
  if (id !== undefined && Object.prototype.hasOwnProperty.call(crsDescriptions, id)) return crsDescriptions[id]
  if (!source) return ''
  if (Object.prototype.hasOwnProperty.call(generatedDescriptions, source)) return generatedDescriptions[source]
  const suffix = ' detection rule'
  const category = source.endsWith(suffix) ? source.slice(0, -suffix.length) : ''
  return Object.prototype.hasOwnProperty.call(crsCategories, category) ? crsCategories[category] + '规则' : source
}

const severityLabels = new Map([
  ['EMERGENCY', '紧急'],
  ['ALERT', '警报'],
  ['CRITICAL', '严重'],
  ['ERROR', '错误'],
  ['WARNING', '警告'],
  ['NOTICE', '提示'],
  ['INFO', '信息'],
  ['DEBUG', '调试'],
])

export function ruleSeverityText(language: string, severity: string): string {
  return language === 'zh-CN' ? severityLabels.get(severity.toUpperCase()) ?? severity : severity
}

export function exploitRuleText(t: TFunction, name: string, field: 'name' | 'description' = 'name', source = name): string {
  return t(`exploitRules:rules.${name}.${field}`, { defaultValue: source })
}
