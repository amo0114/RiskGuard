// Chinese display names and formatting for audit metadata. Unknown codes fall back to the raw
// identifier so new server-side values stay visible instead of disappearing.

export type Tone = "ok" | "warn" | "danger" | "info" | "violet" | "muted"

export const MODES = {
  shadow: { name: "影子模式", desc: "请求照常转发，仅记录审查结论", dot: "bg-amber-500" },
  enforce: { name: "拦截模式", desc: "按策略拒绝不合规请求", dot: "bg-red-500" },
  disabled: { name: "已停用", desc: "透明转发，不做内容审查", dot: "bg-zinc-400" },
} as const

export const DECISIONS: Record<string, { name: string; tone: Tone; color: string }> = {
  allow: { name: "放行", tone: "ok", color: "var(--chart-2)" },
  review: { name: "待复核", tone: "warn", color: "var(--chart-3)" },
  deny: { name: "拒绝", tone: "danger", color: "var(--chart-4)" },
  unavailable: { name: "审查不可用", tone: "violet", color: "var(--chart-1)" },
  unsupported: { name: "未覆盖", tone: "info", color: "var(--chart-5)" },
  reject: { name: "请求拒收", tone: "muted", color: "var(--muted-foreground)" },
  aborted: { name: "客户端中断", tone: "muted", color: "var(--border)" },
}

export const LABELS: Record<string, { name: string; tone: Tone; color: string }> = {
  Safe: { name: "安全", tone: "ok", color: "var(--chart-2)" },
  Controversial: { name: "有争议", tone: "warn", color: "var(--chart-3)" },
  Unsafe: { name: "不安全", tone: "danger", color: "var(--chart-4)" },
  Unknown: { name: "无法判定", tone: "muted", color: "var(--muted-foreground)" },
}
export const LABEL_ORDER = ["Safe", "Controversial", "Unsafe", "Unknown"]

export const CATEGORIES: Record<string, string> = {
  Violent: "暴力",
  "Non-violent Illegal Acts": "非暴力违法",
  "Sexual Content or Sexual Acts": "色情内容",
  PII: "个人隐私信息",
  "Suicide & Self-Harm": "自杀与自伤",
  "Unethical Acts": "不道德行为",
  Jailbreak: "越狱攻击",
  "Politically Sensitive Topics": "政治敏感话题",
  "Copyright Violation": "版权侵权",
}

export const ACTIONS: Record<string, { name: string; tone: Tone }> = {
  allow: { name: "放行", tone: "ok" },
  forward: { name: "放行", tone: "ok" },
  review: { name: "待复核", tone: "warn" },
  deny: { name: "拒绝", tone: "danger" },
  reject: { name: "拒绝", tone: "danger" },
}

export const PROTOCOLS: Record<string, string> = {
  openai_chat: "OpenAI 对话补全",
  openai_completions: "OpenAI 文本补全",
  openai_responses: "OpenAI 响应接口",
  openai_edits: "OpenAI 文本编辑",
  claude_messages: "Claude 消息接口",
  gemini: "Gemini 内容生成",
  embeddings: "向量嵌入",
  rerank: "重排序",
  moderations: "内容审核接口",
  tool_special: "工具搜索与抓取",
  openai_responses_ws: "OpenAI 响应接口（长连接）",
  openai_realtime_ws: "OpenAI 实时会话（长连接）",
  websocket: "长连接（其他）",
  image_generation: "图像生成",
  images: "图像编辑与变体（上传）",
  audio_speech: "语音合成",
  audio: "语音识别与翻译（上传）",
  video_generation: "视频生成",
  video: "视频生成（上传）",
  midjourney: "Midjourney 绘图",
  suno: "Suno 音乐",
  task_plugin: "异步任务插件",
  unknown: "未识别接口",
}
export const TEXT_PROTOCOLS = new Set([
  "openai_chat", "openai_completions", "openai_responses", "openai_edits", "claude_messages",
  "gemini", "moderations", "tool_special", "embeddings", "rerank",
  "image_generation", "audio_speech", "video_generation", "midjourney", "suno",
])

export const COVERAGE: Record<string, string> = {
  full_selected_inputs: "完整审查",
  partial_context: "部分审查",
  unsupported: "未覆盖",
  t0_only: "免审查",
}

export const REASONS: Record<string, string> = {
  CLASSIFIER_SAFE: "分类结果为安全",
  AMBIGUOUS: "分类结果有争议",
  POLICY_REVIEW: "命中需复核类别",
  POLICY_HIGH_RISK: "命中高风险类别",
  POLICY_DISALLOWED: "命中禁止类别",
  POLICY_ALLOWED_CATEGORY: "命中已放行类别",
  POLICY_UNSAFE_UNCATEGORISED: "不安全但未给出类别",
  UNKNOWN_LABEL: "分类结果无法识别",
  PARSE_FAILED: "内容解析失败",
  INPUT_TOO_LONG: "输入超出分类长度上限",
  MODEL_TIMEOUT: "分类超时",
  CLASSIFIER_BUSY: "分类服务繁忙",
  MODEL_UNAVAILABLE: "分类服务不可用",
  COVERAGE_GAP: "接口未纳入审查",
  APPROVED_EXCEPTION: "已批准的覆盖例外",
  T0_ONLY_EXCEPTION: "免审查接口",
  ADMISSION_LIMIT: "审查频率超限",
  SPOOL_FULL: "请求缓冲已满",
  EXTRACT_BUSY: "内容抽取繁忙",
  BODY_TOO_LARGE: "请求体过大",
  BODY_READ_FAILED: "请求上传中断",
  NON_JSON_BODY: "请求体不是 JSON",
  BAD_ENCODING: "内容编码错误",
  UNSUPPORTED_ENCODING: "不支持的内容编码",
  DECODED_TOO_LARGE: "解压后超出上限",
  UNKNOWN_PROTOCOL: "未识别的协议",
  NO_INSPECTABLE_INPUT: "无可审查的输入",
  MEDIA_ONLY: "只有图片或音频，无法审查",
  TRUNCATED: "内容过长已截断",
  MEDIA_NOT_INSPECTED: "含未审查的图片或音频",
  HISTORY_NOT_INSPECTED: "历史对话未审查",
  SYSTEM_NOT_INSPECTED: "系统提示词未审查",
  NO_USER_TEXT: "无用户文本",
}

const CLS_STATUS: Record<string, string> = {
  ok: "正常",
  timeout: "超时",
  busy: "繁忙，未调用",
  unavailable: "不可用",
  error: "调用错误",
  parse_failed: "输出无法解析",
  too_long: "输入超长",
}

export const RANGE_NAMES = { "1h": "近 1 小时", "24h": "近 24 小时", "7d": "近 7 天" } as const

export const protoName = (p?: string) => (p ? (PROTOCOLS[p] ?? `其他接口（${p}）`) : "—")
export const reasonName = (r?: string) => (r ? (REASONS[r] ?? `其他（${r}）`) : "—")
export const catName = (c: string) => CATEGORIES[c] ?? c
export const clsStatus = (s?: string) =>
  !s ? "—" : (CLS_STATUS[s] ?? (/^http_\d+$/.test(s) ? `服务返回 ${s.slice(5)}` : s))

const nf = new Intl.NumberFormat("zh-CN")
export const fmt = (n?: number | null) => (n == null ? "—" : nf.format(n))
export const big = (n = 0) =>
  n >= 1e8 ? `${(n / 1e8).toFixed(2)} 亿` : n >= 1e4 ? `${(n / 1e4).toFixed(n >= 1e5 ? 1 : 2)} 万` : nf.format(n)
export const axisNum = (n: number) => (n >= 1e4 ? `${(n / 1e4).toFixed(n % 1e4 ? 1 : 0)}万` : nf.format(n))
export const pct = (a: number, b: number) =>
  b ? `${((a / b) * 100).toFixed(a && a / b < 0.1 ? 1 : 0)}%` : "—"
export const sum = (o?: Record<string, number>) => Object.values(o ?? {}).reduce((a, b) => a + b, 0)

const pad = (n: number) => String(n).padStart(2, "0")
export const isZeroTime = (t?: string) => !t || t.startsWith("0001-")

export function dt(d: Date, parts: "full" | "short" | "time" = "full") {
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}`
  if (parts === "time") return time
  if (parts === "short") return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${time}`
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${time}:${pad(d.getSeconds())}`
}

// Table timestamps: today's events only need the time of day.
export function when(t: string) {
  const d = new Date(t)
  return d.toDateString() === new Date().toDateString()
    ? `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
    : `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

export function ago(t?: string) {
  if (isZeroTime(t)) return "从未"
  const sec = Math.max(0, (Date.now() - new Date(t!).getTime()) / 1000)
  if (sec < 60) return "刚刚"
  if (sec < 3600) return `${Math.floor(sec / 60)} 分钟前`
  if (sec < 86400) return `${Math.floor(sec / 3600)} 小时前`
  return `${Math.floor(sec / 86400)} 天前`
}

export function dur(sec: number) {
  if (sec < 60) return `${Math.floor(sec)} 秒`
  if (sec < 3600) return `${Math.floor(sec / 60)} 分钟`
  if (sec < 86400) return `${Math.floor(sec / 3600)} 小时 ${Math.floor((sec % 3600) / 60)} 分钟`
  return `${Math.floor(sec / 86400)} 天 ${Math.floor((sec % 86400) / 3600)} 小时`
}

export function ms(v?: number) {
  if (v == null) return "—"
  if (v < 1000) return `${v} 毫秒`
  return `${(v / 1000).toFixed(v % 1000 ? 1 : 0)} 秒`
}

// Histogram percentiles are reported as the upper bound of their bin; -1 is the open bin.
export const bound = (v: number) => (!v ? "—" : v < 0 ? "> 12 秒" : `≤ ${ms(v)}`)

export function bytes(n?: number) {
  if (!n) return "0 B"
  const u = ["B", "KB", "MB", "GB"]
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)))
  const v = n / 1024 ** i
  return `${i ? v.toFixed(v % 1 ? 1 : 0) : v} ${u[i]}`
}

export function goDur(s?: string | number) {
  if (s == null) return "—"
  const m = /^(?:(\d+)h)?(?:(\d+)m(?!s))?(?:([\d.]+)s)?(?:([\d.]+)ms)?$/.exec(String(s))
  if (!m) return String(s)
  const parts = [
    +m[1] ? `${+m[1]} 小时` : "",
    +m[2] ? `${+m[2]} 分钟` : "",
    +m[3] ? `${+m[3]} 秒` : "",
    +m[4] ? `${+m[4]} 毫秒` : "",
  ].filter(Boolean)
  return parts.join(" ") || "0"
}

/** A key fingerprint as people read it: the admin's alias when one exists, else the fingerprint. */
export function keyName(fp: string | undefined, aliases: Record<string, { name: string }> | undefined) {
  if (!fp) return "—"
  const a = aliases?.[fp]?.name
  return a ? `${a} · ${fp.slice(0, 6)}` : fp
}
