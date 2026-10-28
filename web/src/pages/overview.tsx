import * as React from "react"
import { Info } from "lucide-react"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Hint, PageHeader, Section } from "@/components/console/bits"
import { DonutChart, RankList, TrendChart, type Slice, type TrendKey } from "@/components/console/charts"
import { cn } from "@/lib/utils"
import {
  big,
  bound,
  catName,
  COVERAGE_STATE_ORDER,
  COVERAGE_STATES,
  DECISIONS,
  dt,
  fmt,
  LABEL_ORDER,
  LABELS,
  pct,
  RANGE_NAMES,
  reasonName,
} from "@/lib/format"
import { useStore } from "@/lib/store"
import type { Coverage, Summary } from "@/lib/types"

export function ModeAlert({ mode }: { mode: Summary["mode"] }) {
  if (mode === "enforce") return null
  const shadow = mode === "shadow"
  return (
    <div
      className={cn(
        "flex gap-2.5 rounded-xl border px-4 py-3 text-sm",
        shadow ? "border-amber-500/30 bg-amber-500/8" : "border-sky-500/30 bg-sky-500/8"
      )}
    >
      <Info className={cn("mt-0.5 size-4 shrink-0", shadow ? "text-amber-600" : "text-sky-600")} />
      <p>
        {shadow ? (
          <>
            <b className="font-semibold">当前为影子模式。</b>
            所有请求均照常转发至上游；“预计拦截”表示切换到拦截模式后将被拒绝的请求，用于评估误判率与审查容量。
          </>
        ) : (
          <>
            <b className="font-semibold">内容审查已停用。</b>网关仅透明转发并统计流量。
          </>
        )}
      </p>
    </div>
  )
}

function Kpi({
  title,
  tip,
  value,
  unit,
  foot,
  tone,
}: {
  title: string
  tip: string
  value: string
  unit?: string
  foot: React.ReactNode
  tone?: "danger" | "warn"
}) {
  return (
    <Card className="gap-2 py-4 shadow-none">
      <CardHeader className="px-4">
        <CardTitle className="flex items-center gap-1.5 text-sm font-normal text-muted-foreground">
          {title}
          <Hint>{tip}</Hint>
        </CardTitle>
      </CardHeader>
      <CardContent className="px-4">
        <div
          className={cn(
            "text-2xl font-semibold tracking-tight tabular-nums",
            tone === "danger" && "text-red-600 dark:text-red-400",
            tone === "warn" && "text-amber-600 dark:text-amber-400"
          )}
        >
          {value}
          {unit && <span className="ml-1 text-xs font-normal text-muted-foreground">{unit}</span>}
        </div>
        <div className="mt-1 text-xs text-muted-foreground [&_b]:font-medium [&_b]:text-foreground">{foot}</div>
      </CardContent>
    </Card>
  )
}

function CoverageSection({ cov }: { cov: Coverage }) {
  const states: Slice[] = COVERAGE_STATE_ORDER.filter((k) => cov.states[k]).map((k) => ({
    key: k,
    name: COVERAGE_STATES[k].name,
    color: COVERAGE_STATES[k].color,
    count: cov.states[k],
  }))
  // Approved exemptions are a policy choice, not a gap.
  const reasons = cov.reasons
    .filter((r) => !r.key.startsWith("exempt:"))
    .slice(0, 8)
    .map((r) => {
      const [state, code] = r.key.split(":")
      return { name: `${COVERAGE_STATES[state]?.name ?? state} · ${reasonName(code)}`, count: r.count }
    })
  const complete = cov.user_text.complete ?? 0
  const truncated = cov.user_text.truncated ?? 0
  const withText = complete + truncated
  return (
    <Section
      title="审查覆盖"
      hint="每个模型请求只计一种状态。“部分审查”不代表最新用户输入没审：它多半是历史或系统提示词未送审，见右侧原因"
    >
      {cov.untracked > 0 && (
        <p className="mb-3 text-xs text-muted-foreground">
          另有 {fmt(cov.untracked)} 个受审查请求发生在覆盖统计启用之前（
          {cov.since ? `${dt(new Date(cov.since * 60 * 1000), "short")} 起才有数据` : "该范围内尚无覆盖数据"}），未计入下列比例。
        </p>
      )}
      <div className="grid gap-6 md:grid-cols-2">
        <div className="flex flex-col gap-4">
          <DonutChart items={states} center="模型请求" empty="暂无覆盖数据" />
          <div className="rounded-lg border px-4 py-3">
            <div className="flex items-center gap-1.5 text-sm text-muted-foreground">
              最新用户文本有效审查率
              <Hint>
                在抽取到最新用户文本的请求中，文本未被截断且分类器给出有效结论（含命中缓存）的比例。不含没有用户文本、无法解析和审查前失败的请求。
              </Hint>
            </div>
            <div className="mt-1 text-2xl font-semibold tracking-tight tabular-nums">{pct(cov.user_text_ok, withText)}</div>
            <div className="mt-1 text-xs text-muted-foreground">
              {fmt(cov.user_text_ok)} / {fmt(withText)}：完整 {fmt(complete)}，截断 {fmt(truncated)}，无用户文本 {fmt(cov.user_text.absent ?? 0)}
            </div>
          </div>
        </div>
        <div className="flex flex-col gap-2">
          <div className="text-sm text-muted-foreground">主要覆盖缺口原因（每个请求只记第一个原因）</div>
          <RankList items={reasons} color="var(--chart-3)" empty="没有覆盖缺口" />
        </div>
      </div>
    </Section>
  )
}

export function OverviewPage() {
  const { summary, range } = useStore()
  const [hidden, setHidden] = React.useState<Set<TrendKey>>(new Set())
  if (!summary) return null
  const st = summary.stats
  const t = st.totals
  const enforce = summary.mode === "enforce"
  const blockKey = enforce ? "enforced" : "would_block"
  const blocked = t[blockKey] ?? 0
  const evaluations = (t.new_turns ?? 0) + (t.cache_hits ?? 0)
  const unavailable = t.decisions?.unavailable ?? 0
  const slow = st.latency_p95_ms > 3000 || st.latency_p95_ms < 0

  const lines: { key: TrendKey; name: string; color: string; bar?: boolean }[] = [
    { key: "req", name: "请求总数", color: "var(--muted-foreground)" },
    { key: "guarded", name: "受审查请求", color: "var(--chart-1)" },
    { key: "new_turns", name: "分类调用", color: "var(--chart-3)" },
    { key: blockKey, name: enforce ? "已拦截" : "预计拦截", color: "var(--chart-4)", bar: true },
  ]
  const toggle = (k: TrendKey) =>
    setHidden((h) => {
      const n = new Set(h)
      if (!n.delete(k)) n.add(k)
      return n
    })
  const step = st.step_seconds
  const stepName = step >= 3600 ? `${step / 3600} 小时` : `${step / 60} 分钟`

  const decisions: Slice[] = Object.entries(t.decisions ?? {})
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => ({ key: k, name: DECISIONS[k]?.name ?? k, color: DECISIONS[k]?.color ?? "var(--muted-foreground)", count: v }))
  const labels: Slice[] = Object.entries(t.labels ?? {})
    .sort((a, b) => LABEL_ORDER.indexOf(a[0]) - LABEL_ORDER.indexOf(b[0]))
    .map(([k, v]) => ({ key: k, name: LABELS[k]?.name ?? k, color: LABELS[k]?.color ?? "var(--muted-foreground)", count: v }))
  const cats = (st.categories ?? []).map((c) => ({ name: catName(c.key), count: c.count }))
  const reasons = (st.top_reasons ?? []).slice(0, 8).map((r) => ({ name: reasonName(r.key), count: r.count }))

  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="运行总览" description="请求量、审查结论与风险分布" />
      <ModeAlert mode={summary.mode} />
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-3 2xl:grid-cols-6">
        <Kpi
          title="请求总数"
          tip="经过网关的全部请求，包括管理与只读接口"
          value={big(t.req)}
          foot={<>其中受审查 <b>{pct(t.guarded ?? 0, t.req)}</b></>}
        />
        <Kpi
          title="受审查请求"
          tip="进入内容审查流程的请求。评估总数为分类调用尝试与缓存复用之和；差额为免审接口、未覆盖协议或格式错误请求"
          value={big(t.guarded)}
          foot={<>审查评估总数 <b>{fmt(evaluations)}</b>，缓存命中 <b>{pct(t.cache_hits ?? 0, evaluations)}</b></>}
        />
        <Kpi
          title={enforce ? "已拦截" : "预计拦截"}
          tip={enforce ? "拦截模式下实际被拒绝的请求" : "按当前策略，拦截模式下将被拒绝的请求；影子模式下未实际拦截"}
          value={fmt(blocked)}
          unit="次"
          tone={blocked ? "danger" : undefined}
          foot={<>占受审查请求 <b>{pct(blocked, t.guarded ?? 0)}</b></>}
        />
        <Kpi
          title="分类调用"
          tip="实际调用分类模型的次数（不含缓存命中），反映审查容量消耗"
          value={fmt(t.new_turns ?? 0)}
          unit="次"
          foot={<>单分钟峰值 <b>{fmt(st.peak_new_turns_per_minute)}</b> 次</>}
        />
        <Kpi
          title="分类时延 P95"
          tip="分类模型单次调用耗时的 95 分位，取直方图分档上界"
          value={bound(st.latency_p95_ms)}
          tone={slow ? "warn" : undefined}
          foot={<>中位数 <b>{bound(st.latency_p50_ms)}</b>，P99 <b>{bound(st.latency_p99_ms)}</b></>}
        />
        <Kpi
          title="审查异常"
          tip="分类超时、繁忙、不可用或输出无法解析的次数。底部 5xx 响应包含网关自身 503 与上游返回的 5xx 状态码（网关未做来源分拆）"
          value={fmt(t.cls_errors ?? 0)}
          unit="次"
          tone={t.cls_errors ? "warn" : undefined}
          foot={<>审查不可用 <b>{fmt(unavailable)}</b>，5xx 响应 <b>{fmt(t.status_5xx ?? 0)}</b></>}
        />
      </div>

      <Section
        title="请求趋势"
        hint={`${RANGE_NAMES[range]}，每 ${stepName}一个统计点`}
        action={
          <div className="flex flex-wrap justify-end gap-1">
            {lines.map((l) => (
              <button
                key={l.key}
                type="button"
                aria-pressed={!hidden.has(l.key)}
                onClick={() => toggle(l.key)}
                className="flex items-center gap-1.5 rounded-md px-2 py-1 text-xs text-muted-foreground hover:bg-muted aria-[pressed=false]:opacity-40"
              >
                <span className={cn("size-2", l.bar ? "rounded-[2px]" : "rounded-full")} style={{ background: l.color }} />
                {l.name}
              </button>
            ))}
          </div>
        }
      >
        <TrendChart series={st.series} range={range} blockKey={blockKey} hidden={hidden} />
      </Section>

      {st.coverage && <CoverageSection cov={st.coverage} />}

      <div className="grid gap-4 md:grid-cols-2">
        <Section title="审查判定">
          <DonutChart items={decisions} center="受审查" empty="暂无受审查请求" />
        </Section>
        <Section title="分类结果">
          <DonutChart items={labels} center="评估总数" empty="暂无分类结果" />
        </Section>
        <Section title="风险类别" hint="分类结果为不安全或有争议时给出">
          <RankList items={cats} color="var(--chart-4)" empty="未命中风险类别" />
        </Section>
        <Section title="判定原因" hint="出现次数最多的 8 项">
          <RankList items={reasons} color="var(--chart-1)" empty="暂无数据" />
        </Section>
      </div>
    </div>
  )
}
