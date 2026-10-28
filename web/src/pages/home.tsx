import * as React from "react"
import { ArrowRight, ChevronRight, CircleAlert, CircleSlash, ServerCrash, ShieldAlert } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { EmptyState, Meter, PageHeader, Section, StatusDot } from "@/components/console/bits"
import { MetricChart } from "@/components/console/charts"
import { EventSheet, EventTable } from "@/components/console/events"
import { cn } from "@/lib/utils"
import { big, dur, fmt, isZeroTime, MODES, RANGE_NAMES, type Tone } from "@/lib/format"
import { useStore, type EventFilter } from "@/lib/store"
import type { AuditEvent, Health } from "@/lib/types"

export function classifierHealth(h: Health) {
  const okT = isZeroTime(h.last_ok) ? 0 : new Date(h.last_ok).getTime()
  const failT = isZeroTime(h.last_failure) ? 0 : new Date(h.last_failure).getTime()
  const failing = failT > okT
  return {
    okT,
    failT,
    failing,
    label: failing ? "异常" : okT ? "正常" : "尚无调用",
    tone: (failing ? "danger" : okT ? "ok" : "warn") as Tone,
  }
}

const ICON_TONES: Record<string, string> = {
  danger: "bg-red-500/10 text-red-600 dark:text-red-400",
  warn: "bg-amber-500/12 text-amber-600 dark:text-amber-400",
  violet: "bg-violet-500/10 text-violet-600 dark:text-violet-400",
  info: "bg-sky-500/10 text-sky-600 dark:text-sky-400",
}

const needsAttention = (e: AuditEvent) =>
  !!(e.would_block || e.enforced) || ["review", "unavailable", "unsupported"].includes(e.decision)

type Metric = "req" | "blocked" | "new_turns"

function TrafficCard() {
  const { summary, range } = useStore()
  const [metric, setMetric] = React.useState<Metric>("req")
  if (!summary) return null
  const st = summary.stats
  const enforce = summary.mode === "enforce"
  const blockKey = enforce ? "enforced" : "would_block"
  const metrics: Record<Metric, { label: string; total: number; color: string; key: "req" | "new_turns" | typeof blockKey }> = {
    req: { label: "请求", total: st.totals.req, color: "var(--chart-1)", key: "req" },
    blocked: { label: enforce ? "拦截" : "预计拦截", total: st.totals[blockKey] ?? 0, color: "var(--chart-4)", key: blockKey },
    new_turns: { label: "分类调用", total: st.totals.new_turns ?? 0, color: "var(--chart-3)", key: "new_turns" },
  }
  const m = metrics[metric]
  return (
    <Card className="gap-0 py-0 shadow-none">
      <div className="flex flex-col border-b sm:flex-row">
        <CardHeader className="flex-1 content-center py-4">
          <CardTitle className="text-sm">流量概况</CardTitle>
          <CardDescription className="text-xs">{RANGE_NAMES[range]}，按统计点汇总</CardDescription>
        </CardHeader>
        <div className="flex border-t sm:border-t-0">
          {(Object.keys(metrics) as Metric[]).map((k) => (
            <button
              key={k}
              type="button"
              data-active={metric === k}
              onClick={() => setMetric(k)}
              className="flex flex-1 flex-col justify-center gap-1 border-l px-5 py-3 text-left transition-colors first:border-l-0 hover:bg-muted/40 data-[active=true]:bg-muted/60 sm:min-w-32 sm:first:border-l sm:px-6"
            >
              <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <span className="size-2 rounded-full" style={{ background: metrics[k].color }} />
                {metrics[k].label}
              </span>
              <span className="text-xl font-semibold tabular-nums">{big(metrics[k].total)}</span>
            </button>
          ))}
        </div>
      </div>
      <div className="px-2 pt-4 pb-2 sm:px-4">
        <MetricChart series={st.series} range={range} dataKey={m.key} label={m.label} color={m.color} />
      </div>
    </Card>
  )
}

export function HomePage() {
  const { summary, events, config, navigate, lastOk } = useStore()
  const [openKey, setOpenKey] = React.useState<string | null>(null)
  const recent = React.useMemo(() => events.filter(needsAttention), [events])
  if (!summary) return null
  const { health } = summary
  const enforce = summary.mode === "enforce"
  const settings = config?.settings ?? {}
  const num = (k: string) => Number(settings[k] ?? 0)
  const count = (fn: (e: AuditEvent) => boolean) => events.filter(fn).length
  const h = health ? classifierHealth(health) : null
  const mode = MODES[summary.mode]
  const up = Math.max(0, (lastOk - new Date(summary.started_at).getTime()) / 1000)

  const todo: { title: string; desc: string; n: number; tone: string; icon: typeof ShieldAlert; filter: Partial<EventFilter> }[] = [
    {
      title: enforce ? "已拦截的请求" : "预计拦截的请求",
      desc: enforce ? "按策略被网关拒绝" : "切换到拦截模式后会被拒绝，上线前需逐条复核",
      n: count((e) => !!(e.would_block || e.enforced)),
      tone: "danger",
      icon: ShieldAlert,
      filter: { blockedOnly: true },
    },
    {
      title: "待复核",
      desc: "分类结果有争议，或命中需人工复核的风险类别",
      n: count((e) => e.decision === "review"),
      tone: "warn",
      icon: CircleAlert,
      filter: { decision: "review" },
    },
    {
      title: "审查不可用",
      desc: "分类服务超时、繁忙或不可用，未得出结论",
      n: count((e) => e.decision === "unavailable"),
      tone: "violet",
      icon: ServerCrash,
      filter: { decision: "unavailable" },
    },
    {
      title: "未覆盖的接口",
      desc: "请求的接口尚未纳入内容审查",
      n: count((e) => e.decision === "unsupported"),
      tone: "info",
      icon: CircleSlash,
      filter: { decision: "unsupported" },
    },
  ]

  const shown = recent.slice(0, 6)
  const openIndex = openKey == null ? -1 : recent.findIndex((e) => e.trace_id + e.timestamp === openKey)

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="工作台"
        description={
          <>
            {mode.name}运行中 · 策略 <span className="font-mono text-xs">{summary.policy_version || "—"}</span> · 已运行 {dur(up)}
          </>
        }
        actions={
          <Button variant="outline" size="sm" nativeButton={false} render={<a href="#/events" />}>
            查看审计事件
            <ArrowRight />
          </Button>
        }
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <Section
          title="实时告警队列（最近 500 条内存记录）"
          hint="基于网关最新 500 条内存审计事件；用于即时排查，不受全局时间选择器影响"
          flush
          className="lg:col-span-2"
        >
          <ul className="divide-y">
            {todo.map((t) => (
              <li key={t.title}>
                <button
                  type="button"
                  onClick={() => navigate("events", t.filter)}
                  className="group flex w-full items-center gap-4 px-4 py-3.5 text-left transition-colors hover:bg-muted/40"
                >
                  <span
                    className={cn(
                      "grid size-9 shrink-0 place-items-center rounded-lg",
                      !t.n ? "bg-muted text-muted-foreground/60" : ICON_TONES[t.tone]
                    )}
                  >
                    <t.icon className="size-4.5" />
                  </span>
                  <span className="flex min-w-0 flex-1 flex-col">
                    <span className="text-sm font-medium">{t.title}</span>
                    <span className="truncate text-xs text-muted-foreground">{t.desc}</span>
                  </span>
                  <span
                    className={cn(
                      "text-lg tabular-nums",
                      !t.n ? "font-normal text-muted-foreground/40" : "font-semibold"
                    )}
                  >
                    {fmt(t.n)}
                  </span>
                  <ChevronRight className="size-4 text-muted-foreground/40 transition-colors group-hover:text-foreground" />
                </button>
              </li>
            ))}
          </ul>
        </Section>

        <Section
          title="运行状态"
          action={
            <Button variant="ghost" size="xs" className="text-muted-foreground" nativeButton={false} render={<a href="#/system" />}>
              详情
              <ChevronRight />
            </Button>
          }
        >
          <dl className="flex flex-col gap-3.5 text-sm">
            <div className="flex items-center justify-between">
              <dt className="text-muted-foreground">运行模式</dt>
              <dd>
                <StatusDot tone={enforce ? "danger" : summary.mode === "shadow" ? "warn" : "muted"}>{mode.name}</StatusDot>
              </dd>
            </div>
            <div className="flex items-center justify-between">
              <dt className="text-muted-foreground">分类服务</dt>
              <dd>{h ? <StatusDot tone={h.tone}>{h.label}</StatusDot> : "已停用"}</dd>
            </div>
            <div className="flex items-center justify-between">
              <dt className="text-muted-foreground">审计日志</dt>
              <dd>
                {summary.audit_failures ? (
                  <StatusDot tone="danger">写入失败 {fmt(summary.audit_failures)} 次</StatusDot>
                ) : (
                  <StatusDot tone="ok">写入正常</StatusDot>
                )}
              </dd>
            </div>
            {health && (
              <>
                <div className="flex flex-col gap-1.5">
                  <div className="flex justify-between">
                    <dt className="text-muted-foreground">分类并发</dt>
                    <dd className="tabular-nums">
                      {fmt(health.in_flight)} <span className="text-muted-foreground">/ {fmt(num("classifier_max_concurrency"))}</span>
                    </dd>
                  </div>
                  <Meter value={health.in_flight} max={num("classifier_max_concurrency")} />
                </div>
                <div className="flex flex-col gap-1.5">
                  <div className="flex justify-between">
                    <dt className="text-muted-foreground">排队</dt>
                    <dd className="tabular-nums">
                      {fmt(health.waiting)} <span className="text-muted-foreground">/ {fmt(num("classifier_max_queue"))}</span>
                    </dd>
                  </div>
                  <Meter value={health.waiting} max={num("classifier_max_queue")} />
                </div>
              </>
            )}
          </dl>
        </Section>
      </div>

      <TrafficCard />

      <Section
        title="最近需关注的事件"
        hint="预计拦截、待复核、审查不可用与未覆盖的请求"
        flush
        action={
          recent.length > shown.length && (
            <Button variant="ghost" size="xs" className="text-muted-foreground" onClick={() => navigate("events", {})}>
              查看全部
              <ChevronRight />
            </Button>
          )
        }
      >
        {shown.length ? (
          <EventTable rows={shown} compact onOpen={(e) => setOpenKey(e.trace_id + e.timestamp)} />
        ) : (
          <EmptyState text="最近没有需要关注的事件" />
        )}
      </Section>
      <EventSheet
        events={recent}
        index={openIndex < 0 ? null : openIndex}
        onIndex={(i) => setOpenKey(i == null ? null : recent[i].trace_id + recent[i].timestamp)}
        enforce={enforce}
      />
    </div>
  )
}
