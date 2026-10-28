import * as React from "react"

import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table"
import { EmptyState, Meter, PageHeader, Section, StatusDot } from "@/components/console/bits"
import { LatencyChart } from "@/components/console/charts"
import { classifierHealth } from "@/pages/home"
import { ago, bound, bytes, clsStatus, dt, dur, fmt, goDur, RANGE_NAMES } from "@/lib/format"
import { useStore } from "@/lib/store"

type Kind = "bytes" | "context" | "perMin" | "dur" | "n"

const SETTINGS: [string, [string, string, Kind][]][] = [
  [
    "内容审查",
    [
      ["primary_budget_bytes", "单次送审文本上限", "bytes"],
      ["context_budget_bytes", "送审上下文上限", "context"],
      ["max_body_bytes", "请求体大小上限", "bytes"],
      ["extract_concurrency", "内容抽取并发数", "n"],
      ["review_per_ip_per_minute", "单来源审查频率上限", "perMin"],
      ["review_per_credential_per_minute", "单凭据审查频率上限", "perMin"],
    ],
  ],
  [
    "分类服务",
    [
      ["classifier_timeout", "单次分类超时", "dur"],
      ["classifier_max_concurrency", "最大并发调用", "n"],
      ["classifier_max_queue", "最大排队数", "n"],
      ["classifier_queue_wait", "排队等待上限", "dur"],
      ["cache_ttl", "结论缓存有效期", "dur"],
      ["cache_entries", "结论缓存条数", "n"],
    ],
  ],
  [
    "请求缓冲",
    [
      ["spool_max_total_bytes", "缓冲总量上限", "bytes"],
      ["spool_max_files", "缓冲文件数上限", "n"],
    ],
  ],
]

function fmtSetting(v: number | string | undefined, kind: Kind) {
  if (v == null) return "—"
  if (kind === "dur") return goDur(v)
  const n = Number(v)
  if (kind === "bytes") return bytes(n)
  if (kind === "context") return n ? bytes(n) : "不送审"
  if (kind === "perMin") return n ? `${fmt(n)} 次/分钟` : "不限制"
  return fmt(n)
}

function Stat({ k, children, sub }: { k: string; children: React.ReactNode; sub?: React.ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <span className="text-xs text-muted-foreground">{k}</span>
      <span className="truncate text-sm font-medium">{children}</span>
      {sub && <span className="truncate text-xs text-muted-foreground">{sub}</span>}
    </div>
  )
}

function Usage({ k, value, max, show, hint }: { k: string; value: number; max: number; show: (n: number) => string; hint?: string }) {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-baseline justify-between gap-2 text-sm">
        <span className="text-muted-foreground">{k}</span>
        <span className="tabular-nums">
          <span className="font-medium">{show(value)}</span>
          <span className="text-muted-foreground"> / {show(max)}</span>
        </span>
      </div>
      <Meter value={value} max={max} />
      {hint && <span className="text-xs text-muted-foreground">{hint}</span>}
    </div>
  )
}

export function SystemPage() {
  const { summary, config, range, lastOk } = useStore()
  if (!summary) return null
  const hl = summary.health
  const st = summary.stats
  const set = config?.settings ?? {}
  const num = (k: string) => Number(set[k] ?? 0)
  const h = hl ? classifierHealth(hl) : null
  // measured at the last successful sync so render stays pure; it advances with each poll
  const up = Math.max(0, (lastOk - new Date(summary.started_at).getTime()) / 1000)

  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="系统状态" description="分类服务、请求缓冲与运行参数" />
      <div className="grid gap-4 lg:grid-cols-2">
        <Section
          title="分类服务"
          action={hl && h && <StatusDot tone={h.tone} className="text-sm">{h.label}</StatusDot>}
        >
          {hl && h ? (
            <div className="flex flex-col gap-5">
              <div className="grid grid-cols-3 gap-4 rounded-lg bg-muted/40 p-3">
                <Stat k="分类模型">
                  <span className="font-mono text-xs">{summary.model || "—"}</span>
                </Stat>
                <Stat k="最近成功" sub={h.okT ? dt(new Date(h.okT)) : undefined}>
                  {ago(hl.last_ok)}
                </Stat>
                <Stat k="最近失败" sub={h.failT ? clsStatus(hl.last_failure_status) : undefined}>
                  {ago(hl.last_failure)}
                </Stat>
              </div>
              <Usage k="进行中调用" value={hl.in_flight} max={num("classifier_max_concurrency")} show={fmt} />
              <Usage
                k="排队中"
                value={hl.waiting}
                max={num("classifier_max_queue")}
                show={fmt}
                hint="排队超出上限时，拦截模式返回“审查不可用”"
              />
            </div>
          ) : (
            <EmptyState text="内容审查已停用" />
          )}
        </Section>
        <Section
          title="网关进程"
          action={
            summary.audit_failures ? (
              <StatusDot tone="danger" className="text-sm">审计写入异常</StatusDot>
            ) : (
              <StatusDot tone="ok" className="text-sm">运行正常</StatusDot>
            )
          }
        >
          <div className="flex flex-col gap-5">
            <div className="grid grid-cols-2 gap-4 rounded-lg bg-muted/40 p-3">
              <Stat k="运行时长" sub={`启动于 ${dt(new Date(summary.started_at))}`}>
                {dur(up)}
              </Stat>
              <Stat k="审计写入失败" sub={summary.audit_failures ? "请检查 journald" : "审计日志写入正常"}>
                <span className={summary.audit_failures ? "text-red-600 dark:text-red-400 font-medium" : ""}>{fmt(summary.audit_failures)} 次</span>
              </Stat>
            </div>
            {hl && (
              <>
                <Usage k="请求缓冲占用" value={hl.spool_bytes} max={num("spool_max_total_bytes")} show={bytes} />
                <Usage k="缓冲文件" value={hl.spool_files} max={num("spool_max_files")} show={fmt} />
              </>
            )}
          </div>
        </Section>
      </div>
      <div className="grid items-start gap-4 lg:grid-cols-[3fr_2fr]">
        <Section
          title="分类时延分布"
          hint={`${RANGE_NAMES[range]}，仅统计实际调用（不含缓存命中）`}
          action={
            <div className="flex gap-4 text-xs">
              {(
                [
                  ["P50", st.latency_p50_ms],
                  ["P95", st.latency_p95_ms],
                  ["P99", st.latency_p99_ms],
                ] as const
              ).map(([k, v]) => (
                <span key={k} className="flex flex-col items-end">
                  <span className="text-muted-foreground">{k}</span>
                  <span className="font-medium tabular-nums">{bound(v)}</span>
                </span>
              ))}
            </div>
          }
        >
          <LatencyChart hist={st.totals.lat ?? []} bounds={st.latency_bounds_ms ?? []} />
        </Section>
        <Section title="运行参数" hint="只读，来自网关配置文件" flush>
          <Table>
            <TableBody>
              {SETTINGS.map(([group, rows]) => (
                <React.Fragment key={group}>
                  <TableRow className="bg-muted/25 hover:bg-muted/25">
                    <TableCell colSpan={2} className="py-2 text-xs font-medium text-muted-foreground">
                      {group}
                    </TableCell>
                  </TableRow>
                  {rows.map(([k, name, kind]) => (
                    <TableRow key={k}>
                      <TableCell className="text-muted-foreground">{name}</TableCell>
                      <TableCell className="text-right tabular-nums">{fmtSetting(set[k], kind)}</TableCell>
                    </TableRow>
                  ))}
                </React.Fragment>
              ))}
            </TableBody>
          </Table>
        </Section>
      </div>
    </div>
  )
}
