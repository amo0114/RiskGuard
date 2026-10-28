import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, ComposedChart, Line, Pie, PieChart, XAxis, YAxis } from "recharts"

import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart"
import { EmptyState } from "@/components/console/bits"
import { axisNum, big, dt, fmt, ms, pct } from "@/lib/format"
import type { Bucket, RangeKey } from "@/lib/types"

export type TrendKey = "req" | "guarded" | "new_turns" | "would_block" | "enforced"

export function TrendChart({
  series,
  range,
  blockKey,
  hidden,
}: {
  series: Bucket[]
  range: RangeKey
  blockKey: "would_block" | "enforced"
  hidden: Set<TrendKey>
}) {
  const config = {
    req: { label: "请求总数", color: "var(--muted-foreground)" },
    guarded: { label: "受审查请求", color: "var(--chart-1)" },
    new_turns: { label: "分类调用", color: "var(--chart-3)" },
    [blockKey]: { label: blockKey === "enforced" ? "已拦截" : "预计拦截", color: "var(--chart-4)" },
  } satisfies ChartConfig
  const data = series.map((b) => ({
    t: b.m * 60_000,
    req: b.req ?? 0,
    guarded: b.guarded ?? 0,
    new_turns: b.new_turns ?? 0,
    [blockKey]: b[blockKey] ?? 0,
  }))
  const tick = (v: number) => dt(new Date(v), range === "7d" ? "short" : "time")
  return (
    <ChartContainer config={config} className="aspect-auto h-72 w-full" role="region" aria-label="请求量与受审查趋势图表">
      <ComposedChart data={data} margin={{ left: 4, right: 8, top: 8 }}>
        <defs>
          <linearGradient id="fill-guarded" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="var(--color-guarded)" stopOpacity={0.25} />
            <stop offset="95%" stopColor="var(--color-guarded)" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid vertical={false} />
        <XAxis dataKey="t" tickLine={false} axisLine={false} tickMargin={8} minTickGap={48} tickFormatter={tick} />
        <YAxis width={40} tickLine={false} axisLine={false} allowDecimals={false} tickFormatter={axisNum} />
        <ChartTooltip
          content={<ChartTooltipContent indicator="dot" labelFormatter={(_, p) => dt(new Date(p?.[0]?.payload?.t ?? 0), "short")} />}
        />
        {!hidden.has(blockKey) && <Bar dataKey={blockKey} isAnimationActive={false} fill={`var(--color-${blockKey})`} radius={2} maxBarSize={12} />}
        {!hidden.has("guarded") && (
          <Area dataKey="guarded" isAnimationActive={false} type="monotone" stroke="var(--color-guarded)" strokeWidth={2} fill="url(#fill-guarded)" />
        )}
        {!hidden.has("req") && (
          <Line dataKey="req" isAnimationActive={false} type="monotone" stroke="var(--color-req)" strokeDasharray="4 3" strokeWidth={1.5} dot={false} />
        )}
        {!hidden.has("new_turns") && (
          <Line dataKey="new_turns" isAnimationActive={false} type="monotone" stroke="var(--color-new_turns)" strokeWidth={1.5} dot={false} />
        )}
      </ComposedChart>
    </ChartContainer>
  )
}

export function MetricChart({
  series,
  range,
  dataKey,
  label,
  color,
}: {
  series: Bucket[]
  range: RangeKey
  dataKey: "req" | "new_turns" | "would_block" | "enforced"
  label: string
  color: string
}) {
  const config = { v: { label, color } } satisfies ChartConfig
  const data = series.map((b) => ({ t: b.m * 60_000, v: b[dataKey] ?? 0 }))
  const tick = (v: number) => dt(new Date(v), range === "7d" ? "short" : "time")
  return (
    <ChartContainer config={config} className="aspect-auto h-56 w-full" role="region" aria-label={`${label}趋势图表`}>
      <AreaChart data={data} margin={{ left: 4, right: 12, top: 8 }}>
        <defs>
          <linearGradient id="fill-metric" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="var(--color-v)" stopOpacity={0.3} />
            <stop offset="95%" stopColor="var(--color-v)" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid vertical={false} />
        <XAxis dataKey="t" tickLine={false} axisLine={false} tickMargin={8} minTickGap={56} tickFormatter={tick} />
        <YAxis width={36} tickLine={false} axisLine={false} allowDecimals={false} tickFormatter={axisNum} />
        <ChartTooltip
          content={<ChartTooltipContent indicator="line" labelFormatter={(_, p) => dt(new Date(p?.[0]?.payload?.t ?? 0), "short")} />}
        />
        <Area dataKey="v" type="monotone" stroke="var(--color-v)" strokeWidth={2} fill="url(#fill-metric)" isAnimationActive={false} />
      </AreaChart>
    </ChartContainer>
  )
}

export type Slice = { key: string; name: string; color: string; count: number }

export function DonutChart({ items, center, empty }: { items: Slice[]; center: string; empty: string }) {
  const total = items.reduce((a, b) => a + b.count, 0)
  if (!total) return <EmptyState text={empty} />
  const config = Object.fromEntries(items.map((i) => [i.key, { label: i.name, color: i.color }])) satisfies ChartConfig
  return (
    <div className="flex flex-wrap items-center justify-center gap-x-8 gap-y-4 py-1">
      <div className="relative size-36 shrink-0">
        <ChartContainer config={config} className="aspect-square size-36" role="region" aria-label={`${center}占比分布饼图`}>
          <PieChart>
            <ChartTooltip content={<ChartTooltipContent hideLabel nameKey="key" />} />
            <Pie data={items} isAnimationActive={false} dataKey="count" nameKey="key" innerRadius={50} outerRadius={68} strokeWidth={2} paddingAngle={items.length > 1 ? 1 : 0}>
              {items.map((i) => (
                <Cell key={i.key} fill={i.color} />
              ))}
            </Pie>
          </PieChart>
        </ChartContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-lg font-semibold tabular-nums">{big(total)}</span>
          <span className="text-[11px] text-muted-foreground">{center}</span>
        </div>
      </div>
      <ul className="flex min-w-40 flex-1 flex-col gap-2.5 text-sm">
        {items.map((i) => (
          <li key={i.key} className="flex items-center gap-2">
            <span className="size-2 shrink-0 rounded-full" style={{ background: i.color }} />
            <span className="flex-1 truncate text-muted-foreground">{i.name}</span>
            <span className="tabular-nums">{fmt(i.count)}</span>
            <span className="w-12 text-right text-xs text-muted-foreground tabular-nums">{pct(i.count, total)}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function RankList({ items, color, empty }: { items: { name: string; count: number }[]; color: string; empty: string }) {
  if (!items.length) return <EmptyState text={empty} />
  const max = Math.max(...items.map((i) => i.count))
  return (
    <ol className="flex flex-col gap-3.5 text-sm">
      {items.map((i) => (
        <li key={i.name} className="flex flex-col gap-1.5">
          <div className="flex items-center justify-between gap-3">
            <span className="truncate">{i.name}</span>
            <span className="tabular-nums">{fmt(i.count)}</span>
          </div>
          <div className="h-1 overflow-hidden rounded-full bg-muted">
            <div className="h-full rounded-full" style={{ width: `${(i.count / max) * 100}%`, background: color }} />
          </div>
        </li>
      ))}
    </ol>
  )
}

export function LatencyChart({ hist, bounds }: { hist: number[]; bounds: number[] }) {
  const total = hist.reduce((a, b) => a + b, 0)
  if (!total) return <EmptyState text="暂无分类调用" />
  const tick = (b: number) => (b >= 1000 ? `${b / 1000}s` : `${b}ms`)
  const data = [...bounds, -1].map((b, i) => ({
    bin: b < 0 ? `>${tick(bounds[bounds.length - 1])}` : `≤${tick(b)}`,
    name: b < 0 ? `超过 ${ms(bounds[bounds.length - 1])}` : `${i ? ms(bounds[i - 1]) : "0"} 至 ${ms(b)}`,
    count: hist[i] ?? 0,
    slow: b < 0 || b > 3000,
  }))
  const config = { count: { label: "调用次数", color: "var(--chart-1)" } } satisfies ChartConfig
  return (
    <ChartContainer config={config} className="aspect-auto h-56 w-full" role="region" aria-label="分类时延分布直方图">
      <BarChart data={data} margin={{ left: 4, right: 4, top: 8 }}>
        <CartesianGrid vertical={false} />
        <XAxis dataKey="bin" tickLine={false} axisLine={false} tickMargin={8} interval="preserveStartEnd" />
        <YAxis width={36} tickLine={false} axisLine={false} allowDecimals={false} tickFormatter={axisNum} />
        <ChartTooltip content={<ChartTooltipContent hideIndicator labelFormatter={(_, p) => p?.[0]?.payload?.name} />} />
        <Bar dataKey="count" isAnimationActive={false} radius={3}>
          {data.map((d) => (
            <Cell key={d.bin} fill={d.slow ? "var(--chart-3)" : "var(--color-count)"} />
          ))}
        </Bar>
      </BarChart>
    </ChartContainer>
  )
}
