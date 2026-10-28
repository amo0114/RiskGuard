import * as React from "react"
import { cn } from "@/lib/utils"
import { CircleHelp, Inbox } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia } from "@/components/ui/empty"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { ACTIONS, DECISIONS, LABELS, type Tone } from "@/lib/format"

const TONES: Record<Tone, string> = {
  ok: "bg-emerald-500/10 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-400",
  warn: "bg-amber-500/12 text-amber-700 dark:bg-amber-500/15 dark:text-amber-400",
  danger: "bg-red-500/10 text-red-700 dark:bg-red-500/15 dark:text-red-400",
  info: "bg-sky-500/10 text-sky-700 dark:bg-sky-500/15 dark:text-sky-400",
  violet: "bg-violet-500/10 text-violet-700 dark:bg-violet-500/15 dark:text-violet-400",
  muted: "bg-muted text-muted-foreground",
}

export const DOTS: Record<Tone, string> = {
  ok: "bg-emerald-500",
  warn: "bg-amber-500",
  danger: "bg-red-500",
  info: "bg-sky-500",
  violet: "bg-violet-500",
  muted: "bg-zinc-400",
}

export function ToneBadge({ tone, className, children }: { tone: Tone; className?: string; children: React.ReactNode }) {
  return (
    <Badge variant="secondary" className={cn("font-normal", TONES[tone], className)}>
      {children}
    </Badge>
  )
}

/** Quiet status text with a coloured dot; reads better than filled pills in dense tables. */
export function StatusDot({ tone, children, className }: { tone: Tone; children: React.ReactNode; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5", className)}>
      <span className={cn("size-1.5 shrink-0 rounded-full", DOTS[tone])} />
      {children}
    </span>
  )
}

export const DecisionBadge = ({ d }: { d: string }) => {
  const x = DECISIONS[d] ?? { name: d, tone: "muted" as Tone }
  return <StatusDot tone={x.tone}>{x.name}</StatusDot>
}

export const LabelBadge = ({ l }: { l?: string }) => {
  if (!l) return <span className="text-muted-foreground">—</span>
  const x = LABELS[l] ?? { name: l, tone: "muted" as Tone }
  return <ToneBadge tone={x.tone}>{x.name}</ToneBadge>
}

export const ActionBadge = ({ a }: { a?: string }) => {
  const x = (a && ACTIONS[a]) || { name: a || "—", tone: "muted" as Tone }
  return <ToneBadge tone={x.tone}>{x.name}</ToneBadge>
}

export const BlockedBadge = ({ enforced }: { enforced?: boolean }) => (
  <Badge
    variant="outline"
    className={cn(
      "h-5 px-1.5 text-[11px] font-normal",
      enforced
        ? "border-red-500/30 text-red-700 bg-red-500/5 dark:bg-red-500/15 dark:text-red-400"
        : "border-amber-500/30 text-amber-700 bg-amber-500/5 dark:bg-amber-500/15 dark:text-amber-400"
    )}
  >
    {enforced ? "已拦截" : "模拟拦截"}
  </Badge>
)

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string
  description: React.ReactNode
  actions?: React.ReactNode
}) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-3 pt-2 pb-1">
      <div className="flex min-w-0 flex-col gap-1">
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  )
}

/**
 * Card with a title row. `flush` is for tables and lists: the header gets a divider and the
 * content runs edge to edge.
 */
export function Section({
  title,
  hint,
  action,
  flush,
  className,
  contentClassName,
  children,
}: {
  title: React.ReactNode
  hint?: React.ReactNode
  action?: React.ReactNode
  flush?: boolean
  className?: string
  contentClassName?: string
  children: React.ReactNode
}) {
  return (
    <Card className={cn("shadow-none", flush && "gap-0 pb-0", className)}>
      <CardHeader className={cn(flush && "border-b")}>
        <CardTitle className="text-sm">{title}</CardTitle>
        {hint && <CardDescription className="text-xs">{hint}</CardDescription>}
        {action && <CardAction>{action}</CardAction>}
      </CardHeader>
      <CardContent className={cn(flush && "px-0", contentClassName)}>{children}</CardContent>
    </Card>
  )
}

export function Hint({ children }: { children: React.ReactNode }) {
  return (
    <Tooltip>
      <TooltipTrigger
        render={<button type="button" className="text-muted-foreground/60 hover:text-foreground" aria-label="说明" />}
      >
        <CircleHelp className="size-3.5" />
      </TooltipTrigger>
      <TooltipContent className="max-w-64">{children}</TooltipContent>
    </Tooltip>
  )
}

export function EmptyState({ text, className }: { text: string; className?: string }) {
  return (
    <Empty className={cn("border-0 py-10", className)}>
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <Inbox />
        </EmptyMedia>
        <EmptyDescription>{text}</EmptyDescription>
      </EmptyHeader>
    </Empty>
  )
}

/** Label/value rows; one column in narrow containers, two side by side otherwise. */
export function DescList({ items, cols = 2 }: { items: [string, React.ReactNode][]; cols?: 1 | 2 }) {
  return (
    <dl className={cn("grid gap-x-8 text-sm", cols === 2 && "sm:grid-cols-2")}>
      {items.map(([k, v], i) => (
        <div
          key={i}
          className={cn(
            "flex items-start gap-4 border-b border-dashed py-2.5 last:border-b-0",
            cols === 2 && "sm:[&:nth-last-child(2):nth-child(odd)]:border-b-0"
          )}
        >
          <dt className="w-24 shrink-0 text-muted-foreground">{k}</dt>
          <dd className="min-w-0 flex-1 break-all">{v ?? "—"}</dd>
        </div>
      ))}
    </dl>
  )
}

export function Meter({ value, max }: { value: number; max?: number }) {
  const r = max ? Math.min(1, value / max) : 0
  return (
    <div className="h-1.5 overflow-hidden rounded-full bg-muted">
      <div
        className={cn("h-full rounded-full transition-all", r >= 0.9 ? "bg-red-500" : r >= 0.6 ? "bg-amber-500" : "bg-emerald-500")}
        style={{ width: `${Math.max(r * 100, value ? 2 : 0)}%` }}
      />
    </div>
  )
}
