import * as React from "react"
import { ChevronLeft, ChevronRight, Search, ShieldAlert, X } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Toggle } from "@/components/ui/toggle"
import { EmptyState, PageHeader } from "@/components/console/bits"
import { EventSheet, EventTable } from "@/components/console/events"
import { DECISIONS, fmt, keyName, LABELS, protoName, reasonName } from "@/lib/format"
import { EMPTY_FILTER, useStore, type EventFilter } from "@/lib/store"
import { useDocked } from "@/hooks/use-docked"
import type { AuditEvent } from "@/lib/types"

const PAGE_SIZE = 20
const ALL = "__all"
const NONE = "_none"
const key = (e: AuditEvent) => e.trace_id + e.timestamp

function matches(e: AuditEvent, f: EventFilter) {
  const q = f.q.trim().toLowerCase()
  return (
    (!f.decision || e.decision === f.decision) &&
    (!f.label || (f.label === NONE ? !e.label : e.label === f.label)) &&
    (!f.protocol || e.protocol === f.protocol) &&
    (!f.blockedOnly || !!(e.would_block || e.enforced)) &&
    (!f.credential || e.credential_hmac === f.credential) &&
    (!f.client || e.client === f.client) &&
    (!f.model || e.model === f.model) &&
    (!q ||
      [e.trace_id, e.path_template, reasonName(e.reason_code), e.reason_code, protoName(e.protocol), e.client, e.model].some(
        (v) => v && v.toLowerCase().includes(q)
      ))
  )
}

export function FilterSelect({
  value,
  onChange,
  all,
  options,
  label,
}: {
  value: string
  onChange: (v: string) => void
  all: string
  options: [string, string][]
  label: string
}) {
  const items = [{ value: ALL, label: all }, ...options.map(([value, label]) => ({ value, label }))]
  return (
    <Select items={items} value={value || ALL} onValueChange={(v) => onChange(!v || v === ALL ? "" : String(v))}>
      <SelectTrigger size="sm" className={value ? "border-foreground/30 bg-muted/50" : ""} aria-label={label}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {items.map((i) => (
          <SelectItem key={i.value} value={i.value}>
            {i.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

function Pager({ page, pages, go }: { page: number; pages: number; go: (p: number) => void }) {
  const nums: number[] = []
  for (let p = 1; p <= pages; p++) if (p === 1 || p === pages || Math.abs(p - page) <= 1) nums.push(p)
  return (
    <div className="flex items-center gap-1">
      <Button variant="ghost" size="icon-sm" disabled={page <= 1} onClick={() => go(page - 1)} aria-label="上一页">
        <ChevronLeft />
      </Button>
      {nums.map((p, i) => (
        <React.Fragment key={p}>
          {i > 0 && p - nums[i - 1] > 1 && <span className="w-6 text-center text-muted-foreground">…</span>}
          <Button
            variant={p === page ? "outline" : "ghost"}
            size="icon-sm"
            className="tabular-nums"
            onClick={() => go(p)}
            aria-current={p === page ? "page" : undefined}
          >
            {p}
          </Button>
        </React.Fragment>
      ))}
      <Button variant="ghost" size="icon-sm" disabled={page >= pages} onClick={() => go(page + 1)} aria-label="下一页">
        <ChevronRight />
      </Button>
    </div>
  )
}

export function EventsPage() {
  const { events, summary, config, filter: f, setFilter } = useStore()
  const docked = useDocked()
  // the page number belongs to one filter; any filter change goes back to page 1
  const [paging, setPaging] = React.useState({ f, page: 1 })
  const page = paging.f === f ? paging.page : 1
  const setPage = (p: number) => setPaging({ f, page: p })
  // keyed by event, not index: polling prepends new events while the drawer is open
  const [openKey, setOpenKey] = React.useState<string | null>(null)
  const query = React.useDeferredValue(f)

  const enforce = summary?.mode === "enforce"
  const set = (patch: Partial<EventFilter>) => setFilter((x) => ({ ...x, ...patch }))
  const uniq = (k: "decision" | "label" | "protocol" | "credential_hmac" | "client" | "model") => {
    const v = new Set(events.map((e) => e[k]).filter(Boolean) as string[])
    // a filter that came in through the URL stays selectable even if no recent event has it
    const cur = { credential_hmac: f.credential, client: f.client, model: f.model }[k as string]
    if (cur) v.add(cur)
    return [...v]
  }
  const active = !!(f.decision || f.label || f.protocol || f.blockedOnly || f.q || f.credential || f.client || f.model)

  const rows = React.useMemo(() => events.filter((e) => matches(e, query)), [events, query])
  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE))
  const cur = Math.min(page, pages)
  const offset = (cur - 1) * PAGE_SIZE
  const shown = rows.slice(offset, offset + PAGE_SIZE)
  const open = openKey == null ? -1 : rows.findIndex((e) => key(e) === openKey)

  return (
    // Reserve the docked detail panel's width (EventSheet, max-w-md) while one is open.
    <div className={`flex flex-col gap-5 ${docked && open >= 0 ? "pr-[28rem]" : ""}`}>
      <PageHeader title="审计事件" description="最近 500 条受审查请求的元数据，不含请求正文。点击任一行查看详情。" />
      <Card className="gap-0 py-0 shadow-none">
        <div className="flex flex-wrap items-center gap-2 border-b p-3">
          <div className="relative w-full lg:w-72">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              type="search"
              value={f.q}
              onChange={(e) => set({ q: e.target.value })}
              placeholder="搜索请求 ID、接口路径、判定原因"
              aria-label="搜索"
              className="h-8 pl-8"
            />
          </div>
          <FilterSelect
            label="审查判定"
            value={f.decision}
            onChange={(v) => set({ decision: v })}
            all="全部判定"
            options={uniq("decision").map((d) => [d, DECISIONS[d]?.name ?? d])}
          />
          <FilterSelect
            label="分类结果"
            value={f.label}
            onChange={(v) => set({ label: v })}
            all="全部分类结果"
            options={[...uniq("label").map((l): [string, string] => [l, LABELS[l]?.name ?? l]), [NONE, "未分类"]]}
          />
          <FilterSelect
            label="接口类型"
            value={f.protocol}
            onChange={(v) => set({ protocol: v })}
            all="全部接口"
            options={uniq("protocol").map((p) => [p, protoName(p)])}
          />
          <FilterSelect
            label="API Key"
            value={f.credential}
            onChange={(v) => set({ credential: v })}
            all="全部 Key"
            options={uniq("credential_hmac").map((k) => [k, keyName(k, config?.aliases)])}
          />
          <FilterSelect
            label="客户端"
            value={f.client}
            onChange={(v) => set({ client: v })}
            all="全部客户端"
            options={uniq("client").map((c) => [c, c])}
          />
          <FilterSelect
            label="模型"
            value={f.model}
            onChange={(v) => set({ model: v })}
            all="全部模型"
            options={uniq("model").map((m) => [m, m])}
          />
          <Toggle
            variant="outline"
            size="sm"
            pressed={f.blockedOnly}
            onPressedChange={(p) => set({ blockedOnly: p })}
            className={
              enforce
                ? "aria-pressed:border-red-500/40 aria-pressed:bg-red-500/8 aria-pressed:text-red-700 dark:aria-pressed:text-red-400"
                : "aria-pressed:border-amber-500/40 aria-pressed:bg-amber-500/8 aria-pressed:text-amber-700 dark:aria-pressed:text-amber-400"
            }
          >
            <ShieldAlert />
            {enforce ? "仅看已拦截" : "仅看预计拦截"}
          </Toggle>
          {active && (
            <Button variant="ghost" size="sm" className="text-muted-foreground" onClick={() => setFilter(EMPTY_FILTER)}>
              <X />
              清除筛选
            </Button>
          )}
        </div>
        {shown.length ? (
          <EventTable rows={shown} compact={docked && open >= 0} selected={openKey} onOpen={(e) => setOpenKey(key(e))} />
        ) : (
          <EmptyState text={events.length ? "没有符合条件的事件，试试调整筛选条件" : "暂无受审查请求"} />
        )}
        {rows.length > 0 && (
          <div className="flex flex-wrap items-center justify-between gap-2 border-t px-4 py-2 text-xs text-muted-foreground">
            <span className="tabular-nums">
              第 {fmt(offset + 1)}–{fmt(offset + shown.length)} 条，共 {fmt(rows.length)} 条
              {rows.length !== events.length && `（全部 ${fmt(events.length)} 条）`}
            </span>
            <Pager page={cur} pages={pages} go={setPage} />
          </div>
        )}
      </Card>
      <EventSheet
        events={rows}
        index={open < 0 ? null : open}
        onIndex={(i) => setOpenKey(i == null ? null : key(rows[i]))}
        enforce={enforce}
      />
    </div>
  )
}
