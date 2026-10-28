import * as React from "react"
import { Check, ChevronLeft, ChevronRight, Copy } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { BlockedBadge, DecisionBadge, DescList, LabelBadge, ToneBadge } from "@/components/console/bits"
import { cn } from "@/lib/utils"
import { bytes, catName, clsStatus, COVERAGE, dt, fmt, keyName, MODES, ms, protoName, reasonName, when } from "@/lib/format"
import { useStore } from "@/lib/store"
import { useDocked } from "@/hooks/use-docked"
import type { AuditEvent } from "@/lib/types"

export const cats = (e: AuditEvent) => (e.categories?.length ? e.categories.map(catName).join("、") : "")
export const clsMs = (e: AuditEvent) =>
  e.cache_hit ? "缓存命中" : e.classifier_status && e.classifier_status !== "busy" ? ms(e.classifier_ms || 0) : "—"
const blocked = (e: AuditEvent) => !!(e.would_block || e.enforced)

function Decision({ e }: { e: AuditEvent }) {
  return (
    <span className="inline-flex items-center gap-2">
      <DecisionBadge d={e.decision} />
      {blocked(e) && <BlockedBadge enforced={e.enforced} />}
    </span>
  )
}

function Endpoint({ e }: { e: AuditEvent }) {
  const { config } = useStore()
  const who = [e.credential_hmac && keyName(e.credential_hmac, config?.aliases), e.client].filter(Boolean).join(" · ")
  return (
    <div className="min-w-0">
      <div className="truncate">
        {protoName(e.protocol)}
        {e.model && <span className="ml-1.5 text-xs text-muted-foreground">{e.model}</span>}
      </div>
      <div className="truncate font-mono text-[11px] text-muted-foreground" title={who || undefined}>
        {who || `${e.method} ${e.path_template}`}
      </div>
    </div>
  )
}

/** Desktop table; below md the same rows render as cards. */
export function EventTable({
  rows,
  onOpen,
  compact,
  selected,
}: {
  rows: AuditEvent[]
  onOpen: (e: AuditEvent) => void
  compact?: boolean
  selected?: string | null // trace_id + timestamp of the row shown in the detail panel
}) {
  return (
    <>
      <div className="hidden md:block">
        <Table className="table-fixed">
          <colgroup>
            <col className="w-28" />
            <col className="w-[22%]" />
            <col className="w-40" />
            {/* compact (beside a docked panel): the reason moves to the panel, labels take the slack */}
            {!compact && <col />}
            <col className={compact ? undefined : "w-52"} />
            {!compact && <col className="w-24" />}
            {!compact && <col className="w-20" />}
            {!compact && <col className="w-24" />}
            <col className="w-10" />
          </colgroup>
          <TableHeader>
            <TableRow>
              <TableHead>时间</TableHead>
              <TableHead>接口</TableHead>
              <TableHead>审查判定</TableHead>
              {!compact && <TableHead>判定原因</TableHead>}
              <TableHead>分类结果</TableHead>
              {!compact && <TableHead className="text-right">分类耗时</TableHead>}
              {!compact && <TableHead className="text-right">状态码</TableHead>}
              {!compact && <TableHead className="text-right">总耗时</TableHead>}
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((e) => (
              <TableRow
                key={e.trace_id + e.timestamp}
                onClick={() => onOpen(e)}
                aria-selected={selected === e.trace_id + e.timestamp}
                className={cn(
                  "group cursor-pointer aria-selected:bg-muted",
                  e.enforced
                    ? "shadow-[inset_2px_0_0_var(--color-red-500)]"
                    : e.would_block
                      ? "shadow-[inset_2px_0_0_var(--color-amber-500)]"
                      : undefined
                )}
              >
                <TableCell className="text-muted-foreground tabular-nums" title={dt(new Date(e.timestamp))}>
                  <button
                    type="button"
                    className="font-medium text-foreground hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 rounded"
                    onClick={(ev) => {
                      ev.stopPropagation()
                      onOpen(e)
                    }}
                  >
                    {when(e.timestamp)}
                  </button>
                </TableCell>
                <TableCell>
                  <Endpoint e={e} />
                </TableCell>
                <TableCell>
                  <Decision e={e} />
                </TableCell>
                {!compact && <TableCell className="truncate">{reasonName(e.reason_code)}</TableCell>}
                <TableCell>
                  <div className="flex min-w-0 items-center gap-2">
                    <LabelBadge l={e.label} />
                    {cats(e) && <span className="truncate text-xs text-muted-foreground">{cats(e)}</span>}
                  </div>
                </TableCell>
                {!compact && <TableCell className="text-right text-muted-foreground tabular-nums">{clsMs(e)}</TableCell>}
                {!compact && (
                  <TableCell className={cn("text-right tabular-nums", e.http_status >= 500 && "text-red-600 dark:text-red-400")}>
                    {e.http_status || "—"}
                  </TableCell>
                )}
                {!compact && <TableCell className="text-right tabular-nums">{ms(e.latency_ms)}</TableCell>}
                <TableCell>
                  <ChevronRight className="size-4 text-muted-foreground/40 transition-colors group-hover:text-foreground" />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <ul className="divide-y md:hidden">
        {rows.map((e) => (
          <li key={e.trace_id + e.timestamp}>
            <button
              type="button"
              onClick={() => onOpen(e)}
              className={cn(
                "flex w-full flex-col gap-1 px-4 py-3 text-left hover:bg-muted/50",
                e.enforced
                  ? "shadow-[inset_2px_0_0_var(--color-red-500)]"
                  : e.would_block
                    ? "shadow-[inset_2px_0_0_var(--color-amber-500)]"
                    : undefined
              )}
            >
              <div className="flex items-center justify-between gap-2">
                <Decision e={e} />
                <span className="text-xs text-muted-foreground tabular-nums">{when(e.timestamp)}</span>
              </div>
              <div className="text-sm">
                {protoName(e.protocol)}
                <span className="text-muted-foreground"> · {reasonName(e.reason_code)}</span>
              </div>
              <div className="truncate font-mono text-[11px] text-muted-foreground">
                {e.method} {e.path_template}
              </div>
            </button>
          </li>
        ))}
      </ul>
    </>
  )
}

// Question ids match internal/classifier.JudgeQuestions.
const AUX_QUESTIONS: [string, string][] = [
  ["dev", "正常开发或安全研究"],
  ["harmful", "寻求伤害或犯罪帮助"],
  ["jailbreak", "越狱或绕过指令"],
  ["self_harm", "自伤倾向"],
  ["hateful", "侮辱或歧视"],
  ["sexual", "色情内容"],
]

function AuxProb({ p }: { p?: number }) {
  if (p == null) return <span className="text-muted-foreground">—</span>
  return (
    <span className="flex items-center gap-3">
      <span className="h-1.5 w-24 overflow-hidden rounded-full bg-muted">
        <span className="block h-full rounded-full bg-foreground/50" style={{ width: `${p * 100}%` }} />
      </span>
      <span className="tabular-nums">{p.toFixed(2)}</span>
    </span>
  )
}

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="flex flex-col gap-1">
      <h4 className="text-xs font-medium text-muted-foreground">{title}</h4>
      {children}
    </section>
  )
}

/** Detail drawer over a list; arrows step through the same list the table shows. */
export function EventSheet({
  events,
  index,
  onIndex,
}: {
  events: AuditEvent[]
  index: number | null
  onIndex: (i: number | null) => void
  enforce?: boolean
}) {
  const { config } = useStore()
  const docked = useDocked()
  const [raw, setRaw] = React.useState(false)
  const [copied, setCopied] = React.useState(false)
  const e = index == null ? undefined : events[index]
  const yes = (b?: boolean) => (b ? "是" : "否")
  const mono = (s?: string) => (s ? <span className="font-mono text-xs">{s}</span> : "—")
  const copy = async (s: string) => {
    try {
      await navigator.clipboard.writeText(s)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      // clipboard needs a secure context; the ID stays selectable
    }
  }
  const step = (d: number) => index != null && onIndex(Math.min(events.length - 1, Math.max(0, index + d)))

  return (
    <Sheet
      open={!!e}
      // Docked beside the list (the page reserves the width): the list stays usable and a
      // click on another row just switches the panel.
      modal={!docked}
      disablePointerDismissal={docked}
      onOpenChange={(o) => {
        if (!o) {
          onIndex(null)
          setRaw(false)
        }
      }}
    >
      <SheetContent
        overlay={!docked}
        className={cn(
          "w-full gap-0 data-[side=right]:sm:max-w-md",
          // data-[side] variants: plain top/h would lose to the sheet's own data-[side=right] rules
          docked && "shadow-none data-[side=right]:top-14 data-[side=right]:h-[calc(100%-3.5rem)]"
        )}
      >
        {e && index != null && (
          <>
            <SheetHeader className="gap-3 border-b pb-4">
              <div className="flex flex-col gap-1">
                <SheetTitle className="flex items-center gap-2 text-base">
                  <Decision e={e} />
                </SheetTitle>
                <SheetDescription>{dt(new Date(e.timestamp))} · 仅记录元数据，不含请求正文</SheetDescription>
              </div>
              <div className="flex items-center gap-1 rounded-md bg-muted/60 py-1 pr-1 pl-2.5">
                <span className="flex-1 truncate font-mono text-xs">{e.trace_id}</span>
                <Button variant="ghost" size="icon-xs" aria-label="复制请求 ID" onClick={() => void copy(e.trace_id)}>
                  {copied ? <Check className="text-emerald-600" /> : <Copy />}
                </Button>
              </div>
              <div className="grid grid-cols-3 divide-x rounded-lg border text-center">
                {[
                  ["分类结果", <LabelBadge l={e.label} />],
                  ["分类耗时", clsMs(e)],
                  ["总耗时", ms(e.latency_ms)],
                ].map(([k, v], i) => (
                  <div key={i} className="flex flex-col items-center gap-1 px-2 py-2.5">
                    <span className="text-[11px] text-muted-foreground">{k}</span>
                    <span className="text-sm font-medium tabular-nums">{v}</span>
                  </div>
                ))}
              </div>
            </SheetHeader>
            <div className="flex flex-1 flex-col gap-5 overflow-y-auto px-4 py-4">
              <Block title="审查结论">
                <DescList
                  cols={1}
                  items={[
                    ["判定原因", reasonName(e.reason_code)],
                    [
                      "网关执行",
                      e.enforced ? (
                        <ToneBadge tone="danger">网关已阻断 (未转发)</ToneBadge>
                      ) : e.would_block ? (
                        <ToneBadge tone="warn">网关未阻断 (影子模式评估：在拦截模式下将被阻断)</ToneBadge>
                      ) : (
                        "网关已放行"
                      ),
                    ],
                    ["风险类别", cats(e) || "—"],
                    ["审查覆盖", e.coverage ? (COVERAGE[e.coverage] ?? e.coverage) : "—"],
                    ["覆盖说明", e.coverage_reason ? reasonName(e.coverage_reason) : "—"],
                    ["送审字符数", e.inspected_chars ? fmt(e.inspected_chars) : "—"],
                    ["策略版本", mono(e.policy_version)],
                  ]}
                />
              </Block>
              <Block title="请求">
                <DescList
                  cols={1}
                  items={[
                    ["接口类型", protoName(e.protocol)],
                    ["请求路径", mono(`${e.method} ${e.path_template}`)],
                    ["请求体大小", bytes(e.body_bytes)],
                    ["运行模式", MODES[e.phase as keyof typeof MODES]?.name ?? e.phase],
                    ["API Key", e.credential_hmac ? mono(keyName(e.credential_hmac, config?.aliases)) : "—"],
                    ["客户端", mono(e.client)],
                    ["模型", mono(e.model)],
                    ["来源 IP 指纹", mono(e.source_ip_hmac)],
                  ]}
                />
              </Block>
              <Block title="分类模型">
                <DescList
                  cols={1}
                  items={[
                    ["调用状态", clsStatus(e.classifier_status)],
                    ["缓存命中", yes(e.cache_hit)],
                    ["分类模型", mono(e.classifier)],
                  ]}
                />
              </Block>
              {e.aux_status && (
                <Block title="辅助判断（仅记录，不参与判定）">
                  {e.aux ? (
                    <DescList
                      cols={1}
                      items={[
                        ...AUX_QUESTIONS.map(([k, name]): [string, React.ReactNode] => [name, <AuxProb p={e.aux?.[k]} />]),
                        ["判断模型", mono(e.aux_model)],
                        ["耗时", ms(e.aux_ms || 0)],
                      ]}
                    />
                  ) : (
                    <p className="py-2 text-sm text-muted-foreground">
                      未得到结果：{clsStatus(e.aux_status)}
                    </p>
                  )}
                </Block>
              )}
              <Block title="响应与连接">
                <DescList
                  cols={1}
                  items={[
                    ["客户端状态码", e.http_status || "—"],
                    ["客户端中断", e.client_aborted ? "是 (客户端提前断开)" : "否"],
                  ]}
                />
              </Block>
              <section>
                <Button variant="link" size="sm" className="h-auto p-0 text-muted-foreground" onClick={() => setRaw((r) => !r)}>
                  {raw ? "收起原始记录" : "查看原始记录"}
                </Button>
                {raw && (
                  <pre className="mt-2 overflow-x-auto rounded-lg bg-muted p-3 font-mono text-xs leading-relaxed">
                    {JSON.stringify(e, null, 2)}
                  </pre>
                )}
              </section>
            </div>
            <SheetFooter className="flex-row items-center justify-between border-t py-3">
              <span className="text-xs text-muted-foreground tabular-nums">
                第 {index + 1} / {events.length} 条
              </span>
              <div className="flex gap-1">
                <Button variant="outline" size="sm" disabled={index <= 0} onClick={() => step(-1)}>
                  <ChevronLeft />
                  上一条
                </Button>
                <Button variant="outline" size="sm" disabled={index >= events.length - 1} onClick={() => step(1)}>
                  下一条
                  <ChevronRight />
                </Button>
              </div>
            </SheetFooter>
          </>
        )}
      </SheetContent>
    </Sheet>
  )
}
