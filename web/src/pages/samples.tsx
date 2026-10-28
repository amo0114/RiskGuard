import * as React from "react"
import { ChevronDown, ChevronRight, Info } from "lucide-react"

import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"
import {
  ActionBadge,
  DecisionBadge,
  DescList,
  EmptyState,
  LabelBadge,
  PageHeader,
  Section,
  StatusDot,
  ToneBadge,
} from "@/components/console/bits"
import { FilterSelect } from "@/pages/events"
import { api, HTTPError } from "@/lib/api"
import {
  bytes,
  CATEGORIES,
  catName,
  COVERAGE,
  DECISIONS,
  dt,
  fmt,
  protoName,
  reasonName,
  type Tone,
  keyName,
} from "@/lib/format"
import { useStore } from "@/lib/store"
import { ReviewQueue } from "@/components/console/review-queue"
import { useDocked } from "@/hooks/use-docked"
import { cn } from "@/lib/utils"
import type {
  ReviewInput,
  Sample,
  SampleDetail,
  SampleStatus,
} from "@/lib/types"

const CONTENT: Record<Sample["content_status"], { name: string; tone: Tone }> =
  {
    stored: { name: "已保存", tone: "ok" },
    excluded: { name: "未保存（疑似敏感）", tone: "warn" },
    oversize: { name: "未保存（超长）", tone: "muted" },
    none: { name: "无可审查文本", tone: "muted" },
    deleted: { name: "已删除", tone: "muted" },
    expired: { name: "已过期", tone: "muted" },
  }

const REVIEW: Record<string, { name: string; tone: Tone }> = {
  pending: { name: "待复核", tone: "info" },
  labeled: { name: "已标注", tone: "ok" },
  insufficient_context: { name: "上下文不足", tone: "muted" },
  disputed: { name: "有争议", tone: "warn" },
  excluded_sensitive: { name: "排除（敏感）", tone: "danger" },
}

// The sample panel (32rem) needs more room than the events one before it docks.
const SAMPLE_DOCK_PX = 1440
const clock = (s: number) =>
  new Date(s * 1000).toLocaleTimeString("zh-CN", { hour12: false })

const errText = (e: unknown) =>
  e instanceof HTTPError || e instanceof Error ? e.message : String(e)
const when = (s: number) => dt(new Date(s * 1000))
const blocked = (s: Sample) =>
  s.phase === "enforce" ? s.enforced : s.would_block
// What actually happened at the gateway: enforce rejects; shadow allows traffic through regardless.
const disposition = (s: Sample) =>
  s.enforced
    ? "网关已阻断 (未转发)"
    : s.would_block
      ? "网关未阻断 (影子模式)"
      : "网关已放行"
const repeats = (s: Sample) =>
  `${fmt(s.seen)} 次${s.cache_hits ? ` · 缓存命中 ${fmt(s.cache_hits)}` : ""}`

function Notice({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex gap-2.5 rounded-xl border border-amber-500/30 bg-amber-500/8 px-4 py-3 text-sm">
      <Info className="mt-0.5 size-4 shrink-0 text-amber-600" />
      <div>{children}</div>
    </div>
  )
}

function Tile({
  label,
  value,
  sub,
  tone,
  title,
}: {
  label: string
  value: React.ReactNode
  sub?: React.ReactNode
  tone?: "danger" | "warn"
  title?: string
}) {
  return (
    <div
      className="flex min-w-0 flex-col gap-0.5 rounded-lg border px-3 py-2.5"
      title={title}
    >
      <span className="text-xs text-muted-foreground">{label}</span>
      <span
        className={cn(
          "truncate text-lg font-semibold tabular-nums",
          tone === "danger" && "text-red-600 dark:text-red-400",
          tone === "warn" && "text-amber-600 dark:text-amber-400"
        )}
      >
        {value}
      </span>
      {sub && (
        <span className="text-xs break-words text-muted-foreground">{sub}</span>
      )}
    </div>
  )
}

// Tiles wrap with the width (the list may sit beside a docked panel); every number that shows
// whether collection is healthy stays visible, plan and retention move to one footnote line.
function StatusCard({ st }: { st: SampleStatus }) {
  const c = st.counts ?? {}
  const n = (k: string) => c[k] ?? 0
  const drops = (p: string) =>
    Object.entries(c).filter(([k]) => k.startsWith(`${p}.dropped_`))
  const dropped = (p: string) => drops(p).reduce((a, [, v]) => a + v, 0)
  const dropTitle = (p: string) =>
    drops(p)
      .map(([k, v]) => `${k.slice(k.indexOf(".dropped_") + 9)} ${v}`)
      .join("，") || "无丢弃"
  const queue = (p: string, extra = "") => (
    <>
      入选 {fmt(n(`${p}.selected`))} · 丢弃{" "}
      <span
        className={dropped(p) ? "text-red-600 dark:text-red-400" : undefined}
      >
        {fmt(dropped(p))}
      </span>
      {extra}
    </>
  )
  const dbFull =
    (st.max_db_bytes ?? 0) > 0 &&
    (st.db_bytes ?? 0) / (st.max_db_bytes ?? 1) > 0.8
  const diskLow =
    (st.free_bytes ?? -1) >= 0 &&
    (st.free_bytes ?? 0) < (st.min_free_bytes ?? 0) * 1.5
  return (
    <Section title="采集状态" hint="采集故障只停止采集，不影响审查与转发">
      <div className="grid grid-cols-[repeat(auto-fill,minmax(9.5rem,1fr))] gap-2">
        <Tile
          label="随机基础 · 落库"
          value={fmt(n("base.persisted"))}
          sub={queue("base")}
          tone={dropped("base") ? "warn" : undefined}
          title={`入队 ${n("base.accepted")}；丢弃：${dropTitle("base")}`}
        />
        <Tile
          label="问题富集 · 落库"
          value={fmt(n("enriched.persisted"))}
          sub={queue(
            "enriched",
            ` · 重复跳过 ${fmt(n("enriched.skipped_repeat"))}`
          )}
          tone={dropped("enriched") ? "warn" : undefined}
          title={`入队 ${n("enriched.accepted")}；丢弃：${dropTitle("enriched")}`}
        />
        <Tile
          label="可抽样请求"
          value={fmt(n("eligible"))}
          sub={`随机抽样 ${((st.base_probability ?? 0) * 100).toFixed(0)}%`}
        />
        <Tile
          label="队列"
          value={`${fmt(st.queue_items)} / ${fmt(st.queue_max_items)}`}
          sub="待写入的样本"
        />
        <Tile
          label="数据库"
          value={bytes(st.db_bytes)}
          sub={`上限 ${bytes(st.max_db_bytes)} · 磁盘剩余 ${bytes(st.free_bytes)}`}
          tone={dbFull || diskLow ? "warn" : undefined}
        />
        <Tile
          label="采集"
          value={st.last_error ? "有错误" : "正常"}
          sub={st.last_error || "最近没有错误"}
          tone={st.last_error ? "danger" : undefined}
          title={st.last_error || undefined}
        />
      </div>
      <p className="mt-2.5 text-xs text-muted-foreground">
        今日按 UTC {st.day} 计数 · 每日上限 随机 {fmt(st.base_daily_cap)} / 富集{" "}
        {fmt(st.enriched_daily_cap)} · 正文保留{" "}
        {fmt((st.content_retention_hours ?? 0) / 24)} 天，标注{" "}
        {fmt((st.review_retention_hours ?? 0) / 24)} 天
      </p>
    </Section>
  )
}

const ACTION_OPTS: [string, string][] = [
  ["allow", "应放行"],
  ["review", "应复核"],
  ["deny", "应拒绝"],
]
const STATUS_OPTS: [string, string][] = Object.entries(REVIEW)
  .filter(([k]) => k !== "pending")
  .map(([k, v]) => [k, v.name])

function ReviewForm({ d, onSaved }: { d: SampleDetail; onSaved: () => void }) {
  const [status, setStatus] = React.useState("labeled")
  const [action, setAction] = React.useState("")
  const [category, setCategory] = React.useState("")
  const [reason, setReason] = React.useState("")
  const [busy, setBusy] = React.useState(false)
  const [error, setError] = React.useState("")
  const submit = async () => {
    const r: ReviewInput = {
      status,
      expected_action: status === "labeled" ? action : "",
      category,
      reason,
      supersedes: d.reviews[0]?.id ?? 0,
    }
    setBusy(true)
    setError("")
    try {
      await api.addReview(d.id, r)
      setReason("")
      onSaved()
    } catch (e) {
      setError(errText(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="flex flex-col gap-2.5">
      <div className="flex flex-wrap gap-2">
        <FilterSelect
          label="复核结论"
          all="选择结论"
          value={status}
          onChange={setStatus}
          options={STATUS_OPTS}
        />
        {status === "labeled" && (
          <FilterSelect
            label="期望处置"
            all="期望处置"
            value={action}
            onChange={setAction}
            options={ACTION_OPTS}
          />
        )}
        <FilterSelect
          label="风险类别"
          all="无风险类别"
          value={category}
          onChange={setCategory}
          options={Object.entries(CATEGORIES)}
        />
      </div>
      <Textarea
        placeholder="理由（加密保存；不要粘贴原文或密钥）"
        maxLength={2000}
        value={reason}
        onChange={(e) => setReason(e.target.value)}
      />
      {error && <p className="text-xs text-destructive">提交失败：{error}</p>}
      <Button
        size="sm"
        className="self-start"
        disabled={busy || !status || (status === "labeled" && !action)}
        onClick={() => void submit()}
      >
        提交复核
      </Button>
    </div>
  )
}

function SampleSheet({
  sample,
  onClose,
  onChanged,
}: {
  sample: Sample | null
  onClose: () => void
  onChanged: () => void
}) {
  const { config } = useStore()
  const docked = useDocked(SAMPLE_DOCK_PX)
  const roles = config?.me.roles ?? []
  const reviewer = roles.includes("reviewer")
  const [d, setD] = React.useState<SampleDetail | null>(null)
  const [error, setError] = React.useState("")
  const load = React.useCallback(
    (id: number) =>
      api.sample(id).then(
        (detail) => {
          setD(detail)
          setError("")
        },
        (e: unknown) => setError(errText(e))
      ),
    []
  )
  // The parent remounts this sheet per sample (key), so state never shows a previous sample.
  React.useEffect(() => {
    if (sample && reviewer) void load(sample.id)
  }, [sample, reviewer, load])
  const [confirmDelete, setConfirmDelete] = React.useState(false)
  const [deleting, setDeleting] = React.useState(false)
  const doDelete = async () => {
    if (!sample) return
    setDeleting(true)
    try {
      await api.deleteSample(sample.id)
      setConfirmDelete(false)
      onChanged()
      onClose()
    } catch (e) {
      setError(errText(e))
    } finally {
      setDeleting(false)
    }
  }
  const s = d ?? sample
  return (
    <Sheet
      open={!!sample}
      // Docked beside the list on wide screens (the page reserves the width); see EventSheet.
      modal={!docked}
      disablePointerDismissal={docked}
      onOpenChange={(o) => !o && onClose()}
    >
      <SheetContent
        overlay={!docked}
        className={cn(
          "w-full gap-0 data-[side=right]:sm:max-w-xl",
          docked &&
            "shadow-none data-[side=right]:top-14 data-[side=right]:h-[calc(100%-3.5rem)] data-[side=right]:sm:max-w-lg"
        )}
      >
        {s && (
          <>
            <SheetHeader className="gap-2 border-b pb-4">
              <SheetTitle className="flex items-center gap-2 text-base">
                <DecisionBadge d={s.decision} />
                {blocked(s) && (
                  <ToneBadge tone={s.phase === "enforce" ? "danger" : "warn"}>
                    {s.phase === "enforce" ? "已拦截" : "模拟拦截"}
                  </ToneBadge>
                )}
              </SheetTitle>
              <SheetDescription>
                {when(s.ts)} · {protoName(s.protocol)} ·{" "}
                <span className="font-mono">{s.trace_id}</span>
              </SheetDescription>
            </SheetHeader>
            <div className="flex flex-1 flex-col gap-5 overflow-y-auto px-4 py-4">
              <section className="flex flex-col gap-1.5">
                <h4 className="text-xs font-medium text-muted-foreground">
                  {s.cache_hit
                    ? "本次选取的受检文本（脱敏），复用已有分类结果；不是完整会话"
                    : "受检脱敏片段（分类器实际看到的内容，不是完整会话）"}
                </h4>
                {!reviewer ? (
                  <p className="text-sm text-muted-foreground">
                    需要 reviewer 角色才能查看正文与复核。
                  </p>
                ) : error ? (
                  <p className="text-sm text-destructive">{error}</p>
                ) : !d ? (
                  <p className="text-sm text-muted-foreground">加载中…</p>
                ) : d.text ? (
                  <>
                    {/* Plain text only: React escapes it and nothing is rendered as HTML or Markdown. */}
                    <pre className="max-h-96 overflow-auto rounded-lg bg-muted p-3 font-mono text-xs leading-relaxed break-words whitespace-pre-wrap">
                      {d.text}
                    </pre>
                    <p className="text-xs text-muted-foreground">
                      {fmt(d.text_bytes)} 字节
                      {d.truncated && " · 原输入过长，只送审了首尾部分"}
                      {d.redactions &&
                        Object.keys(d.redactions).length > 0 &&
                        ` · 已脱敏：${Object.entries(d.redactions)
                          .map(([k, n]) => `${k}×${n}`)
                          .join("、")}`}
                    </p>
                  </>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    {CONTENT[d.content_status]?.name ?? d.content_status}
                    {d.exclude_reason && `（${d.exclude_reason}）`}
                  </p>
                )}
              </section>
              <section className="flex flex-col gap-1">
                <h4 className="text-xs font-medium text-muted-foreground">
                  系统结果
                </h4>
                <DescList
                  cols={1}
                  items={[
                    ["分类结果", <LabelBadge l={s.label} />],
                    [
                      "风险类别",
                      s.categories?.length
                        ? s.categories.map(catName).join("、")
                        : "—",
                    ],
                    ["判定原因", reasonName(s.reason_code)],
                    [
                      "审查覆盖",
                      `${COVERAGE[s.coverage] ?? s.coverage}${s.coverage_reason ? `（${reasonName(s.coverage_reason)}）` : ""}`,
                    ],
                    ["网关执行", disposition(s)],
                    ["状态码", s.http_status || "—"],
                    [
                      "采样来源",
                      <span title={s.sampling}>
                        {s.base ? "随机基础" : "问题富集"}
                      </span>,
                    ],
                    [
                      "API Key",
                      s.credential_hmac ? (
                        <span className="font-mono text-xs">
                          {keyName(s.credential_hmac, config?.aliases)}
                        </span>
                      ) : (
                        "—"
                      ),
                    ],
                    ["客户端 / 模型", `${s.client || "—"} / ${s.model || "—"}`],
                    ["相同文本出现", repeats(s)],
                    [
                      "本次分类",
                      s.cache_hit
                        ? "复用缓存结果"
                        : s.classifier_status
                          ? `${s.classifier_status} · ${fmt(s.classifier_ms)} ms`
                          : "—",
                    ],
                    [
                      "策略版本",
                      <span className="font-mono text-xs">
                        {s.policy_version}
                      </span>,
                    ],
                  ]}
                />
              </section>
              {d && reviewer && (
                <section className="flex flex-col gap-2">
                  <h4 className="text-xs font-medium text-muted-foreground">
                    人工复核（追加记录，不修改历史；不会改变线上策略）
                  </h4>
                  {d.reviews.map((r) => (
                    <div
                      key={r.id}
                      className="rounded-lg border px-3 py-2 text-sm"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <ToneBadge tone={REVIEW[r.status]?.tone ?? "muted"}>
                          {REVIEW[r.status]?.name ?? r.status}
                        </ToneBadge>
                        {r.expected_action && (
                          <ActionBadge a={r.expected_action} />
                        )}
                        {r.category && (
                          <span className="text-xs">{catName(r.category)}</span>
                        )}
                        <span className="ml-auto text-xs text-muted-foreground">
                          {r.actor} · {when(r.created_at)}
                        </span>
                      </div>
                      {r.reason && (
                        <p className="mt-1.5 text-xs break-words whitespace-pre-wrap">
                          {r.reason}
                        </p>
                      )}
                    </div>
                  ))}
                  {d.content_status === "stored" && (
                    <ReviewForm
                      d={d}
                      onSaved={() => {
                        void load(d.id)
                        onChanged()
                      }}
                    />
                  )}
                </section>
              )}
            </div>
            <SheetFooter className="flex-row items-center justify-between border-t py-3">
              <span className="text-xs text-muted-foreground">
                到期：{when(s.expires_at)}
              </span>
              {roles.includes("admin") && s.content_id ? (
                <>
                  <Button
                    variant="outline"
                    size="sm"
                    className="text-destructive hover:bg-destructive/10"
                    onClick={() => setConfirmDelete(true)}
                  >
                    删除正文与复核
                  </Button>
                  <Dialog open={confirmDelete} onOpenChange={setConfirmDelete}>
                    <DialogContent className="sm:max-w-md">
                      <DialogHeader>
                        <DialogTitle>确认删除样本？</DialogTitle>
                        <DialogDescription>
                          此操作将永久删除该样本的解密正文与历史复核记录，不可撤销。
                        </DialogDescription>
                      </DialogHeader>
                      <DialogFooter>
                        <DialogClose
                          render={
                            <Button
                              variant="outline"
                              size="sm"
                              disabled={deleting}
                            />
                          }
                        >
                          取消
                        </DialogClose>
                        <Button
                          variant="destructive"
                          size="sm"
                          disabled={deleting}
                          onClick={() => void doDelete()}
                        >
                          {deleting ? "删除中…" : "确认删除"}
                        </Button>
                      </DialogFooter>
                    </DialogContent>
                  </Dialog>
                </>
              ) : null}
            </SheetFooter>
          </>
        )}
      </SheetContent>
    </Sheet>
  )
}

function parseSampleParams() {
  const hash = location.hash.replace(/^#\/?/, "")
  const [, queryString] = hash.split("?")
  const p = new URLSearchParams(queryString ?? "")
  return {
    queue: p.get("queue") || "",
    decision: p.get("decision") || "",
    review: p.get("review") || "",
    credential: p.get("credential") || "",
  }
}

export function SamplesPage() {
  const { config, lastOk } = useStore()
  const docked = useDocked(SAMPLE_DOCK_PX)
  const initParams = React.useMemo(() => parseSampleParams(), [])
  const [status, setStatus] = React.useState<SampleStatus | null>(null)
  const [rows, setRows] = React.useState<Sample[]>([])
  const [more, setMore] = React.useState(false)
  const [error, setError] = React.useState("")
  const [queue, setQueue] = React.useState(initParams.queue)
  const [decision, setDecision] = React.useState(initParams.decision)
  const [review, setReview] = React.useState(initParams.review)
  const [credential, setCredential] = React.useState(initParams.credential)
  const [open, setOpen] = React.useState<Sample | null>(null)
  const [focus, setFocus] = React.useState(false)
  // Beside a docked panel only time, verdict, repeats and review stay; the rest is in the panel.
  const compact = docked && !!open

  React.useEffect(() => {
    const params = new URLSearchParams()
    if (queue) params.set("queue", queue)
    if (decision) params.set("decision", decision)
    if (review) params.set("review", review)
    if (credential) params.set("credential", credential)
    const qs = params.toString()
    const targetHash = qs ? `#/samples?${qs}` : `#/samples`
    if (location.hash !== targetHash) {
      history.pushState(null, "", targetHash)
    }
  }, [queue, decision, review, credential])
  // Back/forward or an edited address while this page is open: the URL wins.
  React.useEffect(() => {
    const onHash = () => {
      if (!location.hash.replace(/^#\/?/, "").startsWith("samples")) return
      const p = parseSampleParams()
      setQueue(p.queue)
      setDecision(p.decision)
      setReview(p.review)
      setCredential(p.credential)
    }
    window.addEventListener("hashchange", onHash)
    return () => window.removeEventListener("hashchange", onHash)
  }, [])
  // Rows are one per text (newest request); expanding loads every request that sent it.
  const [expanded, setExpanded] = React.useState<
    Record<number, Sample[] | "loading">
  >({})
  const PAGE = 50

  const shown = React.useRef(0)
  React.useEffect(() => {
    shown.current = rows.length
  }, [rows])
  // before: next page. refresh: reload what is on screen (up to 100 rows) and keep expanded
  // groups and the open drawer, so a timer tick never moves what the reviewer is reading.
  const load = React.useCallback(
    (before?: number, refresh = false) => {
      const limit = refresh
        ? Math.min(100, Math.max(PAGE, shown.current))
        : PAGE
      const q: Record<string, string> = {
        limit: String(limit),
        group: "content",
        queue,
        decision,
        review,
        credential,
      }
      if (before) q.before = String(before)
      return Promise.all([api.sampleStatus(), api.samples(q)]).then(
        ([st, res]) => {
          setError("")
          setStatus(st)
          if (!before && !refresh) setExpanded({})
          setRows((prev) => (before ? [...prev, ...res.samples] : res.samples))
          setMore(res.samples.length === limit)
        },
        (e: unknown) => setError(errText(e))
      )
    },
    [queue, decision, review, credential]
  )
  React.useEffect(() => {
    void load()
  }, [load])
  // The queue reviews what the list filters show (its own review=pending is added by the queue).
  const queueFilter = React.useMemo(
    () => ({ queue, decision, credential }),
    [queue, decision, credential]
  )
  // Follow the console's shared refresh (15s unless paused, and the refresh button).
  const seenTick = React.useRef(lastOk)
  React.useEffect(() => {
    if (seenTick.current === lastOk) return
    seenTick.current = lastOk
    void load(undefined, true)
  }, [lastOk, load])
  const collapse = (id: number) =>
    setExpanded((e) => {
      const next = { ...e }
      delete next[id]
      return next
    })
  const toggle = (s: Sample) => {
    const id = s.content_id
    if (!id) return
    if (expanded[id]) {
      collapse(id)
      return
    }
    setExpanded((e) => ({ ...e, [id]: "loading" }))
    api.samples({ content: String(id), limit: "100" }).then(
      (res) => setExpanded((e) => ({ ...e, [id]: res.samples })),
      (err: unknown) => {
        collapse(id)
        setError(errText(err))
      }
    )
  }

  const header = (
    <PageHeader
      title="样本复核"
      description="抽样保存分类器实际看到的脱敏片段，用于人工判断误拦与漏判"
      actions={
        config?.me.roles.includes("reviewer") &&
        status?.enabled && (
          <Button size="sm" onClick={() => setFocus(true)}>
            逐条复核
          </Button>
        )
      }
    />
  )
  if (focus) {
    return (
      <ReviewQueue
        filter={queueFilter}
        onExit={() => {
          setFocus(false)
          void load()
        }}
      />
    )
  }
  if (status && !status.enabled) {
    return (
      <div className="flex flex-col gap-5">
        {header}
        <Notice>
          样本采集未启用（配置 <code>samples.enabled</code>）。
          {status.last_error && (
            <span className="text-destructive">
              {" "}
              启动失败：{status.last_error}
            </span>
          )}
        </Notice>
      </div>
    )
  }
  const roles = config?.me.roles ?? []
  return (
    // Reserve the docked sample panel's width (max-w-lg) while one is open.
    <div className={cn("flex flex-col gap-5", docked && open && "pr-[32rem]")}>
      {header}
      <Notice>
        {
          "只保存分类器实际送审的片段，不含历史对话、附件与模型回复；保存前脱敏并加密，正文默认 7 天后删除。样本记录 API Key 指纹、客户端与模型：指纹不是 Key 本身，但管理员命名后可对应到具体使用者。查看正文、复核与删除都会以具名账号记录。"
        }
        {!roles.includes("reviewer") &&
          " 当前账号没有 reviewer 角色，只能查看元数据。"}
      </Notice>
      {status && <StatusCard st={status} />}
      <Section
        title="样本"
        hint="随机基础样本用于发现漏判与统计；问题富集样本（拒绝、待复核、故障、未覆盖）只用于排查，不代表总体比例"
        flush
        action={
          <div className="flex flex-wrap gap-2">
            {credential && (
              <Button
                variant="outline"
                size="sm"
                title="清除 Key 筛选"
                onClick={() => setCredential("")}
              >
                Key：{keyName(credential, config?.aliases)} ✕
              </Button>
            )}
            <FilterSelect
              label="采样来源"
              all="全部来源"
              value={queue}
              onChange={setQueue}
              options={[
                ["base", "随机基础"],
                ["enriched", "问题富集"],
              ]}
            />
            <FilterSelect
              label="系统判定"
              all="全部判定"
              value={decision}
              onChange={setDecision}
              options={Object.entries(DECISIONS)
                .slice(0, 5)
                .map(([k, v]) => [k, v.name])}
            />
            <FilterSelect
              label="复核状态"
              all="全部状态"
              value={review}
              onChange={setReview}
              options={[
                ["pending", "待复核"],
                ["reviewed", "已复核"],
              ]}
            />
          </div>
        }
      >
        {error && (
          <p className="px-4 pb-3 text-sm text-destructive">
            加载失败：{error}
          </p>
        )}
        {!rows.length ? (
          <EmptyState text="暂无样本" />
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>时间</TableHead>
                  {!compact && <TableHead>接口</TableHead>}
                  <TableHead>系统判定</TableHead>
                  {!compact && <TableHead>网关执行</TableHead>}
                  {!compact && <TableHead>来源</TableHead>}
                  {!compact && <TableHead>正文</TableHead>}
                  <TableHead>出现</TableHead>
                  <TableHead>复核</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((s) => {
                  const sub = s.content_id ? expanded[s.content_id] : undefined
                  return (
                    <React.Fragment key={s.id}>
                      <TableRow
                        className="cursor-pointer aria-selected:bg-muted"
                        aria-selected={open?.id === s.id}
                        onClick={() => setOpen(s)}
                      >
                        <TableCell className="whitespace-nowrap tabular-nums">
                          <button
                            type="button"
                            className="rounded font-medium hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:outline-none"
                            onClick={(e) => {
                              e.stopPropagation()
                              setOpen(s)
                            }}
                          >
                            {compact ? clock(s.ts) : when(s.ts)}
                          </button>
                        </TableCell>
                        {!compact && (
                          <TableCell className="whitespace-nowrap">
                            {protoName(s.protocol)}
                          </TableCell>
                        )}
                        <TableCell>
                          <DecisionBadge d={s.decision} />
                        </TableCell>
                        {!compact && (
                          <TableCell className="whitespace-nowrap">
                            {s.enforced ? (
                              <ToneBadge tone="danger">网关已阻断</ToneBadge>
                            ) : s.would_block ? (
                              <ToneBadge tone="warn">
                                网关未阻断 (影子)
                              </ToneBadge>
                            ) : (
                              <span className="text-muted-foreground">
                                网关已放行
                              </span>
                            )}
                          </TableCell>
                        )}
                        {!compact && (
                          <TableCell className="whitespace-nowrap">
                            {s.base ? "随机基础" : "问题富集"}
                          </TableCell>
                        )}
                        {!compact && (
                          <TableCell className="whitespace-nowrap">
                            <StatusDot
                              tone={CONTENT[s.content_status]?.tone ?? "muted"}
                            >
                              {CONTENT[s.content_status]?.name ??
                                s.content_status}
                            </StatusDot>
                          </TableCell>
                        )}
                        <TableCell className="whitespace-nowrap tabular-nums">
                          {s.seen > 1 ? (
                            <button
                              type="button"
                              className="inline-flex items-center gap-1 text-left hover:underline"
                              onClick={(e) => {
                                e.stopPropagation()
                                toggle(s)
                              }}
                            >
                              {sub ? (
                                <ChevronDown className="size-3.5" />
                              ) : (
                                <ChevronRight className="size-3.5" />
                              )}
                              {repeats(s)}
                            </button>
                          ) : (
                            repeats(s)
                          )}
                        </TableCell>
                        <TableCell className="whitespace-nowrap">
                          <ToneBadge
                            tone={REVIEW[s.review_status]?.tone ?? "muted"}
                          >
                            {REVIEW[s.review_status]?.name ?? s.review_status}
                          </ToneBadge>
                          {s.expected_action && (
                            <span className="ml-1.5">
                              <ActionBadge a={s.expected_action} />
                            </span>
                          )}
                        </TableCell>
                      </TableRow>
                      {sub === "loading" && (
                        <TableRow>
                          <TableCell
                            colSpan={compact ? 4 : 8}
                            className="pl-8 text-xs text-muted-foreground"
                          >
                            加载中…
                          </TableCell>
                        </TableRow>
                      )}
                      {Array.isArray(sub) &&
                        sub.map((o) => (
                          <TableRow
                            key={`sub-${o.id}`}
                            className="cursor-pointer bg-muted/40 text-xs"
                            onClick={() => setOpen(o)}
                          >
                            <TableCell className="pl-8 whitespace-nowrap tabular-nums">
                              <button
                                type="button"
                                className="rounded font-medium hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:outline-none"
                                onClick={(e) => {
                                  e.stopPropagation()
                                  setOpen(o)
                                }}
                              >
                                {compact ? clock(o.ts) : when(o.ts)}
                              </button>
                            </TableCell>
                            {!compact && (
                              <TableCell className="whitespace-nowrap">
                                {protoName(o.protocol)}
                              </TableCell>
                            )}
                            <TableCell>
                              <DecisionBadge d={o.decision} />
                            </TableCell>
                            {!compact && (
                              <TableCell className="whitespace-nowrap">
                                {disposition(o)} · {o.http_status || "—"}
                              </TableCell>
                            )}
                            {!compact && (
                              <TableCell className="whitespace-nowrap">
                                {o.base ? "随机基础" : "问题富集"}
                              </TableCell>
                            )}
                            <TableCell
                              colSpan={compact ? 2 : 3}
                              className="whitespace-nowrap text-muted-foreground"
                            >
                              {o.cache_hit
                                ? "复用缓存结果"
                                : `实时分类 ${fmt(o.classifier_ms)} ms`}
                              {" · "}
                              <span className="font-mono">{o.trace_id}</span>
                            </TableCell>
                          </TableRow>
                        ))}
                    </React.Fragment>
                  )
                })}
              </TableBody>
            </Table>
          </div>
        )}
        {more && (
          <div className="flex justify-center border-t py-3">
            <Button
              variant="outline"
              size="sm"
              onClick={() => void load(rows[rows.length - 1]?.id)}
            >
              加载更多
            </Button>
          </div>
        )}
      </Section>
      <SampleSheet
        key={open?.id ?? 0}
        sample={open}
        onClose={() => setOpen(null)}
        onChanged={() => void load()}
      />
    </div>
  )
}
