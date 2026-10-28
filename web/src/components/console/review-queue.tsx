import * as React from "react"
import { ArrowLeft, Check, ChevronLeft, ChevronRight, Copy } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Kbd } from "@/components/ui/kbd"
import { Textarea } from "@/components/ui/textarea"
import {
  DecisionBadge,
  EmptyState,
  LabelBadge,
  ToneBadge,
} from "@/components/console/bits"
import { FilterSelect } from "@/pages/events"
import { api, HTTPError } from "@/lib/api"
import {
  CATEGORIES,
  catName,
  COVERAGE,
  dt,
  fmt,
  keyName,
  protoName,
  reasonName,
} from "@/lib/format"
import { useStore } from "@/lib/store"
import type { Sample, SampleDetail } from "@/lib/types"

// One key per verdict; labeled verdicts carry the expected action.
const VERDICTS: {
  key: string
  status: string
  action: string
  name: string
  hint: string
  className: string
}[] = [
  {
    key: "1",
    status: "labeled",
    action: "allow",
    name: "应放行",
    hint: "正常请求，系统判重了",
    className:
      "border-emerald-500/40 hover:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
  },
  {
    key: "2",
    status: "labeled",
    action: "review",
    name: "应复核",
    hint: "确实需要人看",
    className:
      "border-amber-500/40 hover:bg-amber-500/10 text-amber-700 dark:text-amber-400",
  },
  {
    key: "3",
    status: "labeled",
    action: "deny",
    name: "应拒绝",
    hint: "违规，应直接拦截",
    className:
      "border-red-500/40 hover:bg-red-500/10 text-red-700 dark:text-red-400",
  },
  {
    key: "4",
    status: "insufficient_context",
    action: "",
    name: "上下文不足",
    hint: "只看这段无法判断",
    className: "",
  },
  {
    key: "5",
    status: "disputed",
    action: "",
    name: "有争议",
    hint: "需要讨论",
    className: "",
  },
]

const errText = (e: unknown) =>
  e instanceof HTTPError || e instanceof Error ? e.message : String(e)

/** True when a key press belongs to a form control, not to the queue shortcuts. */
const typing = (t: EventTarget | null) =>
  t instanceof HTMLElement &&
  !!t.closest(
    "input, textarea, select, [contenteditable], [role=listbox], [role=option]"
  )

/**
 * Review queue: one stored, still unreviewed text at a time, decided with one click or key.
 * Rows are one per text (newest request), so a text repeated by an agent loop is reviewed once.
 */
export function ReviewQueue({
  filter,
  onExit,
}: {
  filter: Record<string, string>
  onExit: () => void
}) {
  const { config } = useStore()
  const [items, setItems] = React.useState<Sample[] | null>(null)
  const [pos, setPos] = React.useState(0)
  const [done, setDone] = React.useState<Record<number, string>>({})
  const [detail, setDetail] = React.useState<SampleDetail | null>(null)
  const [category, setCategory] = React.useState("")
  const [reason, setReason] = React.useState("")
  const [busy, setBusy] = React.useState(false)
  const [error, setError] = React.useState("")
  const [copied, setCopied] = React.useState(false)
  const [tech, setTech] = React.useState(false)

  React.useEffect(() => {
    api
      .samples({ ...filter, review: "pending", group: "content", limit: "100" })
      .then(
        (res) =>
          setItems(res.samples.filter((s) => s.content_status === "stored")),
        (e: unknown) => setError(errText(e))
      )
  }, [filter])

  const cur = items?.[pos]
  React.useEffect(() => {
    if (!cur) return
    api.sample(cur.id).then(
      (d) => {
        setDetail(d)
        setCategory(d.categories?.[0] ?? "")
        setReason("")
        setTech(false)
        setError("")
      },
      (e: unknown) => setError(errText(e))
    )
  }, [cur])

  const go = React.useCallback(
    (to: number) => {
      if (!items?.length) return
      setDetail(null)
      setPos(Math.max(0, Math.min(items.length - 1, to)))
    },
    [items]
  )
  const nextOpen = React.useCallback(
    (from: number, finished: Record<number, string>) => {
      if (!items) return
      for (let i = from + 1; i < items.length; i++)
        if (!finished[items[i].id]) return go(i)
      for (let i = 0; i < from; i++) if (!finished[items[i].id]) return go(i)
      setDetail(null)
      setPos(items.length) // all done
    },
    [items, go]
  )

  const submit = React.useCallback(
    async (v: (typeof VERDICTS)[number]) => {
      if (!detail || busy) return
      setBusy(true)
      setError("")
      try {
        await api.addReview(detail.id, {
          status: v.status,
          expected_action: v.action,
          category,
          reason,
          supersedes: detail.reviews[0]?.id ?? 0,
        })
        const finished = { ...done, [detail.id]: v.name }
        setDone(finished)
        nextOpen(pos, finished)
      } catch (e) {
        setError(errText(e))
      } finally {
        setBusy(false)
      }
    },
    [detail, busy, category, reason, done, pos, nextOpen]
  )

  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey || typing(e.target)) return
      const v = VERDICTS.find((x) => x.key === e.key)
      if (v) {
        e.preventDefault()
        void submit(v)
      } else if (e.key === "j" || e.key === "ArrowRight") go(pos + 1)
      else if (e.key === "k" || e.key === "ArrowLeft") go(pos - 1)
      else if (e.key === "Escape") onExit()
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [submit, go, pos, onExit])

  const copy = async (s: string) => {
    try {
      await navigator.clipboard.writeText(s)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      // clipboard needs a secure context; the text stays selectable
    }
  }

  const total = items?.length ?? 0
  const finishedCount = Object.keys(done).length
  const header = (
    <div className="flex flex-wrap items-center gap-3">
      <Button variant="ghost" size="sm" onClick={onExit}>
        <ArrowLeft />
        返回样本列表
      </Button>
      <h1 className="text-lg font-semibold">逐条复核</h1>
      {items && (
        <span className="text-sm text-muted-foreground tabular-nums">
          {pos < total ? `第 ${pos + 1} / ${total} 条` : `共 ${total} 条`} ·
          本次已复核 {finishedCount}
        </span>
      )}
      <div className="flex-1" />
      <span className="hidden items-center gap-1.5 text-xs text-muted-foreground md:inline-flex">
        <Kbd>1</Kbd>–<Kbd>5</Kbd> 提交 <Kbd>J</Kbd>/<Kbd>K</Kbd> 下一条/上一条{" "}
        <Kbd>Esc</Kbd> 退出
      </span>
    </div>
  )

  if (!items) {
    return (
      <div className="flex flex-col gap-5">
        {header}
        {error ? (
          <p className="text-sm text-destructive">加载失败：{error}</p>
        ) : (
          <EmptyState text="加载中…" />
        )}
      </div>
    )
  }
  if (!cur) {
    return (
      <div className="flex flex-col gap-5">
        {header}
        <Card className="items-center gap-3 py-12 shadow-none">
          <Check className="size-8 text-emerald-600" />
          <p className="font-medium">
            {total ? "这一批都复核完了" : "没有待复核的样本"}
          </p>
          <p className="text-sm text-muted-foreground">
            {total
              ? `本次复核 ${finishedCount} 条。`
              : "当前筛选下的样本都已有复核记录，或没有保存正文。"}
          </p>
          <Button variant="outline" size="sm" onClick={onExit}>
            返回样本列表
          </Button>
        </Card>
      </div>
    )
  }

  const s = detail ?? cur
  const blocked = s.phase === "enforce" ? s.enforced : s.would_block
  const who = [
    s.credential_hmac && keyName(s.credential_hmac, config?.aliases),
    s.client,
    s.model,
  ].filter(Boolean)
  return (
    <div className="flex flex-col gap-4">
      {header}
      <div className="grid gap-4 items-start lg:grid-cols-[minmax(0,1fr)_340px]">
        <Card className="gap-0 py-0 shadow-none">
          <div className="flex flex-col gap-2 border-b px-5 py-4">
            <div className="flex flex-wrap items-center gap-2">
              <LabelBadge l={s.label} />
              {s.categories?.map((c) => (
                <ToneBadge key={c} tone="warn">
                  {catName(c)}
                </ToneBadge>
              ))}
              <span className="text-muted-foreground">→</span>
              <DecisionBadge d={s.decision} />
              <span className="text-xs text-muted-foreground">
                {s.enforced
                  ? "网关已阻断"
                  : blocked
                    ? "影子模式已放行（拦截模式下会被阻断）"
                    : "网关已放行"}
              </span>
              {done[s.id] && (
                <ToneBadge tone="ok">已复核：{done[s.id]}</ToneBadge>
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              {dt(new Date(s.ts * 1000))} · {protoName(s.protocol)}
              {who.length > 0 && ` · ${who.join(" · ")}`}
              {s.seen > 1 && ` · 同一文本出现 ${fmt(s.seen)} 次`}
            </p>
          </div>
          <div className="relative px-5 py-4">
            <div className="mb-2 flex items-center justify-between">
              <h2 className="text-sm font-medium">
                {s.cache_hit
                  ? "本次选取的受检文本（复用已有分类结果）"
                  : "分类器看到的文本"}
                <span className="ml-2 text-xs font-normal text-muted-foreground">
                  已脱敏，不是完整会话
                </span>
              </h2>
              {detail?.text && (
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label="复制文本"
                  onClick={() => void copy(detail.text ?? "")}
                >
                  {copied ? <Check className="text-emerald-600" /> : <Copy />}
                </Button>
              )}
            </div>
            {!detail ? (
              <p className="py-8 text-sm text-muted-foreground">加载中…</p>
            ) : (
              <>
                {/* Plain text only: React escapes it; nothing is rendered as HTML or Markdown. */}
                <pre className="max-h-[55vh] overflow-auto rounded-lg bg-muted p-4 font-mono text-[13px] leading-relaxed break-words whitespace-pre-wrap">
                  {detail.text}
                </pre>
                <div className="mt-2 flex flex-wrap gap-1.5 text-xs text-muted-foreground">
                  <span>{fmt(detail.text_bytes ?? 0)} 字节</span>
                  {detail.truncated && <span>· 原输入过长，只送审首尾</span>}
                  {s.coverage_reason && (
                    <span>· {reasonName(s.coverage_reason)}</span>
                  )}
                  {detail.redactions &&
                    Object.entries(detail.redactions).map(([k, n]) => (
                      <ToneBadge key={k} tone="muted">
                        已脱敏 {k}×{n}
                      </ToneBadge>
                    ))}
                </div>
              </>
            )}
          </div>
          <div className="border-t px-5 py-2.5">
            <Button
              variant="link"
              size="sm"
              className="h-auto p-0 text-muted-foreground"
              onClick={() => setTech((t) => !t)}
            >
              {tech ? "收起技术详情" : "技术详情"}
            </Button>
            {tech && (
              <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
                <dt className="text-muted-foreground">请求 ID</dt>
                <dd className="font-mono">{s.trace_id}</dd>
                <dt className="text-muted-foreground">审查覆盖</dt>
                <dd>{COVERAGE[s.coverage] ?? s.coverage}</dd>
                <dt className="text-muted-foreground">分类</dt>
                <dd>
                  {s.cache_hit
                    ? "复用缓存结果"
                    : `${s.classifier_status || "—"} · ${fmt(s.classifier_ms)} ms`}
                </dd>
                <dt className="text-muted-foreground">采样</dt>
                <dd>
                  {s.base ? "随机基础" : "问题富集"} · {s.sampling}
                </dd>
                <dt className="text-muted-foreground">策略版本</dt>
                <dd className="font-mono">{s.policy_version}</dd>
              </dl>
            )}
          </div>
        </Card>

        <Card className="h-fit gap-3 px-4 py-4 shadow-none lg:sticky lg:top-20">
          <div>
            <h2 className="text-sm font-medium">你的判断</h2>
            <p className="text-xs text-muted-foreground">
              点一下即提交并进入下一条；不会改变线上策略。
            </p>
          </div>
          <div className="flex flex-col gap-2">
            {VERDICTS.slice(0, 3).map((v) => (
              <Button
                key={v.key}
                variant="outline"
                disabled={!detail || busy}
                className={`h-auto justify-between py-2.5 ${v.className}`}
                onClick={() => void submit(v)}
              >
                <span className="flex flex-col items-start">
                  <span className="font-medium">{v.name}</span>
                  <span className="text-xs font-normal opacity-70">
                    {v.hint}
                  </span>
                </span>
                <Kbd>{v.key}</Kbd>
              </Button>
            ))}
            <div className="grid grid-cols-2 gap-2">
              {VERDICTS.slice(3).map((v) => (
                <Button
                  key={v.key}
                  variant="outline"
                  size="sm"
                  disabled={!detail || busy}
                  onClick={() => void submit(v)}
                >
                  {v.name}
                  <Kbd>{v.key}</Kbd>
                </Button>
              ))}
            </div>
          </div>
          <div className="flex flex-col gap-2 border-t pt-3">
            <FilterSelect
              label="风险类别"
              all="无风险类别"
              value={category}
              onChange={setCategory}
              options={Object.entries(CATEGORIES)}
            />
            <Textarea
              placeholder="理由（可选，加密保存；不要粘贴原文或密钥）"
              maxLength={2000}
              className="min-h-16 text-sm"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </div>
          {error && (
            <p className="text-xs text-destructive">提交失败：{error}</p>
          )}
          <div className="flex justify-between border-t pt-3">
            <Button
              variant="ghost"
              size="sm"
              disabled={pos <= 0}
              onClick={() => go(pos - 1)}
            >
              <ChevronLeft />
              上一条
            </Button>
            <Button
              variant="ghost"
              size="sm"
              disabled={pos >= total - 1}
              onClick={() => go(pos + 1)}
            >
              跳过
              <ChevronRight />
            </Button>
          </div>
        </Card>
      </div>
    </div>
  )
}
