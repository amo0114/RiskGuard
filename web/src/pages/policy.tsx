import * as React from "react"
import { Info } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { ActionBadge, DescList, LabelBadge, PageHeader, Section, StatusDot, ToneBadge } from "@/components/console/bits"
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { cn } from "@/lib/utils"
import { catName, fmt, MODES, PROTOCOLS, protoName, TEXT_PROTOCOLS, type Tone } from "@/lib/format"
import { api } from "@/lib/api"
import { useStore } from "@/lib/store"

function Notice({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex gap-2.5 rounded-xl border border-amber-500/30 bg-amber-500/8 px-4 py-3 text-sm">
      <Info className="mt-0.5 size-4 shrink-0 text-amber-600" />
      <p>{children}</p>
    </div>
  )
}

function Fact({ k, children, sub }: { k: string; children: React.ReactNode; sub?: React.ReactNode }) {
  return (
    <Card className="gap-1.5 px-4 py-4 shadow-none">
      <span className="text-xs text-muted-foreground">{k}</span>
      <div className="truncate text-base font-semibold">{children}</div>
      {sub && <div className="text-xs text-muted-foreground">{sub}</div>}
    </Card>
  )
}

/** Hits column with a faint bar so the busy rows stand out without reading every number. */
function Hits({ n, max }: { n: number; max: number }) {
  return (
    <div className="flex items-center justify-end gap-3">
      <div className="hidden h-1 w-16 overflow-hidden rounded-full bg-muted sm:block">
        <div className="h-full rounded-full bg-foreground/40" style={{ width: `${max ? (n / max) * 100 : 0}%` }} />
      </div>
      <span className={cn("w-10 text-right tabular-nums", !n && "text-muted-foreground/60")}>{fmt(n)}</span>
    </div>
  )
}

/** The console's only write: how an enforce rejection is worded, never whether it happens. */
function BlockReplySwitch() {
  const { config, summary, refresh } = useStore()
  const [confirmOpen, setConfirmOpen] = React.useState(false)
  const [busy, setBusy] = React.useState(false)
  const [error, setError] = React.useState("")
  const br = config?.block_reply
  const admin = config?.me.roles.includes("admin") ?? false
  if (!br) return null

  const targetState = !br.enabled

  const handleConfirm = async () => {
    setBusy(true)
    setError("")
    try {
      await api.setBlockReply(targetState)
      await refresh(true)
      setConfirmOpen(false)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Section
        title="拦截回复"
        hint="仅改变被拦截请求的返回形式，不影响是否拦截；影子模式下不拦截，此设置不生效"
        action={
          <Button
            size="sm"
            variant={br.enabled ? "outline" : "default"}
            disabled={!br.available || !admin || busy}
            onClick={() => {
              setError("")
              setConfirmOpen(true)
            }}
          >
            {br.enabled ? "关闭拦截回复" : "开启拦截回复"}
          </Button>
        }
      >
        <div className="flex flex-col gap-1.5 text-sm">
          <StatusDot tone={br.enabled ? "ok" : "muted"}>
            {br.enabled ? "已开启：返回自定义回复" : "已关闭：返回错误（422 待复核 / 403 拒绝）"}
          </StatusDot>
          <p className="text-xs text-muted-foreground">
            {br.available
              ? `开启后，文本生成类接口（OpenAI Chat、Responses、Claude Messages、Gemini、旧版 Completions/Edits）被拦截时返回 200 的正常回复，内容轮流取自策略中的 ${fmt(br.count)} 条自定义回复；其他接口和故障仍返回错误。${summary?.mode === "enforce" ? "" : "当前不是拦截模式。"}`
              : "当前策略未配置自定义回复（enforce.block_replies），无法开启。"}
          </p>
          {br.available && !admin && <p className="text-xs text-muted-foreground">只有管理员账号可以切换。</p>}
          {error && <p className="text-xs text-destructive">操作异常：{error}</p>}
        </div>
      </Section>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>
              {targetState ? "确认开启自定义拦截回复？" : "确认关闭自定义拦截回复？"}
            </DialogTitle>
            <DialogDescription>
              {targetState
                ? "开启后，文本生成类接口被网关拦截时将不再返回 403/422 报错，而是返回 HTTP 200 及预设的友好提示内容。"
                : "关闭后，所有被拦截的请求将恢复直接返回标准错误状态码（422 待复核 / 403 拒绝）。"}
            </DialogDescription>
          </DialogHeader>

          <div className="flex flex-col gap-2 rounded-lg border bg-muted/40 p-3.5 text-xs text-muted-foreground">
            <div>
              <span className="font-medium text-foreground">受影响协议：</span>
              OpenAI Chat (/v1/chat/completions)、Responses (/v1/responses)、Claude Messages
              (/v1/messages)、Gemini (/v1beta/models/*)、旧版 Completions / Edits
            </div>
            <div>
              <span className="font-medium text-foreground">不受影响范围：</span>
              图像/语音/视频/Midjourney/Suno 生成、Embeddings、Rerank、Moderations、搜索工具，以及审查故障和未覆盖接口，仍返回错误。
            </div>
            {summary?.mode !== "enforce" && (
              <div className="text-amber-600 dark:text-amber-400">
                注意：当前网关处于影子模式（Shadow Mode），策略尚未实际拦截任何流量。
              </div>
            )}
          </div>

          {error && <p className="text-xs text-destructive">切换失败：{error}</p>}

          <DialogFooter>
            <DialogClose render={<Button variant="outline" size="sm" disabled={busy} />}>
              取消
            </DialogClose>
            <Button
              size="sm"
              variant={targetState ? "default" : "destructive"}
              disabled={busy}
              onClick={() => void handleConfirm()}
            >
              {busy ? "切换中…" : targetState ? "确认开启" : "确认关闭"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

type Group = { key: string; name: string; tone: Tone; desc: string; inEnforce: React.ReactNode }

export function PolicyPage() {
  const { config, summary } = useStore()
  if (!summary) return null
  const pol = config?.policy
  const header = <PageHeader title="策略与覆盖" description="当前生效的审查策略（只读）、拦截回复设置与各接口的审查覆盖情况" />
  if (!pol) {
    return (
      <div className="flex flex-col gap-5">
        {header}
        <Notice>内容审查已停用，当前没有加载审查策略。</Notice>
      </div>
    )
  }
  const t = summary.stats.totals
  const draft = /-draft$/.test(pol.version)

  const labelHits = t.labels ?? {}
  const labelRows: [string, React.ReactNode, number][] = ["Safe", "Controversial", "Unsafe", "Unknown"]
    .filter((k) => k === "Unsafe" || k in pol.labels)
    .map((k) => [
      k,
      k === "Unsafe" ? <span className="text-xs text-muted-foreground">按风险类别处置</span> : <ActionBadge a={pol.labels[k]} />,
      labelHits[k] ?? 0,
    ])
  const labelMax = Math.max(0, ...labelRows.map((r) => r[2]))

  const catHits = Object.fromEntries((summary.stats.categories ?? []).map((c) => [c.key, c.count]))
  const catRows = Object.entries(pol.unsafe_categories).sort(
    (a, b) => (catHits[b[0]] ?? 0) - (catHits[a[0]] ?? 0) || catName(a[0]).localeCompare(catName(b[0]), "zh")
  )
  const catMax = Math.max(0, ...catRows.map(([k]) => catHits[k] ?? 0))

  const seen = t.protocols ?? {}
  const exc = new Set(pol.coverage_exceptions ?? [])
  const t0 = new Set(pol.t0_only_protocols ?? [])
  const groups: Group[] = [
    { key: "text", name: "审查最新用户输入", tone: "ok", desc: "送分类模型审查", inEnforce: <span className="text-xs text-muted-foreground">按分类结果处置</span> },
    { key: "t0", name: "免审查", tone: "muted", desc: "不含可审查文本", inEnforce: <ActionBadge a="forward" /> },
    { key: "exc", name: "已批准例外", tone: "warn", desc: "经审批暂不审查", inEnforce: <ActionBadge a="forward" /> },
    { key: "gap", name: "未覆盖", tone: "info", desc: "拦截模式下直接拒绝", inEnforce: <ActionBadge a="reject" /> },
  ]
  const groupOf = (p: string) => (t0.has(p) ? "t0" : TEXT_PROTOCOLS.has(p) ? "text" : exc.has(p) ? "exc" : "gap")
  const order = Object.keys(PROTOCOLS)
  const protos = order
    .concat(Object.keys(seen).filter((p) => !(p in PROTOCOLS)))
    .sort((a, b) => (seen[b] ?? 0) - (seen[a] ?? 0) || order.indexOf(a) - order.indexOf(b))
  const protoMax = Math.max(0, ...protos.map((p) => seen[p] ?? 0))
  const covered = protos.filter((p) => groupOf(p) === "text").length

  return (
    <div className="flex flex-col gap-5">
      {header}
      {draft && (
        <Notice>
          <b className="font-semibold">当前策略为草案。</b>
          网关拒绝以草案策略启动拦截模式；策略调整须经评测与审批后更新配置文件，控制台不提供修改入口。
        </Notice>
      )}

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Fact k="策略版本" sub={draft ? <StatusDot tone="warn">草案，不可用于拦截模式</StatusDot> : <StatusDot tone="ok">已批准</StatusDot>}>
          <span className="font-mono text-sm">{pol.version}</span>
        </Fact>
        <Fact k="运行模式" sub={MODES[summary.mode]?.desc}>
          {MODES[summary.mode]?.name ?? summary.mode}
        </Fact>
        <Fact k="分类模型" sub={Number(config?.settings.context_budget_bytes ?? 0) ? "最新用户输入及部分上下文" : "仅审查最新用户输入"}>
          <span className="font-mono text-sm">{config?.model}</span>
        </Fact>
        <Fact k="接口覆盖" sub={`${fmt(protos.length - covered)} 类接口不送审`}>
          {fmt(covered)} <span className="text-sm font-normal text-muted-foreground">/ {fmt(protos.length)} 类接口送审</span>
        </Fact>
      </div>

      <Section title="拦截模式下的兜底处置" hint="分类结果以外的情况；影子模式下仅记录，不拦截">
        <DescList
          items={[
            ["待复核请求", <ActionBadge a={pol.enforce.review} />],
            ["未列出类别", <ActionBadge a={pol.unsafe_default} />],
            ["无可审查输入", <ActionBadge a={pol.enforce.no_inspectable_input} />],
            ["无法解析请求", <ActionBadge a={pol.enforce.unparseable} />],
          ]}
        />
      </Section>

      <BlockReplySwitch />

      <div className="grid items-start gap-4 lg:grid-cols-2">
        <Section title="分类结果处置" hint="命中次数为所选时间范围内的统计" flush>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>分类结果</TableHead>
                <TableHead>处置</TableHead>
                <TableHead className="text-right">命中</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {labelRows.map(([k, action, n]) => (
                <TableRow key={k}>
                  <TableCell>
                    <LabelBadge l={k} />
                  </TableCell>
                  <TableCell>{action}</TableCell>
                  <TableCell>
                    <Hits n={n} max={labelMax} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Section>
        <Section title="风险类别处置" hint="分类结果为不安全时，按命中的类别处置" flush>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>风险类别</TableHead>
                <TableHead>处置</TableHead>
                <TableHead className="text-right">命中</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {catRows.map(([k, a]) => (
                <TableRow key={k}>
                  <TableCell>{catName(k)}</TableCell>
                  <TableCell>
                    <ActionBadge a={a} />
                  </TableCell>
                  <TableCell>
                    <Hits n={catHits[k] ?? 0} max={catMax} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Section>
      </div>

      <Section
        title="接口覆盖"
        hint="系统提示词、工具结果与历史对话不送审；请求数为所选时间范围内的受审查请求"
        flush
      >
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>接口类型</TableHead>
              <TableHead>审查方式</TableHead>
              <TableHead>拦截模式下</TableHead>
              <TableHead className="text-right">请求数</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {groups.map((g) => {
              const items = protos.filter((p) => groupOf(p) === g.key)
              if (!items.length) return null
              return (
                <React.Fragment key={g.key}>
                  <TableRow className="bg-muted/25 hover:bg-muted/25">
                    <TableCell colSpan={4} className="py-2">
                      <span className="flex items-center gap-2 text-xs">
                        <StatusDot tone={g.tone} className="font-medium">
                          {g.name}
                        </StatusDot>
                        <span className="text-muted-foreground">
                          {fmt(items.length)} 类 · {g.desc}
                        </span>
                      </span>
                    </TableCell>
                  </TableRow>
                  {items.map((p) => (
                    <TableRow key={p}>
                      <TableCell className={cn("first:pl-8", !seen[p] && "text-muted-foreground")}>{protoName(p)}</TableCell>
                      <TableCell>
                        <ToneBadge tone={g.tone}>{g.name}</ToneBadge>
                      </TableCell>
                      <TableCell>{g.inEnforce}</TableCell>
                      <TableCell>
                        <Hits n={seen[p] ?? 0} max={protoMax} />
                      </TableCell>
                    </TableRow>
                  ))}
                </React.Fragment>
              )
            })}
          </TableBody>
        </Table>
      </Section>
    </div>
  )
}
