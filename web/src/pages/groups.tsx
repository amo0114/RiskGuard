import * as React from "react"

import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Toggle } from "@/components/ui/toggle"
import { EmptyState, PageHeader, Section } from "@/components/console/bits"
import { api, HTTPError } from "@/lib/api"
import { catName, dt, fmt, RANGE_NAMES } from "@/lib/format"
import { useStore } from "@/lib/store"
import type { Dim, DimRow } from "@/lib/types"

const DIMS: [Dim, string, string][] = [
  [
    "credential",
    "API Key",
    "按 Key 指纹（同一把 Key 的请求），管理员可为指纹命名",
  ],
  ["client", "客户端", "按 User-Agent 的产品名与版本，如 codex-tui/0.164.0"],
  ["model", "模型", "按请求里的 model 字段（Gemini 取自路径）"],
]

const pct = (n: number, d: number) =>
  d ? `${((n / d) * 100).toFixed(1)}%` : "—"

function AliasDialog({
  row,
  onClose,
  onSaved,
}: {
  row: DimRow | null
  onClose: () => void
  onSaved: () => void
}) {
  const [name, setName] = React.useState(row?.alias ?? "")
  const [busy, setBusy] = React.useState(false)
  const [error, setError] = React.useState("")
  const save = async (value: string) => {
    if (!row) return
    setBusy(true)
    setError("")
    try {
      await api.setAlias(row.key, value)
      onSaved()
      onClose()
    } catch (e) {
      setError(e instanceof HTTPError ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Dialog open={!!row} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>为 Key 指纹命名</DialogTitle>
          <DialogDescription>
            指纹 <span className="font-mono">{row?.key}</span>
            。名称只给具名账号看，共享令牌仍只看到指纹。请用能对上人的称呼（如“张三-codex”），不要填写
            Key 本身。
          </DialogDescription>
        </DialogHeader>
        <Input
          value={name}
          maxLength={40}
          placeholder="名称（最多 40 字）"
          aria-label="名称"
          onChange={(e) => setName(e.target.value)}
        />
        {error && <p className="text-xs text-destructive">保存失败：{error}</p>}
        <DialogFooter>
          {row?.alias && (
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => void save("")}
            >
              移除名称
            </Button>
          )}
          <Button
            disabled={busy || !name.trim()}
            onClick={() => void save(name)}
          >
            保存
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export function GroupsPage() {
  const { range, lastOk, config, navigate, refresh } = useStore()
  const [dim, setDim] = React.useState<Dim>("credential")
  const [rows, setRows] = React.useState<DimRow[] | null>(null)
  const [error, setError] = React.useState("")
  const [naming, setNaming] = React.useState<DimRow | null>(null)
  const admin = config?.me.roles.includes("admin") ?? false

  // Follows the shared refresh (15s, the refresh button, the range selector).
  React.useEffect(() => {
    api.dimensions(dim, range).then(
      (res) => {
        setRows(res.rows)
        setError("")
      },
      (e: unknown) => setError(e instanceof Error ? e.message : String(e))
    )
  }, [dim, range, lastOk])

  const label = (r: DimRow) =>
    dim === "credential" ? (
      <span className="flex min-w-0 flex-col">
        {r.alias && <span className="truncate font-medium">{r.alias}</span>}
        <span className="truncate font-mono text-xs text-muted-foreground">
          {r.key}
        </span>
      </span>
    ) : (
      <span className="font-mono text-xs">{r.key}</span>
    )
  const filterKey = dim as "credential" | "client" | "model"

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="Key 与客户端"
        description={`${RANGE_NAMES[range]}内受审查请求按 API Key、客户端或模型分组（按整点小时统计）。点击行查看对应的审计事件。`}
      />
      <Section
        title="分组统计"
        hint={DIMS.find((d) => d[0] === dim)?.[2]}
        flush
        action={
          <div className="flex gap-1.5">
            {DIMS.map(([d, name]) => (
              <Toggle
                key={d}
                variant="outline"
                size="sm"
                pressed={dim === d}
                onPressedChange={() => {
                  setRows(null)
                  setDim(d)
                }}
              >
                {name}
              </Toggle>
            ))}
          </div>
        }
      >
        {error && (
          <p className="px-4 pb-3 text-sm text-destructive">
            加载失败：{error}
          </p>
        )}
        {!rows ? (
          <EmptyState text="加载中…" />
        ) : !rows.length ? (
          <EmptyState text="该时间范围内没有受审查请求" />
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{DIMS.find((d) => d[0] === dim)?.[1]}</TableHead>
                  <TableHead className="text-right">请求</TableHead>
                  <TableHead className="text-right">待复核</TableHead>
                  <TableHead className="text-right">拒绝</TableHead>
                  <TableHead className="text-right">
                    {config?.mode === "enforce" ? "已拦截" : "预计拦截"}
                  </TableHead>
                  <TableHead className="text-right">分类失败</TableHead>
                  <TableHead>主要风险类别</TableHead>
                  <TableHead>最近活跃</TableHead>
                  {dim === "credential" && <TableHead />}
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((r) => {
                  const blocked =
                    config?.mode === "enforce" ? r.enforced : r.would_block
                  const linkable = !r.key.startsWith("(")
                  return (
                    <TableRow
                      key={r.key}
                      className={linkable ? "cursor-pointer" : undefined}
                      onClick={() =>
                        linkable && navigate("events", { [filterKey]: r.key })
                      }
                    >
                      <TableCell className="max-w-72">
                        {linkable ? (
                          <button
                            type="button"
                            className="max-w-full rounded text-left hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                            onClick={(e) => {
                              e.stopPropagation()
                              navigate("events", { [filterKey]: r.key })
                            }}
                          >
                            {label(r)}
                          </button>
                        ) : (
                          <span className="text-muted-foreground">
                            {r.key === "(none)"
                              ? "（无）"
                              : "（其他，超出每小时上限）"}
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="text-right tabular-nums">
                        {fmt(r.requests)}
                      </TableCell>
                      <TableCell className="text-right tabular-nums">
                        {fmt(r.decisions.review ?? 0)}
                        <span className="ml-1 text-xs text-muted-foreground">
                          {pct(r.decisions.review ?? 0, r.requests)}
                        </span>
                      </TableCell>
                      <TableCell className="text-right tabular-nums">
                        {fmt(r.decisions.deny ?? 0)}
                      </TableCell>
                      <TableCell className="text-right tabular-nums">
                        {fmt(blocked)}
                      </TableCell>
                      <TableCell className="text-right tabular-nums">
                        {fmt(r.cls_errors)}
                      </TableCell>
                      <TableCell className="text-xs">
                        {r.categories?.length
                          ? r.categories
                              .map((c) => `${catName(c.key)} ${fmt(c.count)}`)
                              .join("、")
                          : "—"}
                      </TableCell>
                      <TableCell className="text-xs whitespace-nowrap text-muted-foreground tabular-nums">
                        {r.last_seen ? dt(new Date(r.last_seen * 1000)) : "—"}
                      </TableCell>
                      {dim === "credential" && (
                        <TableCell className="whitespace-nowrap">
                          {linkable && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={(e) => {
                                e.stopPropagation()
                                location.hash = `#/samples?credential=${r.key}`
                              }}
                            >
                              样本
                            </Button>
                          )}
                          {linkable && admin && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={(e) => {
                                e.stopPropagation()
                                setNaming(r)
                              }}
                            >
                              {r.alias ? "改名" : "命名"}
                            </Button>
                          )}
                        </TableCell>
                      )}
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </Section>
      <AliasDialog
        key={naming?.key ?? ""}
        row={naming}
        onClose={() => setNaming(null)}
        onSaved={() => void refresh(true)}
      />
    </div>
  )
}
