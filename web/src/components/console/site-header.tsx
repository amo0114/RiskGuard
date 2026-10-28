import * as React from "react"
import { Clock, Moon, Pause, Play, RefreshCw, Sun } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SidebarTrigger } from "@/components/ui/sidebar"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useTheme } from "@/components/theme-provider"
import { RANGE_NAMES } from "@/lib/format"
import { useStore } from "@/lib/store"
import type { RangeKey } from "@/lib/types"

const RANGES = (Object.keys(RANGE_NAMES) as RangeKey[]).map((value) => ({ value, label: RANGE_NAMES[value] }))

function SyncStatus() {
  const { lastOk, failed, paused } = useStore()
  const [now, setNow] = React.useState(() => Date.now())
  React.useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [])
  if (!lastOk) return null
  const age = Math.max(0, now - lastOk) / 1000
  const dot = failed ? "bg-red-500" : age > 45 ? "bg-amber-500" : "bg-emerald-500"
  return (
    <span className={`hidden items-center gap-1.5 text-xs sm:inline-flex ${failed ? "text-red-600 dark:text-red-400" : "text-muted-foreground"}`}>
      <span className={`size-1.5 rounded-full ${dot}`} />
      {failed
        ? "同步失败，重试中"
        : `${age < 5 ? "数据已同步" : `${Math.floor(age)} 秒前同步`}${paused ? " · 自动刷新已暂停" : ""}`}
    </span>
  )
}

export function SiteHeader() {
  const { range, setRange, refresh, paused, setPaused } = useStore()
  const { theme, setTheme } = useTheme()
  const dark =
    theme === "dark" || (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches)
  return (
    <header className="sticky top-0 z-10 flex h-14 shrink-0 items-center gap-2 bg-background/85 px-4 backdrop-blur md:px-6">
      <SidebarTrigger className="-ml-1 md:hidden" />
      <Select items={RANGES} value={range} onValueChange={(v) => v && setRange(v as RangeKey)}>
        <SelectTrigger size="sm" className="border-0 bg-transparent font-medium shadow-none hover:bg-muted dark:bg-transparent" aria-label="统计时间范围">
          <Clock className="text-muted-foreground" />
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {RANGES.map((r) => (
            <SelectItem key={r.value} value={r.value}>
              {r.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <div className="flex-1" />
      <SyncStatus />
      <Tooltip>
        <TooltipTrigger render={<Button variant="ghost" size="icon-sm" aria-label="立即刷新" onClick={() => void refresh(true)} />}>
          <RefreshCw />
        </TooltipTrigger>
        <TooltipContent>立即刷新</TooltipContent>
      </Tooltip>
      <Tooltip>
        <TooltipTrigger
          render={
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label={paused ? "恢复自动刷新" : "暂停自动刷新"}
              aria-pressed={paused}
              onClick={() => setPaused(!paused)}
            />
          }
        >
          {paused ? <Play /> : <Pause />}
        </TooltipTrigger>
        <TooltipContent>{paused ? "恢复自动刷新（每 15 秒）" : "暂停自动刷新"}</TooltipContent>
      </Tooltip>
      <Tooltip>
        <TooltipTrigger
          render={<Button variant="ghost" size="icon-sm" aria-label="切换深色/浅色" onClick={() => setTheme(dark ? "light" : "dark")} />}
        >
          {dark ? <Sun /> : <Moon />}
        </TooltipTrigger>
        <TooltipContent>切换深色/浅色</TooltipContent>
      </Tooltip>
    </header>
  )
}
