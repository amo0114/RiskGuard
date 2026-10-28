import { BarChart3, ClipboardCheck, Home, LogOut, ReceiptText, Server, ShieldCheck, Users } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { MODES } from "@/lib/format"
import { useStore, type View } from "@/lib/store"

const NAV: { label?: string; items: { view: View; title: string; icon: typeof Home }[] }[] = [
  { items: [{ view: "home", title: "首页", icon: Home }] },
  {
    label: "监控",
    items: [
      { view: "overview", title: "运行总览", icon: BarChart3 },
      { view: "events", title: "审计事件", icon: ReceiptText },
      { view: "groups", title: "Key 与客户端", icon: Users },
      { view: "samples", title: "样本复核", icon: ClipboardCheck },
    ],
  },
  {
    label: "管理",
    items: [
      { view: "policy", title: "策略与覆盖", icon: ShieldCheck },
      { view: "system", title: "系统状态", icon: Server },
    ],
  },
]

const ROLE_NAMES: Record<string, string> = { reviewer: "复核员", admin: "管理员" }

export function Logo({ className = "size-7" }: { className?: string }) {
  return (
    <span className={`grid shrink-0 place-items-center rounded-lg bg-primary text-primary-foreground ${className}`}>
      <ShieldCheck className="size-[58%]" strokeWidth={2} />
    </span>
  )
}

export function AppSidebar() {
  const { view, navigate, summary, config, logout } = useStore()
  const me = config?.me
  const roleNames = me?.roles.length ? me.roles.map((r) => ROLE_NAMES[r] ?? r).join("、") : "仅元数据"
  const { setOpenMobile } = useSidebar()
  const mode = summary ? MODES[summary.mode] : null
  const enforce = summary?.mode === "enforce"

  const go = (v: View, filter?: Parameters<typeof navigate>[1]) => {
    navigate(v, filter)
    setOpenMobile(false)
  }

  return (
    <Sidebar variant="sidebar" collapsible="offcanvas">
      <SidebarHeader className="h-14 flex-row items-center gap-2.5 px-4">
        <Logo />
        <span className="text-[15px] font-semibold tracking-wide">风控网关</span>
      </SidebarHeader>
      <SidebarContent>
        {NAV.map((g, i) => (
          <SidebarGroup key={i} className="py-1">
            {g.label && <SidebarGroupLabel>{g.label}</SidebarGroupLabel>}
            <SidebarMenu>
              {g.items.map((it) => (
                <SidebarMenuItem key={it.view}>
                  <SidebarMenuButton
                    isActive={view === it.view}
                    render={<a href={`#/${it.view}`} onClick={() => setOpenMobile(false)} />}
                  >
                    <it.icon />
                    <span>{it.title}</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroup>
        ))}
      </SidebarContent>
      <SidebarFooter className="gap-3 p-3">
        {summary && mode && (
          <div className="rounded-xl border bg-background p-3.5 text-xs leading-relaxed text-muted-foreground">
            <div className="mb-1 flex items-center gap-2 text-sm font-semibold text-foreground">
              <span className={`size-2 rounded-full ${mode.dot}`} />
              {mode.name}
              <Badge variant="secondary" className="h-5 bg-violet-500/10 px-1.5 text-[11px] text-violet-700 dark:text-violet-300">
                运行中
              </Badge>
            </div>
            <p className="mb-3">
              {summary.mode === "shadow" ? "请求照常转发，仅记录审查结论。切换到拦截模式前，先复核“预计拦截”的请求。" : mode.desc}
            </p>
            <div className="flex flex-col gap-1.5">
              {summary.mode !== "disabled" && (
                <Button variant="outline" size="sm" onClick={() => go("events", { blockedOnly: true })}>
                  {enforce ? "查看已拦截" : "查看预计拦截"}
                </Button>
              )}
              <Button variant="outline" size="sm" onClick={() => go("policy")}>
                查看策略
              </Button>
            </div>
          </div>
        )}
        <div className="flex items-center gap-2.5 px-1">
          <span className="grid size-8 place-items-center rounded-lg bg-violet-500/10 text-sm font-semibold text-violet-700 dark:text-violet-300">
            管
          </span>
          <div className="flex min-w-0 flex-1 flex-col leading-tight">
            <span className="truncate text-sm font-medium">{me && me.actor !== "shared-token" ? me.actor : "共享令牌"}</span>
            <span className="truncate text-xs text-muted-foreground">{roleNames}</span>
          </div>
          <Tooltip>
            <TooltipTrigger render={<Button variant="ghost" size="icon-sm" aria-label="退出登录" onClick={() => void logout()} />}>
              <LogOut />
            </TooltipTrigger>
            <TooltipContent>退出登录</TooltipContent>
          </Tooltip>
        </div>
      </SidebarFooter>
    </Sidebar>
  )
}
