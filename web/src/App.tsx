import { RefreshCw, ServerCrash } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar"
import { AppSidebar } from "@/components/console/app-sidebar"
import { LoginPage } from "@/components/console/login-page"
import { SiteHeader } from "@/components/console/site-header"
import { EventsPage } from "@/pages/events"
import { GroupsPage } from "@/pages/groups"
import { HomePage } from "@/pages/home"
import { OverviewPage } from "@/pages/overview"
import { PolicyPage } from "@/pages/policy"
import { SamplesPage } from "@/pages/samples"
import { SystemPage } from "@/pages/system"
import { useStore, type View } from "@/lib/store"

const PAGES: Record<View, () => React.ReactNode> = {
  home: HomePage,
  overview: OverviewPage,
  events: EventsPage,
  groups: GroupsPage,
  samples: SamplesPage,
  policy: PolicyPage,
  system: SystemPage,
}

function Loading() {
  return (
    <div className="flex flex-col gap-4">
      <Skeleton className="h-8 w-48" />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
        {Array.from({ length: 6 }, (_, i) => (
          <Skeleton key={i} className="h-28 rounded-xl" />
        ))}
      </div>
      <Skeleton className="h-80 rounded-xl" />
    </div>
  )
}

function ConnectionError({ onRetry }: { onRetry: () => void }) {
  return (
    <div className="flex min-h-[50vh] flex-col items-center justify-center text-center">
      <div className="flex size-12 items-center justify-center rounded-xl bg-destructive/10 text-destructive dark:bg-destructive/20">
        <ServerCrash className="size-6" />
      </div>
      <h2 className="mt-4 text-lg font-semibold tracking-tight">无法连接风控网关</h2>
      <p className="mt-1.5 max-w-sm text-sm text-muted-foreground">
        未能从网关管理接口获取运行状态，可能网关服务正在启动、配置重载或网络通信异常。
      </p>
      <Button variant="outline" className="mt-6 gap-2" onClick={onRetry}>
        <RefreshCw className="size-4" />
        重新连接
      </Button>
    </div>
  )
}

export default function App() {
  const { authed, summary, view, failed, refresh } = useStore()
  if (authed === false) return <LoginPage />
  const Page = PAGES[view]
  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset className="min-w-0">
        <SiteHeader />
        <main className="mx-auto w-full max-w-[1400px] flex-1 px-4 pt-2 pb-10 md:px-6">
          {failed && !summary ? (
            <ConnectionError onRetry={() => void refresh(true)} />
          ) : summary ? (
            <Page />
          ) : (
            <Loading />
          )}
        </main>
      </SidebarInset>
    </SidebarProvider>
  )
}
