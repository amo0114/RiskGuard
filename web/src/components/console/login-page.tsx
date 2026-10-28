import * as React from "react"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Logo } from "@/components/console/app-sidebar"
import { api } from "@/lib/api"
import { useStore } from "@/lib/store"

export function LoginPage() {
  const { refresh } = useStore()
  const [token, setToken] = React.useState("")
  const [error, setError] = React.useState("")
  const [busy, setBusy] = React.useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!token.trim()) {
      setError("请输入访问令牌")
      return
    }
    setBusy(true)
    setError("")
    try {
      const status = await api.login(token.trim())
      if (status !== 200) {
        setError(status === 429 ? "尝试次数过多，请 1 分钟后再试" : "访问令牌无效")
        return
      }
      setToken("")
      await refresh(true)
    } catch {
      setError("无法连接网关，请检查网络")
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="grid min-h-svh place-items-center bg-background px-4">
      <div className="w-full max-w-sm text-center">
        <Logo className="mx-auto size-11" />
        <h1 className="mt-5 text-2xl font-semibold tracking-tight">登录风控网关控制台</h1>
        <p className="mt-1.5 text-sm text-muted-foreground">请输入管理员发放的访问令牌</p>
        <form onSubmit={submit} className="mt-6 flex flex-col gap-3 text-left">
          <Input
            type="password"
            autoFocus
            autoComplete="off"
            spellCheck={false}
            placeholder="访问令牌"
            aria-label="访问令牌"
            className="h-10 font-mono"
            value={token}
            onChange={(e) => setToken(e.target.value)}
          />
          {error && (
            <p role="alert" className="text-sm text-red-600 dark:text-red-400">
              {error}
            </p>
          )}
          <Button type="submit" size="lg" className="h-10" disabled={busy}>
            {busy ? "登录中…" : "登录"}
          </Button>
        </form>
        <p className="mt-6 text-xs leading-relaxed text-muted-foreground">
          令牌保存在服务器 <code className="font-mono">/etc/riskguard/console.token</code>
          。控制台为只读视图，不展示请求正文、密钥或原始来源地址。
        </p>
      </div>
    </div>
  )
}
