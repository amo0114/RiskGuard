import * as React from "react"

import { api, Unauthorized } from "@/lib/api"
import type { AuditEvent, ConsoleConfig, RangeKey, Summary } from "@/lib/types"

export type View = "home" | "overview" | "events" | "groups" | "samples" | "policy" | "system"
export const VIEWS: View[] = ["home", "overview", "events", "groups", "samples", "policy", "system"]

export type EventFilter = {
  decision: string
  label: string
  protocol: string
  blockedOnly: boolean
  q: string
  credential: string
  client: string
  model: string
}
export const EMPTY_FILTER: EventFilter = {
  decision: "",
  label: "",
  protocol: "",
  blockedOnly: false,
  q: "",
  credential: "",
  client: "",
  model: "",
}
// Exact-match filters that travel in the events URL alongside blockedOnly and q.
const URL_FILTERS = ["decision", "label", "protocol", "credential", "client", "model"] as const

const REFRESH_MS = 15_000

type Store = {
  authed: boolean | null // null while the first request is in flight
  summary: Summary | null
  events: AuditEvent[]
  config: ConsoleConfig | null
  range: RangeKey
  setRange: (r: RangeKey) => void
  lastOk: number
  failed: boolean
  refresh: (reloadConfig?: boolean) => Promise<void>
  /** Stops the 15s auto refresh (per viewer); the refresh button still works. */
  paused: boolean
  setPaused: (p: boolean) => void
  view: View
  navigate: (v: View, filter?: Partial<EventFilter>) => void
  filter: EventFilter
  setFilter: React.Dispatch<React.SetStateAction<EventFilter>>
  logout: () => Promise<void>
}

const StoreContext = React.createContext<Store | null>(null)

export function useStore() {
  const s = React.useContext(StoreContext)
  if (!s) throw new Error("useStore must be used inside <StoreProvider>")
  return s
}

const storage = {
  get(k: string) {
    try {
      return localStorage.getItem(k)
    } catch {
      return null
    }
  },
  set(k: string, v: string) {
    try {
      localStorage.setItem(k, v)
    } catch {
      // per-viewer convenience only
    }
  },
}

function parseHash(): { view: View; filter?: Partial<EventFilter> } {
  const hash = location.hash.replace(/^#\/?/, "")
  const [path, queryString] = hash.split("?")
  const view = (VIEWS.includes(path as View) ? path : "home") as View
  if (!queryString) return { view }
  const params = new URLSearchParams(queryString)
  const filter: Partial<EventFilter> = {}
  for (const k of URL_FILTERS) if (params.has(k)) filter[k] = params.get(k) || ""
  if (params.has("blockedOnly")) filter.blockedOnly = params.get("blockedOnly") === "true"
  if (params.has("q")) filter.q = params.get("q") || ""
  return { view, filter }
}

function eventsHash(f: EventFilter): string {
  const params = new URLSearchParams()
  for (const k of URL_FILTERS) if (f[k]) params.set(k, f[k])
  if (f.blockedOnly) params.set("blockedOnly", "true")
  if (f.q) params.set("q", f.q)
  const qs = params.toString()
  return qs ? `#/events?${qs}` : `#/events`
}

export function StoreProvider({ children }: { children: React.ReactNode }) {
  const initial = React.useMemo(() => parseHash(), [])
  const [authed, setAuthed] = React.useState<boolean | null>(null)
  const [summary, setSummary] = React.useState<Summary | null>(null)
  const [events, setEvents] = React.useState<AuditEvent[]>([])
  const [config, setConfig] = React.useState<ConsoleConfig | null>(null)
  const [range, setRangeState] = React.useState<RangeKey>(() => {
    const r = storage.get("rg.range")
    return r === "1h" || r === "7d" ? r : "24h"
  })
  const [lastOk, setLastOk] = React.useState(0)
  const [failed, setFailed] = React.useState(false)
  const [paused, setPausedState] = React.useState(() => storage.get("rg.paused") === "1")
  const [view, setView] = React.useState<View>(initial.view)
  const [filter, setFilter] = React.useState<EventFilter>(() => ({
    ...EMPTY_FILTER,
    ...(initial.filter || {}),
  }))
  const rangeRef = React.useRef(range)
  const configRef = React.useRef(config)
  React.useEffect(() => {
    rangeRef.current = range
    configRef.current = config
  }, [range, config])

  const refresh = React.useCallback(async (reloadConfig = false) => {
    try {
      const [sm, ev, cfg] = await Promise.all([
        api.summary(rangeRef.current),
        api.events(),
        reloadConfig || !configRef.current ? api.config() : Promise.resolve(null),
      ])
      setSummary(sm)
      setEvents(ev.events ?? [])
      if (cfg) setConfig(cfg)
      setAuthed(true)
      setFailed(false)
      setLastOk(Date.now())
    } catch (e) {
      if (e instanceof Unauthorized) {
        setAuthed(false)
        setConfig(null)
      } else {
        setFailed(true)
      }
    }
  }, [])

  React.useEffect(() => {
    void refresh()
  }, [refresh, range])

  React.useEffect(() => {
    if (!authed || paused) return
    const t = setInterval(() => {
      if (!document.hidden) void refresh()
    }, REFRESH_MS)
    const onVisible = () => {
      if (!document.hidden) void refresh()
    }
    document.addEventListener("visibilitychange", onVisible)
    return () => {
      clearInterval(t)
      document.removeEventListener("visibilitychange", onVisible)
    }
  }, [authed, paused, refresh])

  React.useEffect(() => {
    const onHash = () => {
      const parsed = parseHash()
      setView(parsed.view)
      // The events URL is the whole filter: a hash without a parameter clears it.
      if (parsed.view === "events") {
        setFilter({ ...EMPTY_FILTER, ...parsed.filter })
      }
      window.scrollTo(0, 0)
    }
    window.addEventListener("hashchange", onHash)
    return () => window.removeEventListener("hashchange", onHash)
  }, [])

  // Each filter change is a history entry (back/forward restores it via hashchange); typing in
  // the search box only rewrites the current entry.
  const lastFilter = React.useRef(filter)
  React.useEffect(() => {
    if (view !== "events") return
    const prev = lastFilter.current
    lastFilter.current = filter
    const targetHash = eventsHash(filter)
    if (location.hash === targetHash) return
    const typing = (Object.keys(filter) as (keyof EventFilter)[]).every(
      (k) => k === "q" || prev[k] === filter[k]
    )
    if (typing) history.replaceState(null, "", targetHash)
    else history.pushState(null, "", targetHash)
  }, [view, filter])

  const value = React.useMemo<Store>(
    () => ({
      authed,
      summary,
      events,
      config,
      range,
      setRange: (r) => {
        storage.set("rg.range", r)
        setRangeState(r)
      },
      lastOk,
      failed,
      refresh,
      paused,
      setPaused: (p) => {
        storage.set("rg.paused", p ? "1" : "0")
        setPausedState(p)
      },
      view,
      navigate: (v, f) => {
        if (v === "events") {
          // Without an explicit filter, keep the current one in the URL (hashchange applies it).
          location.hash = eventsHash(f ? { ...EMPTY_FILTER, ...f } : filter)
        } else {
          location.hash = `#/${v}`
        }
      },
      filter,
      setFilter,
      logout: async () => {
        try {
          await api.logout()
        } catch {
          // the session is gone either way
        }
        setAuthed(false)
        setConfig(null)
      },
    }),
    [authed, summary, events, config, range, lastOk, failed, refresh, paused, view, filter]
  )

  return <StoreContext.Provider value={value}>{children}</StoreContext.Provider>
}
