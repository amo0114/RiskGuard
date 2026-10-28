import type {
  AuditEvent,
  ConsoleConfig,
  Dim,
  DimRow,
  RangeKey,
  ReviewInput,
  Sample,
  SampleDetail,
  SampleStatus,
  Summary,
} from "@/lib/types"

export class Unauthorized extends Error {}

/** Non-2xx answer; message is the server's error text when it sent one. */
export class HTTPError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/console/api/${path}`, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    ...init,
  })
  if (res.status === 401) throw new Unauthorized()
  if (!res.ok) {
    const body = (await res.json().catch(() => null)) as {
      error?: string
    } | null
    throw new HTTPError(res.status, body?.error ?? `HTTP ${res.status}`)
  }
  return res.json() as Promise<T>
}

export const api = {
  summary: (range: RangeKey) => call<Summary>(`summary?range=${range}`),
  events: () => call<{ events: AuditEvent[] | null }>("events"),
  config: () => call<ConsoleConfig>("config"),
  dimensions: (dim: Dim, range: RangeKey) =>
    call<{ dim: Dim; rows: DimRow[] }>(`dimensions?dim=${dim}&range=${range}`),
  setAlias: (key: string, name: string) =>
    call<{ key: string; name: string }>("aliases", {
      method: "POST",
      body: JSON.stringify({ key, name }),
    }),
  logout: () => call<unknown>("logout", { method: "POST" }),
  samples: (q: Record<string, string>) =>
    call<{ enabled: boolean; samples: Sample[] }>(
      `samples?${new URLSearchParams(q)}`
    ),
  sampleStatus: () => call<SampleStatus>("samples/status"),
  sample: (id: number) => call<SampleDetail>(`samples/${id}`),
  addReview: (id: number, r: ReviewInput) =>
    call<{ id: number }>(`samples/${id}/reviews`, {
      method: "POST",
      body: JSON.stringify(r),
    }),
  deleteSample: (id: number) =>
    call<unknown>(`samples/${id}/delete`, { method: "POST" }),
  setBlockReply: (enabled: boolean) =>
    call<{ enabled: boolean }>("block-reply", {
      method: "POST",
      body: JSON.stringify({ enabled }),
    }),
  login: async (token: string) => {
    const res = await fetch("/console/api/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    })
    return res.status
  },
}
