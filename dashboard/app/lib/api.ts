const API_BASE = process.env.NEXT_PUBLIC_CLOWNPEANUTS_API ?? "http://127.0.0.1:8099"
const WS_BASE = process.env.NEXT_PUBLIC_CLOWNPEANUTS_WS ?? "ws://127.0.0.1:8099/ws/events"
const WS_THEATER_BASE = process.env.NEXT_PUBLIC_CLOWNPEANUTS_WS_THEATER ?? "ws://127.0.0.1:8099/ws/theater/live"
const WS_BASE_PROTOCOL = "cp-events-v1"
const DASHBOARD_AUTH_BOOTSTRAP_PATH = "/api/auth/session"

let authSessionBootstrapPromise: Promise<void> | null = null

const ensureDashboardAuthSession = (): Promise<void> => {
  if (authSessionBootstrapPromise) {
    return authSessionBootstrapPromise
  }
  authSessionBootstrapPromise = fetch(DASHBOARD_AUTH_BOOTSTRAP_PATH, {
    method: "POST",
    credentials: "include",
    cache: "no-store",
  })
    .then(() => undefined)
    .catch(() => undefined)
  return authSessionBootstrapPromise
}

const cpFetch = async (url: string, init?: RequestInit): Promise<Response> => {
  await ensureDashboardAuthSession()
  const nextInit = { ...(init ?? {}) }
  nextInit.credentials = init?.credentials ?? "include"
  return fetch(url, nextInit)
}

const withApiTokenQuery = (url: string): string => {
  return url
}

const apiWebSocketProtocols = (): string[] => [WS_BASE_PROTOCOL]

const withQueryParams = (url: string, params: Record<string, string>): string => {
  try {
    const parsed = new URL(url)
    for (const [key, value] of Object.entries(params)) {
      parsed.searchParams.set(key, value)
    }
    return parsed.toString()
  } catch {
    return url
  }
}

export {
  API_BASE,
  WS_BASE,
  WS_THEATER_BASE,
  apiWebSocketProtocols,
  cpFetch,
  ensureDashboardAuthSession,
  withApiTokenQuery,
  withQueryParams,
}
