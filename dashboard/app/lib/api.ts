const API_BASE = "/api/cp"
const WS_BASE = "/ws/events"
const WS_THEATER_BASE = "/ws/theater/live"
const WS_BASE_PROTOCOL = "cp-events-v1"
const DASHBOARD_AUTH_BOOTSTRAP_PATH = "/api/auth/session"
const DASHBOARD_WEBSOCKET_TICKET_PATH = "/api/auth/websocket-ticket"

let authSessionBootstrapPromise: Promise<void> | null = null

const ensureDashboardAuthSession = (): Promise<void> => {
  if (authSessionBootstrapPromise) {
    return authSessionBootstrapPromise
  }
  authSessionBootstrapPromise = fetch(DASHBOARD_AUTH_BOOTSTRAP_PATH, {
    credentials: "include",
    cache: "no-store",
  })
    .then(async (response) => {
      const payload = await response.json().catch(() => ({})) as { authenticated?: boolean }
      if (!response.ok || !payload.authenticated) {
        if (typeof window !== "undefined") window.location.assign("/login")
        throw new Error("dashboard authentication required")
      }
    })
    .catch((error) => {
      authSessionBootstrapPromise = null
      throw error
    })
  return authSessionBootstrapPromise
}

const cpFetch = async (url: string, init?: RequestInit): Promise<Response> => {
  await ensureDashboardAuthSession()
  const nextInit = { ...(init ?? {}) }
  nextInit.credentials = init?.credentials ?? "include"
  const response = await fetch(url, nextInit)
  if (response.status === 401) {
    authSessionBootstrapPromise = null
    if (typeof window !== "undefined") window.location.assign("/login")
  }
  return response
}

const withApiTokenQuery = (url: string): string => {
  return url
}

const apiWebSocketProtocols = async (): Promise<{ protocols: string[]; websocketBase: string }> => {
  await ensureDashboardAuthSession()
  const response = await fetch(DASHBOARD_WEBSOCKET_TICKET_PATH, {
    method: "POST",
    credentials: "include",
    cache: "no-store",
  })
  if (!response.ok) {
    authSessionBootstrapPromise = null
    if (typeof window !== "undefined") window.location.assign("/login")
    throw new Error("websocket authentication required")
  }
  const payload = await response.json() as { ticket?: string; websocket_base?: string }
  const ticket = String(payload.ticket ?? "")
  const websocketBase = String(payload.websocket_base ?? "").replace(/\/$/, "")
  if (!ticket || !websocketBase) throw new Error("invalid websocket authentication response")
  const encodedTicket = btoa(ticket).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
  return {
    protocols: [WS_BASE_PROTOCOL, `cp-auth.${encodedTicket}`],
    websocketBase,
  }
}

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
