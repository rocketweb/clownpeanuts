import { NextRequest, NextResponse } from "next/server"

import {
  createWebSocketTicket,
  DASHBOARD_SESSION_COOKIE_NAME,
  readDashboardAuthConfig,
  verifyDashboardSession,
} from "../../../lib/server-auth"

const websocketBase = (request: NextRequest): string => {
  const configured = (process.env.CLOWNPEANUTS_PUBLIC_WS_BASE ?? "").trim().replace(/\/$/, "")
  if (configured) {
    const parsed = new URL(configured)
    if (!new Set(["ws:", "wss:"]).has(parsed.protocol)) throw new Error("invalid public websocket scheme")
    return parsed.toString().replace(/\/$/, "")
  }
  const hostHeader = (request.headers.get("x-forwarded-host") ?? request.headers.get("host") ?? request.nextUrl.host)
    .split(",")[0]
    .trim()
  const hostname = new URL(`http://${hostHeader}`).hostname
  const forwardedProtocol = (request.headers.get("x-forwarded-proto") ?? "").split(",")[0].trim()
  const protocol = forwardedProtocol === "https" || request.nextUrl.protocol === "https:" ? "wss" : "ws"
  const port = Number(process.env.CLOWNPEANUTS_PUBLIC_WS_PORT ?? "8099")
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error("invalid public websocket port")
  const bracketedHostname = hostname.includes(":") ? `[${hostname}]` : hostname
  return `${protocol}://${bracketedHostname}:${port}`
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  const config = readDashboardAuthConfig()
  const session = request.cookies.get(DASHBOARD_SESSION_COOKIE_NAME)?.value
  if (!config.configured || !verifyDashboardSession(session, config.username, config.sessionSecret)) {
    return NextResponse.json({ detail: "authentication required" }, { status: 401 })
  }
  try {
    return NextResponse.json({
      ticket: createWebSocketTicket(config.sessionSecret),
      websocket_base: websocketBase(request),
    })
  } catch {
    return NextResponse.json({ detail: "websocket endpoint is misconfigured" }, { status: 503 })
  }
}
