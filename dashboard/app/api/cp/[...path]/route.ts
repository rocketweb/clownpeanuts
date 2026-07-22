import { NextRequest, NextResponse } from "next/server"

import {
  DASHBOARD_SESSION_COOKIE_NAME,
  readDashboardAuthConfig,
  verifyDashboardSession,
} from "../../../lib/server-auth"

export const dynamic = "force-dynamic"

type RouteContext = { params: Promise<{ path: string[] }> }

const MUTATION_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"])

const mutationHasSameOrigin = (request: NextRequest): boolean => {
  const origin = request.headers.get("origin")
  if (!origin) return false
  const forwardedProtocol = (request.headers.get("x-forwarded-proto") ?? "").split(",")[0].trim()
  const protocol = forwardedProtocol || request.nextUrl.protocol.replace(/:$/, "")
  if (!new Set(["http", "https"]).has(protocol)) return false
  const host = (request.headers.get("x-forwarded-host") ?? request.headers.get("host") ?? request.nextUrl.host)
    .split(",")[0]
    .trim()
  try {
    return new URL(origin).origin === new URL(`${protocol}://${host}`).origin
  } catch {
    return false
  }
}

const proxy = async (request: NextRequest, context: RouteContext): Promise<NextResponse> => {
  const config = readDashboardAuthConfig()
  const session = request.cookies.get(DASHBOARD_SESSION_COOKIE_NAME)?.value
  if (!config.configured || !verifyDashboardSession(session, config.username, config.sessionSecret)) {
    return NextResponse.json({ detail: "authentication required" }, { status: 401 })
  }

  const method = request.method.toUpperCase()
  if (MUTATION_METHODS.has(method) && !mutationHasSameOrigin(request)) {
    return NextResponse.json({ detail: "cross-origin mutation refused" }, { status: 403 })
  }

  const internalBase = (process.env.CLOWNPEANUTS_API_INTERNAL_URL ?? "http://127.0.0.1:8099").trim()
  let base: URL
  try {
    base = new URL(internalBase)
  } catch {
    return NextResponse.json({ detail: "internal API URL is invalid" }, { status: 503 })
  }
  if (!new Set(["http:", "https:"]).has(base.protocol) || base.username || base.password) {
    return NextResponse.json({ detail: "internal API URL is invalid" }, { status: 503 })
  }

  const { path } = await context.params
  const encodedPath = path.map((part) => encodeURIComponent(part)).join("/")
  const target = new URL(encodedPath, `${base.toString().replace(/\/$/, "")}/`)
  target.search = request.nextUrl.search
  const headers = new Headers()
  for (const name of ["accept", "content-type", "if-match", "if-none-match"]) {
    const value = request.headers.get(name)
    if (value) headers.set(name, value)
  }
  headers.set("authorization", `Bearer ${config.apiToken}`)

  const body = method === "GET" || method === "HEAD" ? undefined : request.body
  const upstreamRequest: RequestInit & { duplex?: "half" } = {
    method,
    headers,
    body,
    cache: "no-store",
    redirect: "manual",
    signal: AbortSignal.timeout(30_000),
  }
  if (body) upstreamRequest.duplex = "half"
  let upstream: Response
  try {
    upstream = await fetch(target, upstreamRequest)
  } catch {
    return NextResponse.json({ detail: "upstream API unavailable" }, { status: 502 })
  }

  const responseHeaders = new Headers()
  for (const name of ["content-type", "content-disposition", "etag", "last-modified", "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining"]) {
    const value = upstream.headers.get(name)
    if (value) responseHeaders.set(name, value)
  }
  return new NextResponse(upstream.body, {
    status: upstream.status,
    headers: responseHeaders,
  })
}

export const GET = proxy
export const POST = proxy
export const PUT = proxy
export const PATCH = proxy
export const DELETE = proxy
