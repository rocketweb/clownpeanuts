import { NextRequest, NextResponse } from "next/server"

import {
  createDashboardSession,
  DASHBOARD_SESSION_COOKIE_NAME,
  DASHBOARD_SESSION_TTL_SECONDS,
  readDashboardAuthConfig,
  verifyDashboardCredentials,
  verifyDashboardSession,
} from "../../../lib/server-auth"

const MAX_LOGIN_ATTEMPTS = 10
const MAX_GLOBAL_LOGIN_ATTEMPTS = 50
const LOGIN_WINDOW_MS = 15 * 60 * 1_000
const MAX_TRACKED_LOGIN_CLIENTS = 10_000
const attempts = new Map<string, { failures: number; resetAt: number }>()
let globalAttempts = { failures: 0, resetAt: 0 }

const clientKey = (request: NextRequest): string =>
  (request.headers.get("x-forwarded-for") ?? request.headers.get("x-real-ip") ?? "unknown")
    .split(",")[0]
    .trim()

const sameOrigin = (request: NextRequest): boolean => {
  const origin = request.headers.get("origin")
  if (!origin) return true
  const expectedHost = (request.headers.get("x-forwarded-host") ?? request.headers.get("host") ?? request.nextUrl.host)
    .split(",")[0]
    .trim()
  try {
    return new URL(origin).host === expectedHost
  } catch {
    return false
  }
}

const secureCookie = (request: NextRequest): boolean => {
  const configured = (process.env.CLOWNPEANUTS_COOKIE_SECURE ?? "").trim().toLowerCase()
  if (configured === "true") return true
  if (configured === "false") return false
  const forwardedProtocol = (request.headers.get("x-forwarded-proto") ?? "").split(",")[0].trim()
  return forwardedProtocol === "https" || request.nextUrl.protocol === "https:"
}

const sessionResponse = (request: NextRequest): NextResponse => {
  const config = readDashboardAuthConfig()
  const session = request.cookies.get(DASHBOARD_SESSION_COOKIE_NAME)?.value
  const authenticated = config.configured && verifyDashboardSession(
    session,
    config.username,
    config.sessionSecret,
  )
  return NextResponse.json({ ok: true, configured: config.configured, authenticated })
}

export async function GET(request: NextRequest): Promise<NextResponse> {
  return sessionResponse(request)
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  if (!sameOrigin(request)) {
    return NextResponse.json({ detail: "cross-origin login refused" }, { status: 403 })
  }
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
    return NextResponse.json({ detail: "application/json required" }, { status: 415 })
  }
  const contentLength = Number(request.headers.get("content-length") ?? "0")
  if (Number.isFinite(contentLength) && contentLength > 4_096) {
    return NextResponse.json({ detail: "login request too large" }, { status: 413 })
  }

  const key = clientKey(request)
  const now = Date.now()
  if (globalAttempts.resetAt <= now) globalAttempts = { failures: 0, resetAt: now + LOGIN_WINDOW_MS }
  if (globalAttempts.failures >= MAX_GLOBAL_LOGIN_ATTEMPTS) {
    return NextResponse.json(
      { detail: "too many login attempts" },
      { status: 429, headers: { "Retry-After": String(Math.ceil((globalAttempts.resetAt - now) / 1_000)) } },
    )
  }
  for (const [trackedKey, trackedState] of attempts) {
    if (trackedState.resetAt <= now) attempts.delete(trackedKey)
  }
  while (attempts.size >= MAX_TRACKED_LOGIN_CLIENTS && !attempts.has(key)) {
    const oldestKey = attempts.keys().next().value as string | undefined
    if (!oldestKey) break
    attempts.delete(oldestKey)
  }
  const state = attempts.get(key)
  if (state && state.resetAt > now && state.failures >= MAX_LOGIN_ATTEMPTS) {
    return NextResponse.json(
      { detail: "too many login attempts" },
      { status: 429, headers: { "Retry-After": String(Math.ceil((state.resetAt - now) / 1_000)) } },
    )
  }
  const config = readDashboardAuthConfig()
  if (!config.configured) {
    return NextResponse.json({ detail: "dashboard authentication is not configured" }, { status: 503 })
  }
  let payload: unknown
  try {
    payload = await request.json()
  } catch {
    return NextResponse.json({ detail: "invalid JSON" }, { status: 400 })
  }
  const body = payload && typeof payload === "object" ? payload as Record<string, unknown> : {}
  const username = typeof body.username === "string" ? body.username.slice(0, 256) : ""
  const password = typeof body.password === "string" ? body.password.slice(0, 1_024) : ""
  if (!verifyDashboardCredentials(username, password, config.username, config.password)) {
    globalAttempts.failures += 1
    const current = attempts.get(key)
    attempts.set(key, {
      failures: (current?.resetAt ?? 0) > now ? current!.failures + 1 : 1,
      resetAt: (current?.resetAt ?? 0) > now ? current!.resetAt : now + LOGIN_WINDOW_MS,
    })
    return NextResponse.json({ detail: "invalid username or password" }, { status: 401 })
  }

  attempts.delete(key)
  globalAttempts = { failures: 0, resetAt: now + LOGIN_WINDOW_MS }
  const response = NextResponse.json({ ok: true, authenticated: true })
  response.cookies.set({
    name: DASHBOARD_SESSION_COOKIE_NAME,
    value: createDashboardSession(config.username, config.sessionSecret),
    httpOnly: true,
    sameSite: "strict",
    secure: secureCookie(request),
    path: "/",
    maxAge: DASHBOARD_SESSION_TTL_SECONDS,
  })
  return response
}

export async function DELETE(request: NextRequest): Promise<NextResponse> {
  if (!sameOrigin(request)) {
    return NextResponse.json({ detail: "cross-origin logout refused" }, { status: 403 })
  }
  const response = NextResponse.json({ ok: true, authenticated: false })
  response.cookies.delete(DASHBOARD_SESSION_COOKIE_NAME)
  return response
}
