import { NextResponse } from "next/server"

const API_TOKEN_COOKIE_NAME = "cp_api_token"

const _resolveDashboardApiToken = (): string => {
  const token = (process.env.CLOWNPEANUTS_API_TOKEN ?? "").trim()
  return token
}

const _sessionResponse = (): NextResponse => {
  const token = _resolveDashboardApiToken()
  const response = NextResponse.json({ ok: true, configured: token.length > 0 })
  if (!token) {
    response.cookies.delete(API_TOKEN_COOKIE_NAME)
    return response
  }
  response.cookies.set({
    name: API_TOKEN_COOKIE_NAME,
    value: token,
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 60 * 60 * 12,
  })
  return response
}

export async function GET(): Promise<NextResponse> {
  return _sessionResponse()
}

export async function POST(): Promise<NextResponse> {
  return _sessionResponse()
}
