import { NextResponse } from "next/server"

const API_TOKEN_COOKIE_NAME = "cp_api_token"

const _resolveDashboardApiToken = (): string => {
  const token = (process.env.CLOWNPEANUTS_API_TOKEN ?? "").trim()
  return token
}

// Mint the operator-token cookie. Only invoked on POST so a plain navigation
// (GET, <img>, link) cannot cause the operator token to be deposited in an
// arbitrary visitor's browser on the dashboard origin.
const _mintSessionResponse = (): NextResponse => {
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

// GET is a safe status probe only: it never sets the token cookie.
export async function GET(): Promise<NextResponse> {
  const token = _resolveDashboardApiToken()
  return NextResponse.json({ ok: true, configured: token.length > 0 })
}

export async function POST(): Promise<NextResponse> {
  return _mintSessionResponse()
}
