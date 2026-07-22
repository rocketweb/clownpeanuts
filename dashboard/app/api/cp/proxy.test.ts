import { afterEach, describe, expect, it, vi } from "vitest"
import { NextRequest } from "next/server"

import { POST } from "./[...path]/route"
import {
  createDashboardSession,
  DASHBOARD_SESSION_COOKIE_NAME,
} from "../../lib/server-auth"

const USERNAME = "operator"
const PASSWORD = "correct-horse-battery-staple"
const SECRET = "dashboard-session-secret-0123456789abcdef"
const API_TOKEN = "operator-token-0123456789abcdef"

const configureDashboard = (): void => {
  vi.stubEnv("CLOWNPEANUTS_DASHBOARD_USERNAME", USERNAME)
  vi.stubEnv("CLOWNPEANUTS_DASHBOARD_PASSWORD", PASSWORD)
  vi.stubEnv("CLOWNPEANUTS_DASHBOARD_SESSION_SECRET", SECRET)
  vi.stubEnv("CLOWNPEANUTS_API_TOKEN", API_TOKEN)
  vi.stubEnv("CLOWNPEANUTS_API_INTERNAL_URL", "http://127.0.0.1:8099")
}

const mutationRequest = (origin?: string): NextRequest => {
  const session = createDashboardSession(USERNAME, SECRET)
  const headers = new Headers({
    cookie: `${DASHBOARD_SESSION_COOKIE_NAME}=${session}`,
    "content-type": "application/x-www-form-urlencoded",
    host: "127.0.0.1:3000",
  })
  if (origin) headers.set("origin", origin)
  return new NextRequest("http://127.0.0.1:3000/api/cp/intel/rotate", {
    method: "POST",
    headers,
    body: "",
  })
}

const context = { params: Promise.resolve({ path: ["intel", "rotate"] }) }

afterEach(() => {
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
})

describe("dashboard API mutation proxy", () => {
  it("rejects a mutation submitted from another localhost origin", async () => {
    configureDashboard()
    const upstream = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }))
    vi.stubGlobal("fetch", upstream)

    const response = await POST(mutationRequest("http://127.0.0.1:3999"), context)

    expect(response.status).toBe(403)
    expect(upstream).not.toHaveBeenCalled()
  })

  it("rejects a mutation when the browser origin is missing", async () => {
    configureDashboard()
    const upstream = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }))
    vi.stubGlobal("fetch", upstream)

    const response = await POST(mutationRequest(), context)

    expect(response.status).toBe(403)
    expect(upstream).not.toHaveBeenCalled()
  })

  it("streams a same-origin mutation to the authenticated upstream", async () => {
    configureDashboard()
    const upstream = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }))
    vi.stubGlobal("fetch", upstream)
    const request = mutationRequest("http://127.0.0.1:3000")
    const bufferedBody = vi.spyOn(request, "arrayBuffer")

    const response = await POST(request, context)

    expect(response.status).toBe(200)
    expect(bufferedBody).not.toHaveBeenCalled()
    expect(upstream).toHaveBeenCalledOnce()
    expect(upstream.mock.calls[0][1]).toMatchObject({
      method: "POST",
      body: request.body,
      duplex: "half",
    })
    const headers = upstream.mock.calls[0][1]?.headers as Headers
    expect(headers.get("authorization")).toBe(`Bearer ${API_TOKEN}`)
  })
})
