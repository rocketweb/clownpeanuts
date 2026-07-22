import { createHmac } from "node:crypto"
import { describe, expect, it } from "vitest"

import {
  createDashboardSession,
  createWebSocketTicket,
  verifyDashboardCredentials,
  verifyDashboardSession,
} from "./server-auth"

const USERNAME = "operator"
const PASSWORD = "correct-horse-battery-staple"
const SECRET = "dashboard-session-secret-0123456789abcdef"
const NOW_MS = 1_750_000_000_000

describe("dashboard credentials", () => {
  it("requires both the configured username and password", () => {
    expect(verifyDashboardCredentials(USERNAME, PASSWORD, USERNAME, PASSWORD)).toBe(true)
    expect(verifyDashboardCredentials(USERNAME, "wrong", USERNAME, PASSWORD)).toBe(false)
    expect(verifyDashboardCredentials("wrong", PASSWORD, USERNAME, PASSWORD)).toBe(false)
    expect(verifyDashboardCredentials("", "", "", "")).toBe(false)
  })
})

describe("dashboard sessions", () => {
  it("accepts a signed, unexpired session and rejects tampering or expiry", () => {
    const session = createDashboardSession(USERNAME, SECRET, NOW_MS)

    expect(verifyDashboardSession(session, USERNAME, SECRET, NOW_MS + 1_000)).toBe(true)
    expect(verifyDashboardSession(`${session}tampered`, USERNAME, SECRET, NOW_MS + 1_000)).toBe(false)
    expect(verifyDashboardSession(session, USERNAME, SECRET, NOW_MS + 12 * 60 * 60 * 1_000 + 1_000)).toBe(false)
  })
})

describe("websocket tickets", () => {
  it("creates the ticket format accepted by the Python API", () => {
    const ticket = createWebSocketTicket(SECRET, NOW_MS, "fixed-nonce")
    const [version, expiresAt, nonce, signature] = ticket.split(".")
    const unsigned = `${version}.${expiresAt}.${nonce}`
    const expected = createHmac("sha256", SECRET).update(unsigned).digest("base64url")

    expect(version).toBe("cpws1")
    expect(Number(expiresAt)).toBe(Math.floor(NOW_MS / 1_000) + 60)
    expect(nonce).toBe("fixed-nonce")
    expect(signature).toBe(expected)
  })
})
