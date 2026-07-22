import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto"

export const DASHBOARD_SESSION_COOKIE_NAME = "cp_dashboard_session"
export const DASHBOARD_SESSION_TTL_SECONDS = 12 * 60 * 60
export const WEBSOCKET_TICKET_TTL_SECONDS = 60

type Environment = Record<string, string | undefined>

export type DashboardAuthConfig = {
  username: string
  password: string
  sessionSecret: string
  apiToken: string
  configured: boolean
}

const digest = (value: string): Buffer => createHash("sha256").update(value, "utf8").digest()

const safeEqual = (left: string, right: string): boolean => timingSafeEqual(digest(left), digest(right))

const sign = (value: string, secret: string): string =>
  createHmac("sha256", secret).update(value, "utf8").digest("base64url")

export const readDashboardAuthConfig = (environment: Environment = process.env): DashboardAuthConfig => {
  const username = (environment.CLOWNPEANUTS_DASHBOARD_USERNAME ?? "").trim()
  const password = environment.CLOWNPEANUTS_DASHBOARD_PASSWORD ?? ""
  const sessionSecret = environment.CLOWNPEANUTS_DASHBOARD_SESSION_SECRET ?? ""
  const apiToken = (environment.CLOWNPEANUTS_API_TOKEN ?? "").trim()
  return {
    username,
    password,
    sessionSecret,
    apiToken,
    configured:
      username.length > 0 &&
      password.length >= 12 &&
      sessionSecret.length >= 32 &&
      apiToken.length >= 16,
  }
}

export const verifyDashboardCredentials = (
  suppliedUsername: string,
  suppliedPassword: string,
  configuredUsername: string,
  configuredPassword: string,
): boolean => {
  if (!configuredUsername || !configuredPassword) return false
  const usernameMatches = safeEqual(suppliedUsername, configuredUsername)
  const passwordMatches = safeEqual(suppliedPassword, configuredPassword)
  return usernameMatches && passwordMatches
}

export const createDashboardSession = (
  username: string,
  secret: string,
  nowMs: number = Date.now(),
): string => {
  const expiresAt = Math.floor(nowMs / 1_000) + DASHBOARD_SESSION_TTL_SECONDS
  const encodedUsername = Buffer.from(username, "utf8").toString("base64url")
  const unsigned = `cps1.${expiresAt}.${encodedUsername}`
  return `${unsigned}.${sign(unsigned, secret)}`
}

export const verifyDashboardSession = (
  session: string | undefined,
  expectedUsername: string,
  secret: string,
  nowMs: number = Date.now(),
): boolean => {
  if (!session || !expectedUsername || secret.length < 32) return false
  const parts = session.split(".")
  if (parts.length !== 4 || parts[0] !== "cps1") return false
  const expiresAt = Number(parts[1])
  const nowSeconds = Math.floor(nowMs / 1_000)
  if (!Number.isSafeInteger(expiresAt) || expiresAt < nowSeconds || expiresAt > nowSeconds + DASHBOARD_SESSION_TTL_SECONDS) {
    return false
  }
  let username: string
  try {
    username = Buffer.from(parts[2], "base64url").toString("utf8")
  } catch {
    return false
  }
  const unsigned = parts.slice(0, 3).join(".")
  return safeEqual(username, expectedUsername) && safeEqual(parts[3], sign(unsigned, secret))
}

export const createWebSocketTicket = (
  secret: string,
  nowMs: number = Date.now(),
  nonce: string = randomBytes(18).toString("base64url"),
): string => {
  const expiresAt = Math.floor(nowMs / 1_000) + WEBSOCKET_TICKET_TTL_SECONDS
  const unsigned = `cpws1.${expiresAt}.${nonce}`
  return `${unsigned}.${sign(unsigned, secret)}`
}
