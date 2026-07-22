"use client"

import { FormEvent, useEffect, useState } from "react"
import { useRouter } from "next/navigation"

export default function LoginPage() {
  const router = useRouter()
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [message, setMessage] = useState("")
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    fetch("/api/auth/session", { cache: "no-store", credentials: "include" })
      .then((response) => response.json())
      .then((payload: { authenticated?: boolean }) => {
        if (payload.authenticated) router.replace("/")
      })
      .catch(() => undefined)
  }, [router])

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setBusy(true)
    setMessage("")
    try {
      const response = await fetch("/api/auth/session", {
        method: "POST",
        credentials: "include",
        cache: "no-store",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username, password }),
      })
      const payload = await response.json().catch(() => ({})) as { detail?: string }
      if (!response.ok) {
        setMessage(payload.detail ?? "Login failed")
        return
      }
      router.replace("/")
      router.refresh()
    } catch {
      setMessage("The control plane could not be reached.")
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="cp-login" aria-labelledby="login-title">
      <section className="cp-login-panel">
        <p className="cp-kicker">Restricted operator surface</p>
        <h1 id="login-title">Enter the control plane.</h1>
        <p className="cp-login-copy">Use the dashboard credentials configured by your deployment operator.</p>
        <form onSubmit={submit} className="cp-login-form">
          <label htmlFor="username">Username</label>
          <input
            id="username"
            name="username"
            autoComplete="username"
            required
            maxLength={256}
            value={username}
            onChange={(event) => setUsername(event.target.value)}
          />
          <label htmlFor="password">Password</label>
          <input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            maxLength={1024}
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
          {message ? <p className="cp-login-error" role="alert">{message}</p> : null}
          <button type="submit" disabled={busy}>{busy ? "Verifying…" : "Authenticate"}</button>
        </form>
      </section>
      <aside className="cp-login-mark" aria-hidden="true">CP</aside>
    </main>
  )
}
