"use client"

export function LogoutButton() {
  const logout = async () => {
    await fetch("/api/auth/session", {
      method: "DELETE",
      credentials: "include",
      cache: "no-store",
    }).catch(() => undefined)
    window.location.assign("/login")
  }

  return (
    <button type="button" className="cp-topbar-link cp-logout" onClick={logout}>
      Log out
    </button>
  )
}
