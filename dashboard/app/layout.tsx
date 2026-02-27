import "./globals.css"
import type { Metadata } from "next"
import Link from "next/link"

export const metadata: Metadata = {
  title: "ClownPeanuts Ops",
  description: "Live deception operations dashboard",
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="cp-shell">
          <aside className="cp-rail" aria-label="Primary navigation">
            <Link href="/" className="cp-rail-brand" aria-label="ClownPeanuts home">
              CP
            </Link>
            <nav className="cp-rail-nav">
              <Link href="/" className="cp-rail-link">
                Ops
              </Link>
              <Link href="/theater" className="cp-rail-link">
                Theater
              </Link>
              <a href="https://github.com/rocketweb/clownpeanuts" target="_blank" rel="noreferrer" className="cp-rail-link">
                Repo
              </a>
            </nav>
          </aside>
          <div className="cp-main">
            <header className="cp-topbar">
              <strong className="cp-topbar-title">ClownPeanuts Control Plane</strong>
              <nav className="cp-topbar-links" aria-label="Dashboard sections">
                <Link href="/" className="cp-topbar-link">
                  Operations
                </Link>
                <Link href="/theater" className="cp-topbar-link">
                  Theater
                </Link>
                <span className="cp-topbar-link cp-topbar-link-muted">Intel</span>
                <span className="cp-topbar-link cp-topbar-link-muted">Retention</span>
              </nav>
            </header>
            <div className="cp-content">{children}</div>
          </div>
        </div>
      </body>
    </html>
  )
}
