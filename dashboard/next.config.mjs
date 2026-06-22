/** @type {import('next').NextConfig} */
const commonSecurityHeaders = [
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
]

// The operator console renders attacker-derived intel, so a Content-Security-Policy
// is a key second line of defense against an accidental unescaped-render regression.
// It must ship in EVERY environment, not just production. The dev variant relaxes
// script-src so Next.js HMR (which uses eval) still works; it is never empty.
function contentSecurityPolicy({ dev }) {
  const scriptSrc = dev ? "script-src 'self' 'unsafe-eval' 'unsafe-inline'" : "script-src 'self'"
  return [
    "default-src 'self'",
    scriptSrc,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self' https: wss: http://127.0.0.1:8099 http://localhost:8099 ws://127.0.0.1:8099 ws://localhost:8099",
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ].join('; ')
}

// HSTS requires HTTPS and is meaningless (or harmful) over the plain-HTTP dev server,
// so it stays production-only.
const hstsHeader = {
  key: 'Strict-Transport-Security',
  value: 'max-age=31536000; includeSubDomains; preload',
}

const nextConfig = {
  reactStrictMode: true,
  async headers() {
    const isProduction = process.env.NODE_ENV === 'production'
    const headers = [
      ...commonSecurityHeaders,
      { key: 'Content-Security-Policy', value: contentSecurityPolicy({ dev: !isProduction }) },
    ]
    if (isProduction) {
      headers.push(hstsHeader)
    }

    return [
      {
        source: '/:path*',
        headers,
      },
    ]
  },
}

export default nextConfig
