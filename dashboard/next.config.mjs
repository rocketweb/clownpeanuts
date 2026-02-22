/** @type {import('next').NextConfig} */
const commonSecurityHeaders = [
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
]

const productionOnlyHeaders = [
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=31536000; includeSubDomains; preload',
  },
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self' data:",
      "connect-src 'self' https: wss: http://127.0.0.1:8099 http://localhost:8099 ws://127.0.0.1:8099 ws://localhost:8099",
      "object-src 'none'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
      "form-action 'self'",
    ].join('; '),
  },
]

const nextConfig = {
  reactStrictMode: true,
  async headers() {
    const headers =
      process.env.NODE_ENV === 'production'
        ? [...commonSecurityHeaders, ...productionOnlyHeaders]
        : commonSecurityHeaders

    return [
      {
        source: '/:path*',
        headers,
      },
    ]
  },
}

export default nextConfig
