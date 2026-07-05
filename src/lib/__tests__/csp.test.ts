import { describe, expect, it, vi } from 'vitest'
import { buildMissionControlCsp, buildNonceRequestHeaders } from '@/lib/csp'

describe('buildMissionControlCsp', () => {
  it('includes unsafe-eval only outside production', () => {
    vi.stubEnv('NODE_ENV', 'development')
    expect(buildMissionControlCsp({ nonce: 'nonce-123', googleEnabled: false }))
      .toContain(`script-src 'self' 'unsafe-eval' 'nonce-nonce-123' 'strict-dynamic'`)

    vi.stubEnv('NODE_ENV', 'production')
    expect(buildMissionControlCsp({ nonce: 'nonce-123', googleEnabled: false }))
      .toContain(`script-src 'self' 'nonce-nonce-123' 'strict-dynamic'`)

    vi.unstubAllEnvs()

    expect(buildMissionControlCsp({ nonce: 'nonce-123', googleEnabled: false }))
      .toContain("style-src 'self' 'unsafe-inline'")
    expect(buildMissionControlCsp({ nonce: 'nonce-123', googleEnabled: false }))
      .toContain("style-src-elem 'self' 'unsafe-inline'")
    expect(buildMissionControlCsp({ nonce: 'nonce-123', googleEnabled: false }))
      .toContain("style-src-attr 'unsafe-inline'")
  })
})

describe('buildNonceRequestHeaders', () => {
  it('propagates nonce and CSP into request headers for Next.js rendering', () => {
    const headers = buildNonceRequestHeaders({
      headers: new Headers({ host: 'localhost:3000' }),
      nonce: 'nonce-123',
      googleEnabled: false,
    })

    expect(headers.get('x-nonce')).toBe('nonce-123')
    expect(headers.get('Content-Security-Policy')).toContain("style-src 'self' 'unsafe-inline'")
  })
})
