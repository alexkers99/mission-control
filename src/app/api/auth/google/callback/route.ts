import { NextRequest, NextResponse } from 'next/server'
import { createSession } from '@/lib/auth'
import { getDatabase, logAuditEvent } from '@/lib/db'
import { verifyGoogleIdToken } from '@/lib/google-auth'
import { loginLimiter } from '@/lib/rate-limit'
import { getMcSessionCookieName, getMcSessionCookieOptions, isRequestSecure } from '@/lib/session-cookie'

/**
 * GET /api/auth/google/callback
 *
 * Handles the OAuth 2.0 authorization code callback from Google.
 * Exchanges the authorization code for tokens, verifies the ID token,
 * creates a local session, and redirects to the dashboard.
 */
export async function GET(request: NextRequest) {
  const rateCheck = loginLimiter(request)
  if (rateCheck) return rateCheck

  // Derive the public-facing origin from proxy headers — request.url reflects the
  // container's internal bind address (e.g. http://0.0.0.0:3000) behind Traefik,
  // which would otherwise send users to an unreachable address on every redirect.
  // Declared outside the try block so the catch handler can use it too.
  const protocol = request.headers.get('x-forwarded-proto') || 'https'
  const host = request.headers.get('x-forwarded-host') || request.headers.get('host') || 'localhost:3000'
  const origin = `${protocol}://${host}`
  const redirectUri = `${origin}/api/auth/google/callback`

  try {
    const { searchParams } = new URL(request.url)
    const code = searchParams.get('code')
    const error = searchParams.get('error')
    const returnedState = searchParams.get('state')

    // Handle OAuth error (user denied, etc.)
    if (error) {
      console.warn(`Google OAuth error: ${error}`)
      return NextResponse.redirect(new URL('/login?error=google_denied', origin))
    }

    if (!code) {
      return NextResponse.redirect(new URL('/login?error=google_no_code', origin))
    }

    // CSRF protection: verify state token
    const storedState = request.cookies.get('google_oauth_state')?.value
    if (!returnedState || !storedState || returnedState !== storedState) {
      console.warn('Google OAuth state mismatch — possible CSRF')
      return NextResponse.redirect(new URL('/login?error=google_csrf', origin))
    }

    const clientId = process.env.GOOGLE_CLIENT_ID || process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID || ''
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET || ''

    if (!clientId || !clientSecret) {
      return NextResponse.redirect(new URL('/login?error=google_config', origin))
    }

    // Exchange authorization code for tokens
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
      }),
    })

    if (!tokenResponse.ok) {
      const errorBody = await tokenResponse.text().catch(() => 'unknown')
      console.error(`Google token exchange failed (${tokenResponse.status}): ${errorBody}`)
      return NextResponse.redirect(new URL('/login?error=google_token', origin))
    }

    const tokenData = await tokenResponse.json()
    const idToken: string = tokenData.id_token

    if (!idToken) {
      return NextResponse.redirect(new URL('/login?error=google_token', origin))
    }

    // Verify the ID token via the same helper the POST credential flow uses —
    // validates signature (through Google's tokeninfo endpoint), audience,
    // and that the email is verified.
    let payload
    try {
      payload = await verifyGoogleIdToken(idToken)
    } catch (err) {
      console.error('Google ID token verification failed:', err)
      return NextResponse.redirect(new URL('/login?error=google_token', origin))
    }

    const email = String(payload.email || '').toLowerCase().trim()
    const sub = String(payload.sub || '').trim()
    const displayName = String(payload.name || email.split('@')[0] || 'Google User').trim()
    const avatar = payload.picture ? String(payload.picture) : null

    const db = getDatabase()

    // Match by Google provider_user_id first, then by email — same logic as POST handler
    const row = db.prepare(`
      SELECT u.id, u.username, u.display_name, u.role, u.provider, u.email, u.avatar_url, u.is_approved,
             u.created_at, u.updated_at, u.last_login_at, u.workspace_id, COALESCE(w.tenant_id, 1) as tenant_id
      FROM users u
      LEFT JOIN workspaces w ON w.id = u.workspace_id
      WHERE provider = 'google' AND (provider_user_id = ? OR lower(email) = ?)
      ORDER BY u.id ASC
      LIMIT 1
    `).get(sub, email) as any

    const ipAddress = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'
    const userAgent = request.headers.get('user-agent') || undefined

    if (!row || Number(row.is_approved ?? 1) !== 1) {
      upsertAccessRequest({
        email,
        providerUserId: sub,
        displayName,
        avatarUrl: avatar || undefined,
      })

      logAuditEvent({
        action: 'google_login_pending_approval',
        actor: email,
        detail: { email, sub },
        ip_address: ipAddress,
        user_agent: userAgent,
      })

      return NextResponse.redirect(new URL('/login?error=google_pending', origin))
    }

    db.prepare(`
      UPDATE users
      SET provider = 'google', provider_user_id = ?, email = ?, avatar_url = COALESCE(?, avatar_url), updated_at = (unixepoch())
      WHERE id = ?
    `).run(sub, email, avatar, row.id)

    const { token, expiresAt } = createSession(row.id, ipAddress, userAgent, row.workspace_id ?? 1)

    logAuditEvent({ action: 'login_google', actor: row.username, actor_id: row.id, ip_address: ipAddress, user_agent: userAgent })

    const isSecureRequest = isRequestSecure(request)
    const cookieName = getMcSessionCookieName(isSecureRequest)

    const response = NextResponse.redirect(new URL('/', origin))
    response.cookies.set(cookieName, token, {
      ...getMcSessionCookieOptions({ maxAgeSeconds: expiresAt - Math.floor(Date.now() / 1000), isSecureRequest }),
    })

    // Clear the CSRF state cookie
    response.cookies.set('google_oauth_state', '', {
      httpOnly: true,
      secure: isSecureRequest,
      sameSite: 'lax',
      maxAge: 0,
      path: '/api/auth/google',
    })

    return response
  } catch (error: any) {
    console.error('Google callback error:', error)
    return NextResponse.redirect(new URL('/login?error=google_error', origin))
  }
}

/**
 * Upsert an access request for a new Google user awaiting admin approval.
 */
function upsertAccessRequest(input: {
  email: string
  providerUserId: string
  displayName: string
  avatarUrl?: string
}) {
  const db = getDatabase()
  db.prepare(`
    INSERT INTO access_requests (provider, email, provider_user_id, display_name, avatar_url, status, attempt_count, requested_at, last_attempt_at)
    VALUES ('google', ?, ?, ?, ?, 'pending', 1, (unixepoch()), (unixepoch()))
    ON CONFLICT(email, provider) DO UPDATE SET
      provider_user_id = excluded.provider_user_id,
      display_name = excluded.display_name,
      avatar_url = excluded.avatar_url,
      status = 'pending',
      attempt_count = access_requests.attempt_count + 1,
      last_attempt_at = (unixepoch())
  `).run(input.email.toLowerCase(), input.providerUserId, input.displayName, input.avatarUrl || null)
}