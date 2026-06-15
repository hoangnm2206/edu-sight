import { NextRequest, NextResponse } from 'next/server'
import { AccessToken } from 'livekit-server-sdk'
import { logger } from '../../../../lib/logger'

// Local-auth model: we trust the client to provide its own display name.
// This is acceptable because the localStorage user database is also on the
// client — there is no cross-user identity to spoof. Rate limit + format
// validation prevent abuse and JWT-corrupting input.

const MAX_NAME_LENGTH = 64
const MAX_ROOM_LENGTH = 64
const NAME_DISALLOWED = /[\x00-\x1F\x7F<>"\\]/
const SAFE_ROOM = /^[A-Za-z0-9_-]+$/

const RATE_WINDOW_MS = 30_000
const RATE_LIMIT = 30
const recentRequests = new Map<string, number[]>()

function getClientIp(req: NextRequest): string {
  const fwd = req.headers.get('x-forwarded-for')
  if (fwd) return fwd.split(',')[0].trim()
  return req.headers.get('x-real-ip') || 'unknown'
}

function rateLimited(ip: string): boolean {
  const now = Date.now()
  const cutoff = now - RATE_WINDOW_MS
  const hits = (recentRequests.get(ip) || []).filter((t) => t > cutoff)
  hits.push(now)
  recentRequests.set(ip, hits)
  return hits.length > RATE_LIMIT
}

export async function POST(req: NextRequest) {
  try {
    const ip = getClientIp(req)
    if (rateLimited(ip)) {
      return NextResponse.json({ error: 'Too many requests' }, { status: 429 })
    }

    const body = await req.json().catch(() => null)
    if (!body || typeof body !== 'object') {
      return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 })
    }

    const { roomName, participantName } = body as {
      roomName?: unknown
      participantName?: unknown
    }
    if (typeof roomName !== 'string' || typeof participantName !== 'string') {
      return NextResponse.json(
        { error: 'roomName and participantName must be strings' },
        { status: 400 }
      )
    }

    const trimmedRoom = roomName.trim()
    const trimmedName = participantName.trim()

    if (
      trimmedRoom.length === 0 ||
      trimmedRoom.length > MAX_ROOM_LENGTH ||
      !SAFE_ROOM.test(trimmedRoom)
    ) {
      return NextResponse.json({ error: 'Invalid roomName format' }, { status: 400 })
    }
    if (
      trimmedName.length === 0 ||
      trimmedName.length > MAX_NAME_LENGTH ||
      NAME_DISALLOWED.test(trimmedName)
    ) {
      return NextResponse.json({ error: 'Invalid participantName format' }, { status: 400 })
    }

    const apiKey = process.env.LIVEKIT_API_KEY?.trim()
    const apiSecret = process.env.LIVEKIT_API_SECRET?.trim()
    if (!apiKey || !apiSecret) {
      logger.error('Missing LIVEKIT_API_KEY or LIVEKIT_API_SECRET')
      return NextResponse.json({ error: 'Server configuration error' }, { status: 500 })
    }

    const at = new AccessToken(apiKey, apiSecret, {
      identity: trimmedName,
      name: trimmedName,
      ttl: '4h',
    })
    at.addGrant({
      room: trimmedRoom,
      roomJoin: true,
      canPublish: true,
      canSubscribe: true,
      canPublishData: true,
    })

    const token = await at.toJwt()
    logger.info(`[TOKEN] "${trimmedName}" → "${trimmedRoom}"`)

    return NextResponse.json({ token })
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Internal server error'
    logger.error('[TOKEN ERROR]', error)
    return NextResponse.json({ error: message }, { status: 500 })
  }
}
