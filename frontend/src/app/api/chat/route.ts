import { NextRequest, NextResponse } from 'next/server'

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5500'
const BACKEND_API_KEY = process.env.BACKEND_API_KEY

const MAX_MESSAGE_LENGTH = 10000
const MAX_CONVERSATION_ID_LENGTH = 256

function validateAndSanitizeBody(body: unknown): { message: string; conversation_id?: string } | null {
  if (typeof body !== 'object' || body === null) {
    return null
  }

  const raw = body as Record<string, unknown>

  if (typeof raw.message !== 'string' || raw.message.trim().length === 0) {
    return null
  }

  if (raw.message.length > MAX_MESSAGE_LENGTH) {
    return null
  }

  const sanitized: { message: string; conversation_id?: string } = {
    message: raw.message.trim(),
  }

  if (raw.conversation_id !== undefined) {
    if (typeof raw.conversation_id !== 'string') {
      return null
    }
    if (raw.conversation_id.length > MAX_CONVERSATION_ID_LENGTH) {
      return null
    }
    sanitized.conversation_id = raw.conversation_id
  }

  return sanitized
}

export async function POST(request: NextRequest) {
  if (!BACKEND_API_KEY) {
    console.error('BACKEND_API_KEY is not configured')
    return NextResponse.json(
      {
        detail: 'Backend service is not properly configured',
        policy_error: {
          type: 'general',
          message: 'Backend service unavailable',
        },
      },
      { status: 503 }
    )
  }

  try {
    const body = await request.json()

    const sanitizedBody = validateAndSanitizeBody(body)

    if (!sanitizedBody) {
      return NextResponse.json(
        {
          detail: 'Invalid request body',
          policy_error: {
            type: 'validation',
            message: 'Request contains invalid or unexpected fields',
          },
        },
        { status: 400 }
      )
    }

    const response = await fetch(`${BACKEND_URL}/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': BACKEND_API_KEY,
      },
      body: JSON.stringify(sanitizedBody),
    })

    const data = await response.json()

    if (!response.ok) {
      return NextResponse.json(data, { status: response.status })
    }

    return NextResponse.json(data)
  } catch (error) {
    console.error('Backend proxy error:', error)
    return NextResponse.json(
      {
        detail: 'Failed to connect to backend service',
        policy_error: {
          type: 'general',
          message: 'Backend service unavailable',
        },
      },
      { status: 503 }
    )
  }
}