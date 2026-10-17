import type { SignChallengeRequest } from '@castalia-wallet/provider-types'

export type ChallengePayloadInput = Omit<SignChallengeRequest, 'domain' | 'version'>

export type ChallengeValidationOptions = {
  now?: string | Date
  expectedOrigin?: string
  expectedAudience?: string
}

export function buildChallengePayload(input: ChallengePayloadInput): SignChallengeRequest {
  return {
    domain: 'castalia-wallet',
    version: 1,
    nonce: input.nonce,
    origin: input.origin,
    audience: input.audience,
    operation: input.operation,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
  }
}

export function validateChallengePayload(
  payload: SignChallengeRequest,
  options: ChallengeValidationOptions = {},
): void {
  if (payload.domain !== 'castalia-wallet') {
    throw new Error('challenge domain must be castalia-wallet')
  }

  if (payload.version !== 1) {
    throw new Error('challenge version must be 1')
  }

  if (!payload.nonce || payload.nonce.trim().length === 0) {
    throw new Error('challenge nonce is required')
  }

  if (!payload.origin || payload.origin.trim().length === 0) {
    throw new Error('challenge origin is required')
  }

  if (!payload.audience || payload.audience.trim().length === 0) {
    throw new Error('challenge audience is required')
  }

  if (!payload.operation || payload.operation.trim().length === 0) {
    throw new Error('challenge operation is required')
  }

  const issuedAt = Date.parse(payload.issuedAt)
  const expiresAt = Date.parse(payload.expiresAt)
  const now = options.now instanceof Date
    ? options.now.getTime()
    : Date.parse(options.now ?? new Date().toISOString())

  if (Number.isNaN(issuedAt)) {
    throw new Error('challenge issuedAt must be a valid timestamp')
  }

  if (Number.isNaN(expiresAt)) {
    throw new Error('challenge expiresAt must be a valid timestamp')
  }

  if (expiresAt <= issuedAt) {
    throw new Error('challenge expiresAt must be after issuedAt')
  }

  if (now > expiresAt) {
    throw new Error('challenge expired')
  }

  if (options.expectedOrigin && payload.origin !== options.expectedOrigin) {
    throw new Error('challenge origin mismatch')
  }

  if (options.expectedAudience && payload.audience !== options.expectedAudience) {
    throw new Error('challenge audience mismatch')
  }
}
