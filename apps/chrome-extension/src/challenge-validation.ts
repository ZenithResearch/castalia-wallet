import type { SignChallengeRequest } from '@castalia-wallet/provider-types'

export interface ChallengeValidationOptions {
  now?: Date | string
  expectedOrigin?: string
  expectedAudience?: string
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

  if (isNaN(issuedAt)) {
    throw new Error('challenge issuedAt is not a valid date')
  }

  if (isNaN(expiresAt)) {
    throw new Error('challenge expiresAt is not a valid date')
  }

  if (expiresAt <= issuedAt) {
    throw new Error('challenge expiresAt must be after issuedAt')
  }

  if (now > expiresAt) {
    throw new Error('challenge has expired')
  }

  if (options.expectedOrigin && payload.origin !== options.expectedOrigin) {
    throw new Error('challenge origin mismatch')
  }

  if (options.expectedAudience && payload.audience !== options.expectedAudience) {
    throw new Error('challenge audience mismatch')
  }
}
