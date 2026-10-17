import { generateKeyPairSync, sign, verify } from 'node:crypto'
import type { SignChallengeRequest } from '@castalia-wallet/provider-types'

export type DevWalletKeyPair = {
  kind: 'disposable-dev'
  publicKey: string
  privateKeyPem: string
  privateKeyExtractable: false
}

export type WalletSigningState = {
  setupComplete: boolean
  unlocked: boolean
}

export function createDevWalletKeyPair(): DevWalletKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })

  return {
    kind: 'disposable-dev',
    publicKey,
    privateKeyPem: privateKey,
    privateKeyExtractable: false,
  }
}

export function assertCanSign(state: WalletSigningState): void {
  if (!state.setupComplete) {
    throw new Error('wallet setup is required before signing')
  }

  if (!state.unlocked) {
    throw new Error('wallet is locked')
  }
}

export function signChallengeWithDevKey(
  keyPair: DevWalletKeyPair,
  challenge: SignChallengeRequest,
): string {
  const message = canonicalChallengeBytes(challenge)
  return sign(null, message, keyPair.privateKeyPem).toString('base64')
}

export function verifyChallengeSignature(input: {
  publicKey: string
  challenge: SignChallengeRequest
  signature: string
}): boolean {
  try {
    return verify(
      null,
      canonicalChallengeBytes(input.challenge),
      input.publicKey,
      Buffer.from(input.signature, 'base64'),
    )
  } catch {
    return false
  }
}

export function canonicalChallengeBytes(challenge: SignChallengeRequest): Buffer {
  return Buffer.from(JSON.stringify({
    audience: challenge.audience,
    domain: challenge.domain,
    expiresAt: challenge.expiresAt,
    issuedAt: challenge.issuedAt,
    nonce: challenge.nonce,
    operation: challenge.operation,
    origin: challenge.origin,
    version: challenge.version,
  }), 'utf8')
}
