export type ProviderRequestValidationInput = {
  method: string
  payload: unknown
  computedOrigin: string
  pageSuppliedOrigin?: string
  walletSetupComplete: boolean
  walletUnlocked: boolean
  approvedOrigins: ReadonlySet<string>
}

export type ProviderRequestValidationResult =
  | { ok: true; origin: string; method: string }
  | { ok: false; origin: string; method: string; error: string }

const AVAILABILITY_METHODS = new Set([
  'castalia.wallet.isAvailable',
])

const SENSITIVE_METHODS = new Set([
  'castalia.wallet.requestRegistration',
  'castalia.wallet.getSubject',
  'castalia.wallet.getMembership',
  'castalia.wallet.signChallenge',
  'castalia.wallet.requestMembershipPresentation',
  'castalia.wallet.listCapabilities',
  'castalia.wallet.federationStatus',
  'castalia.wallet.storageQuota',
])

const UNSUPPORTED_FUTURE_METHODS = new Set([
  'castalia.wallet.requestAuth',
  'castalia.wallet.requestCapability',
  'castalia.wallet.privateRpc',
  'castalia.wallet.privateRead',
  'castalia.wallet.proveCapability',
])

export function validateProviderRequest(
  input: ProviderRequestValidationInput,
): ProviderRequestValidationResult {
  const origin = input.computedOrigin

  if (!origin || origin.trim().length === 0) {
    return reject(input, origin, 'computed origin is required')
  }

  if (AVAILABILITY_METHODS.has(input.method)) {
    return { ok: true, origin, method: input.method }
  }

  if (UNSUPPORTED_FUTURE_METHODS.has(input.method)) {
    return reject(input, origin, `unsupported Checkpoint A method: ${input.method}`)
  }

  if (!SENSITIVE_METHODS.has(input.method)) {
    return reject(input, origin, `unknown method: ${input.method}`)
  }

  if (!input.approvedOrigins.has(origin)) {
    return reject(input, origin, `origin not approved: ${origin}`)
  }

  if (!input.walletSetupComplete) {
    return reject(input, origin, 'wallet setup is required before sensitive operations')
  }

  if (!input.walletUnlocked) {
    return reject(input, origin, 'wallet is locked')
  }

  return { ok: true, origin, method: input.method }
}

function reject(
  input: ProviderRequestValidationInput,
  origin: string,
  error: string,
): ProviderRequestValidationResult {
  return { ok: false, origin, method: input.method, error }
}
