import type { ReadAccessProvider } from './read-access.js'
export * from './read-access.js'
export * from './session-login.js'
import type { ProviderProfilesProvider } from './provider-profiles.js'
import type { CredentialPresentationProvider } from './credential-presentation.js'
export * from './credential-presentation.js'
import type { FilesKeyProviderV1 } from './files-key-contract.js'
export * from './files-key-contract.js'
import type { RegistrationRequestV1, SignedRegistrationManifestV1 } from '@castalia/filesystem/registration'
export type { RegistrationRequestV1, SignedRegistrationManifestV1 } from '@castalia/filesystem/registration'

export type CastaliaWalletKind = 'castalia-dregg'

export type CastaliaWalletOperation =
  | 'castalia.wallet.requestRegistration'
  | 'castalia.wallet.signChallenge'
  | 'castalia.wallet.requestMembershipPresentation'
  | 'castalia.wallet.getSubject'
  | 'castalia.wallet.getMembership'
  | 'castalia.wallet.isAvailable'
  | 'castalia.wallet.openMembershipFlow'

export type CapabilitySummary = {
  id: string
  label?: string
  scope?: string
}

export type DreggHybridIdentity = {
  version: 1
  signatureSuite: 'Ed25519+ML-DSA-65'
  ed25519PublicKey: string
  mlDsa65PublicKey: string
  mlDsa65PublicKeyCommitment: string
  derivation: 'dregg.hybrid-from-ed25519-seed.v1'
}

export type CastaliaSubject = {
  subjectId: string
  publicKey: string
  dreggOwnerPublicKey: string
  /** Present in hybrid-capable Wallet builds; optional only for provider-v1 compatibility. */
  dreggHybridIdentity?: DreggHybridIdentity
  walletKind: CastaliaWalletKind
  capabilities?: CapabilitySummary[]
}

export type SignChallengeRequest = {
  domain: 'castalia-wallet'
  version: 1
  nonce: string
  origin: string
  audience: string
  operation: CastaliaWalletOperation | string
  issuedAt: string
  expiresAt: string
}

export type SignaturePresentation = {
  subject: CastaliaSubject
  challenge: SignChallengeRequest
  signature: string
  signatureAlgorithm: 'ed25519' | 'node-ed25519'
}

export type CastaliaMemberApplicationV1 = {
  factoryId: string
  programId: string
  applicantOfficialDreggCellId: string
  ownerPublicKey: string
  applicationKind: 7
  applicationVersion: 1
  applicationNonce: number
  membershipClass: 1 | 2
  jurisdictionCode: number
  applicationFlags: number
  createdAt: number
}

export type MembershipEnrollmentChallengeV2 = {
  version: 2
  challengeId: string
  nonce: string
  origin: string
  audience: string
  operation: 'castalia.membership.enroll'
  ownerPublicKey: string
  applicationCommitment: string
  signatureSuite: 1
  issuedAt: number
  expiresAt: number
}

export type MembershipPresentationRequestV2 = {
  application: CastaliaMemberApplicationV1
  challenge: MembershipEnrollmentChallengeV2
}

export type MembershipPresentationV2 = {
  schema: 'castalia.wallet-membership-presentation.v2'
  ownerPublicKey: string
  challenge: MembershipEnrollmentChallengeV2
  signatureSuite: 'Ed25519'
  signature: string
}

export type CastaliaMembershipSummary = ZenithMembershipCredentialV3

export type CastaliaWalletOnboardingRequest = {
  version: 'castalia.wallet-onboarding.v1'
  requestId: string
  origin: string
  audience: string
  operation: 'authenticate'
  nonce: string
  issuedAtMs: number
  expiresAtMs: number
}

export type CastaliaWalletOnboardingPresentation = {
  format: 'castalia.wallet-presentation.v1'
  payload: string
}

export type CastaliaWalletProvider = ReadAccessProvider & CredentialPresentationProvider & ProviderProfilesProvider & FilesKeyProviderV1 & {
  readonly kind: 'castalia.wallet-provider'
  readonly version: '1'
  readonly membershipJoinProtocol?: 'castalia.zenith-membership.v3'
  isAvailable(): Promise<boolean>
  openMembershipFlow(): Promise<{ state: 'opened' }>
  getSubject(): Promise<CastaliaSubject>
  getMembership(): Promise<CastaliaMembershipSummary>
  /** Signs a namespace proposal; receiver verification and acceptance remain separate. */
  requestRegistrationV2(input: RegistrationRequestV1): Promise<SignedRegistrationManifestV1>
  requestRegistration(input: RegistrationRequestV1): Promise<SignedRegistrationManifestV1>
  signChallenge(input: SignChallengeRequest): Promise<SignaturePresentation>
  requestMembershipPresentation(input: MembershipPresentationRequestV2): Promise<MembershipPresentationV2>
  getStatus(): Promise<{
    state: 'locked' | 'ready'
    publicIdentity?: string
  }>
  createAuthenticationPresentation(
    request: CastaliaWalletOnboardingRequest,
  ): Promise<CastaliaWalletOnboardingPresentation>
}
import type { ZenithMembershipCredentialV3 } from '@castalia-wallet/zenith-membership'

export * from './provider-profiles.js'
export * from './provider-profile-store.js'
