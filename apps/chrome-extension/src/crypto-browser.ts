// Browser-compatible dev key + signing for Checkpoint A demo
// Uses Web Crypto API (available in service workers and content scripts)

export interface DevWalletKeyPair {
  kind: 'disposable-dev';
  publicKey: string;        // PEM format for compatibility
  publicKeyRawHex: string;  // Dregg's canonical 32-byte Ed25519 owner key
  privateKeyPem: string;    // Not really used in browser path
  privateKeyExtractable: false;
}

let cachedKeyPair: CryptoKeyPair | null = null;

export function resetDevWalletKeyPairBrowser(): void {
  cachedKeyPair = null;
}

export async function createDevWalletKeyPairBrowser(): Promise<DevWalletKeyPair> {
  if (!cachedKeyPair) {
    cachedKeyPair = await crypto.subtle.generateKey(
      {
        name: "Ed25519",
      },
      true,
      ["sign", "verify"]
    );
  }

  // Export public key as SPKI (closest to PEM we can easily do)
  const publicKeySpki = await crypto.subtle.exportKey("spki", cachedKeyPair.publicKey);
  const publicKeyRaw = await crypto.subtle.exportKey("raw", cachedKeyPair.publicKey);
  const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(publicKeySpki)));
  const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${publicKeyBase64.match(/.{1,64}/g)?.join('\n')}\n-----END PUBLIC KEY-----`;
  const publicKeyRawHex = Array.from(
    new Uint8Array(publicKeyRaw),
    (byte) => byte.toString(16).padStart(2, '0'),
  ).join('');

  return {
    kind: 'disposable-dev',
    publicKey: publicKeyPem,
    publicKeyRawHex,
    privateKeyPem: 'browser-webcrypto', // placeholder
    privateKeyExtractable: false,
  };
}

function canonicalChallengeJson(challenge: any): string {
  return JSON.stringify({
    audience: challenge.audience,
    domain: challenge.domain,
    expiresAt: challenge.expiresAt,
    issuedAt: challenge.issuedAt,
    nonce: challenge.nonce,
    operation: challenge.operation,
    origin: challenge.origin,
    version: challenge.version,
  });
}

export async function signChallengeWithDevKeyBrowser(
  keyPair: DevWalletKeyPair,
  challenge: any
): Promise<string> {
  if (!cachedKeyPair) {
    throw new Error("Key pair not generated yet");
  }

  const message = new TextEncoder().encode(canonicalChallengeJson(challenge));
  const signature = await crypto.subtle.sign("Ed25519", cachedKeyPair.privateKey, message);
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

export async function signBytesWithDevKeyBrowser(message: Uint8Array): Promise<string> {
  if (!cachedKeyPair) throw new Error("Key pair not generated yet");
  const signature = await crypto.subtle.sign("Ed25519", cachedKeyPair.privateKey, Uint8Array.from(message));
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}
