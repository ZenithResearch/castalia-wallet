/**
 * Session-Scoped State Model for Castalia Wallet Chrome Extension (Option B - Review Demo)
 *
 * Design goals (explicitly approved):
 * - Fresh Ed25519 key pair generated on EVERY "Setup" action (maximum safety during review).
 * - approvedOrigins is STRICTLY per-session. The list is empty after any extension reload.
 * - No 24h / cross-reload persistence of any kind.
 * - Uses chrome.storage.session (MV3 native) for data that must survive service worker restarts
 *   but still clears when the browser session / extension is reloaded.
 * - Private key lives ONLY in memory inside the current service worker lifetime.
 */

import {
  createDevWalletKeyPairBrowser as createDevWalletKeyPair,
  resetDevWalletKeyPairBrowser,
  type DevWalletKeyPair,
} from '../crypto-browser.js';
import type { DreggMembershipClientConfig } from '@castalia-wallet/dregg-adapter';

// Chrome MV3 extension globals (service worker context only; not present during node typecheck/tests of pure modules)
declare const chrome: any;

export interface SessionWalletState {
  setupComplete: boolean;
  unlocked: boolean;
  approvedOrigins: string[];
  publicKey: string | null;
  subjectId: string | null;
  membershipConfig: DreggMembershipClientConfig | null;
}

export interface SessionStateManager {
  getState(): Promise<SessionWalletState>;
  setup(): Promise<{ publicKey: string; subjectId: string }>;           // Always generates a FRESH key
  unlock(): Promise<void>;
  lock(): Promise<void>;
  approveOrigin(origin: string): Promise<void>;
  revokeOrigin(origin: string): Promise<void>;
  isOriginApproved(origin: string): Promise<boolean>;
  bindMembership(config: DreggMembershipClientConfig): Promise<void>;
  unbindMembership(): Promise<void>;
  clearIdentityAuthorizations(): Promise<void>;
  clearForReload(): Promise<void>;                   // Explicit reset called on service worker startup
}

const STORAGE_KEY = 'castalia-session-state';

let inMemoryPrivateKeyPem: string | null = null; // Never persisted; only for current SW lifetime
let inMemoryKeyPair: DevWalletKeyPair | null = null;

async function loadFromStorage(): Promise<SessionWalletState> {
  const result = await chrome.storage.session.get(STORAGE_KEY);
  const stored = result[STORAGE_KEY];

  if (stored) {
    return {
      setupComplete: stored.setupComplete ?? false,
      unlocked: stored.unlocked ?? false,
      approvedOrigins: stored.approvedOrigins ?? [],
      publicKey: stored.publicKey ?? null,
      subjectId: stored.subjectId ?? null,
      membershipConfig: stored.membershipConfig ?? null,
    };
  }

  return getDefaultState();
}

function getDefaultState(): SessionWalletState {
  return {
    setupComplete: false,
    unlocked: false,
    approvedOrigins: [],
    publicKey: null,
    subjectId: null,
    membershipConfig: null,
  };
}

async function saveToStorage(state: Partial<SessionWalletState>): Promise<void> {
  const current = await loadFromStorage();
  const next = { ...current, ...state };
  await chrome.storage.session.set({ [STORAGE_KEY]: next });
}

export const sessionState: SessionStateManager = {
  async getState(): Promise<SessionWalletState> {
    return loadFromStorage();
  },

  async setup(): Promise<{ publicKey: string; subjectId: string }> {
    // ALWAYS generate a fresh key pair (review safety requirement)
    resetDevWalletKeyPairBrowser();
    const keyPair: DevWalletKeyPair = await createDevWalletKeyPair();

    inMemoryPrivateKeyPem = keyPair.privateKeyPem;
    inMemoryKeyPair = keyPair;

    // Cleaner subjectId for demo (strip PEM headers)
    const cleanPub = keyPair.publicKey
      .replace(/-----BEGIN PUBLIC KEY-----/, "")
      .replace(/-----END PUBLIC KEY-----/, "")
      .replace(/\s/g, "");
    const subjectId = `did:castalia:dev:${cleanPub.slice(0, 16)}`;

    const newState: Partial<SessionWalletState> = {
      setupComplete: true,
      unlocked: true,
      publicKey: keyPair.publicKey,
      subjectId,
      approvedOrigins: [], // fresh session starts with no approvals
      membershipConfig: null, // an issued membership is holder-bound to the previous key
    };

    await saveToStorage(newState);
    return { publicKey: keyPair.publicKey, subjectId };
  },

  async unlock(): Promise<void> {
    const state = await loadFromStorage();
    if (!state.setupComplete) {
      throw new Error('Cannot unlock: wallet is not set up');
    }
    await saveToStorage({ unlocked: true });
  },

  async lock(): Promise<void> {
    await saveToStorage({ unlocked: false });
  },

  async approveOrigin(origin: string): Promise<void> {
    const state = await loadFromStorage();
    if (!state.approvedOrigins.includes(origin)) {
      const updated = [...state.approvedOrigins, origin];
      await saveToStorage({ approvedOrigins: updated });
    }
  },

  async revokeOrigin(origin: string): Promise<void> {
    const state = await loadFromStorage();
    const updated = state.approvedOrigins.filter(o => o !== origin);
    await saveToStorage({ approvedOrigins: updated });
  },

  async isOriginApproved(origin: string): Promise<boolean> {
    const state = await loadFromStorage();
    return state.approvedOrigins.includes(origin);
  },

  async bindMembership(config: DreggMembershipClientConfig): Promise<void> {
    await saveToStorage({ membershipConfig: config });
  },

  async unbindMembership(): Promise<void> {
    await saveToStorage({ membershipConfig: null });
  },

  async clearIdentityAuthorizations(): Promise<void> {
    await saveToStorage({
      setupComplete: false,
      unlocked: false,
      approvedOrigins: [],
      publicKey: null,
      subjectId: null,
      membershipConfig: null,
    });
  },

  async clearForReload(): Promise<void> {
    // This is the key method that enforces per-session behavior
    inMemoryPrivateKeyPem = null;
    inMemoryKeyPair = null;
    resetDevWalletKeyPairBrowser();

    await chrome.storage.session.remove(STORAGE_KEY);

    // Re-initialize to default (empty approvals, locked, not set up from the perspective of a new session)
    await saveToStorage(getDefaultState());
  },
};

// Helper to get the in-memory private key PEM (only available during current service worker lifetime)
export function getInMemoryPrivateKeyPem(): string | null {
  return inMemoryPrivateKeyPem;
}

// Helper to get the full in-memory key pair object for signing (only during current SW lifetime)
export function getInMemoryKeyPair(): DevWalletKeyPair | null {
  return inMemoryKeyPair;
}
