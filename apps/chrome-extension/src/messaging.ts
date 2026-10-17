/**
 * Typed popup → service-worker messaging protocol (T1.3)
 *
 * Popup-initiated request/response only (for now).
 * Reliable foundation for state/actions: GET_STATE, SETUP, UNLOCK, LOCK, APPROVE/REVOKE/IS_ORIGIN_APPROVED.
 *
 * SessionWalletState is the source of truth (per Option B / per-session reset invariants).
 * Legacy ExtensionWalletState remains in service-worker.ts for now (thin adapter later).
 */

import type { SessionWalletState } from './state/session-state.js';

// Chrome MV3 globals (popup + service-worker contexts; not present in node typecheck)
declare const chrome: any;

export type PopupRequest =
  | { type: 'GET_STATE' }
  | { type: 'SETUP' }
  | { type: 'UNLOCK' }
  | { type: 'LOCK' }
  | { type: 'APPROVE_ORIGIN'; origin: string }
  | { type: 'REVOKE_ORIGIN'; origin: string }
  | { type: 'IS_ORIGIN_APPROVED'; origin: string };

export type PopupResponse =
  | {
      ok: true;
      state: SessionWalletState;
      data?: { publicKey?: string; subjectId?: string } | boolean;
    }
  | { ok: false; error: string; state?: SessionWalletState };

/**
 * Send a typed request from popup to service worker.
 * Returns a promise that resolves to the response (never rejects to keep popup robust).
 */
export async function sendPopupRequest(request: PopupRequest): Promise<PopupResponse> {
  return new Promise((resolve) => {
    if (typeof chrome === 'undefined' || !chrome.runtime?.sendMessage) {
      resolve({
        ok: false,
        error: 'Not running in a Chrome extension context (chrome.runtime unavailable)',
      });
      return;
    }

    try {
      chrome.runtime.sendMessage(request, (response: any) => {
        if (chrome.runtime.lastError) {
          resolve({
            ok: false,
            error: chrome.runtime.lastError.message || 'sendMessage failed',
          });
          return;
        }
        // Trust the SW response shape (typed at compile time)
        resolve(response as PopupResponse);
      });
    } catch (err) {
      resolve({
        ok: false,
        error: err instanceof Error ? err.message : 'Unexpected sendMessage error',
      });
    }
  });
}
