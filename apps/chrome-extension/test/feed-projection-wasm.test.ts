import test from 'node:test'
import { initSync, WasmFeedProjectionV1 } from '../src/generated/castalia-wallet-core/castalia_wallet_core.js'
import { CASTALIA_WALLET_CORE_WASM } from '../src/generated/castalia-wallet-core/wasm-bytes.js'
// @ts-expect-error Test-only JavaScript assertions deliberately use the real generated class.
import { verifyProjectionBinding } from '../../../tests/feed-projection-wasm-contract.mjs'

initSync({ module: CASTALIA_WALLET_CORE_WASM })
test('actual rebuilt web-target WASM projection in Node preserves vectors and one-shot lifetimes', () => {
  verifyProjectionBinding(WasmFeedProjectionV1)
})
