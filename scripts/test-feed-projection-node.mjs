import { createRequire } from 'node:module'
import { resolve } from 'node:path'
import { verifyProjectionBinding } from '../tests/feed-projection-wasm-contract.mjs'

if (process.argv.length !== 3) throw new Error('Pass the freshly built nodejs-target castalia_wallet_core.js path')
const { WasmFeedProjectionV1 } = createRequire(import.meta.url)(resolve(process.argv[2]))
console.log(JSON.stringify({ target: 'wasm-pack nodejs; Node only', ...verifyProjectionBinding(WasmFeedProjectionV1) }))
