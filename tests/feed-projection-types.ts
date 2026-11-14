import { WasmFeedProjectionV1 } from '../apps/chrome-extension/src/generated/castalia-wallet-core/bindings.js'
declare const source: Uint8Array, selection: Uint8Array, origin: string
const prepared: WasmFeedProjectionV1 = new WasmFeedProjectionV1(source, selection, origin)
const selected: string = prepared.previewJson()
const destination: string = prepared.destinationOrigin()
const confirmed: string = prepared.confirm(source, origin)
prepared.dispose()
prepared.free()
void [selected, destination, confirmed]
