import assert from 'node:assert/strict'
import test from 'node:test'
import { createCastaliaWalletProvider } from '../src/provider.ts'
import { validateProviderRequest } from '../src/bridge.ts'
import { WasmWallet } from '../src/generated/castalia-wallet-core/bindings.js'

test('provider retains generic contracts without application-specific methods', () => {
 const provider=createCastaliaWalletProvider(async()=>{throw Error('must not dispatch')})
 for(const method of ['devgraph','requestDevgraphIssueCreatePresentation']) assert.equal(method in provider,false,method)
 for(const method of ['presentCredential','getCapabilities','wrapFilesKey','unwrapFilesKey','requestRegistrationV2','requestFilesServiceAuthentication']) assert.equal(typeof provider[method as keyof typeof provider],'function',method)
})
test('old methods are rejected as unknown even with unlocked custody and an approved origin', () => {
 for(const method of ['castalia.wallet.devgraph','castalia.wallet.requestDevgraphIssueCreatePresentation']) {
  const result=validateProviderRequest({method,payload:{},computedOrigin:'https://app.example',walletSetupComplete:true,walletUnlocked:true,approvedOrigins:new Set(['https://app.example'])})
  assert.equal(result.ok,false)
  if(result.ok)throw Error('retired method admitted')
  assert.match(result.error,/unknown method/)
 }
})
test('actual generated WASM has generic signing and no legacy application signing exports', () => {
 const methods=Object.getOwnPropertyNames(WasmWallet.prototype)
 assert.ok(methods.includes('prepareCredentialPresentation'))
 assert.ok(methods.includes('approveCredentialPresentation'))
 assert.ok(methods.includes('wrapFilesKey'))
 assert.deepEqual(methods.filter(method=>/devgraph|arena|kanban/i.test(method)),[])
})
