import { createPrivateKey,createPublicKey } from 'node:crypto'
const key=createPrivateKey({key:Buffer.from('302e020100300506032b657004220420'+'0b'.repeat(32),'hex'),format:'der',type:'pkcs8'})
const public_key=createPublicKey(key).export({format:'der',type:'spki'}).subarray(-32).toString('hex')
console.log(JSON.stringify(['fixture-service','second-service'].map(audience=>({issuer:'fixture-issuer',key_id:'fixture-key',public_key,audience,callers:[{kind:'browser',id:'https://credentials.test'}]}))))
