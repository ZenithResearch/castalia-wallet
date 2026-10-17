export function presentationTrustPins(raw = '[]') {
 if(typeof raw !== 'string'||Buffer.byteLength(raw)>262144)throw new Error('Invalid presentation trust configuration')
 const pins=JSON.parse(raw)
 if(!Array.isArray(pins)||pins.length>64)throw new Error('Invalid presentation trust pins')
 const seen=new Set()
 const text=v=>typeof v==='string'&&/^[\x20-\x7e]{1,200}$/.test(v)
 for(const pin of pins){
  if(!pin||Object.keys(pin).sort().join(',')!=='audience,callers,issuer,key_id,public_key'||![pin.issuer,pin.key_id,pin.audience].every(text)||!/^[0-9a-f]{64}$/.test(pin.public_key)||!Array.isArray(pin.callers)||pin.callers.length<1||pin.callers.length>64)throw new Error('Invalid presentation trust pin')
  const id=JSON.stringify([pin.issuer,pin.key_id,pin.audience]);if(seen.has(id))throw new Error('Ambiguous presentation issuer pin');seen.add(id)
  for(const caller of pin.callers){
   if(!caller||Object.keys(caller).sort().join(',')!=='id,kind'||!text(caller.id)||caller.kind!=='browser')throw new Error('Extension presentation pin requires browser caller')
   const u=new URL(caller.id)
   if(u.origin!==caller.id||u.username||u.password||u.hostname.endsWith('.')||u.protocol!=='https:'&&!(u.protocol==='http:'&&['127.0.0.1','localhost','[::1]'].includes(u.hostname)))throw new Error('Invalid presentation caller origin')
  }
 }
 return pins
}
