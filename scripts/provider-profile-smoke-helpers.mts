import {spawn} from 'node:child_process'
import type {BrowserContext} from 'playwright-core'
/** Exercise the real Wallet-owned manual import UI; never write trust directly to storage. */
export async function importProfile(context:BrowserContext, extensionId:string, profile:unknown, purposes:{membership:boolean;presentations:boolean}, approveHostPermission?:()=>Promise<void>) {
 const settings=await context.newPage()
 await settings.goto(`chrome-extension://${extensionId}/src/provider-settings.html`)
 await settings.locator('#profile-json').fill(JSON.stringify(profile))
 await settings.getByRole('button',{name:'Review profile',exact:true}).click()
 if(purposes.membership)await settings.getByLabel('Trust this provider for membership enrollment and proof verification').check()
 if(purposes.presentations)await settings.getByLabel('Trust these authorities for the specified request credentials').check()
 const issuerOrigin=purposes.membership?(profile as {membership?:{issuer_origin:string}}).membership?.issuer_origin:undefined
 const nativeLane=process.env.BUILDKITE==='true'&&process.platform==='linux'&&process.env.CASTALIA_NATIVE_PERMISSION_TEST==='1'&&!approveHostPermission&&issuerOrigin
 await settings.getByRole('button',{name:'Approve selected purposes',exact:true}).click()
 if(approveHostPermission)await approveHostPermission()
 const saved=settings.getByText('Provider trust saved.',{exact:true}).waitFor({timeout:60000})
 if(nativeLane){
  // Chrome may reuse an existing host grant. Race actual UI completion against
  // observing a native prompt; permissions.contains is not an approval receipt.
  const child=spawn('/usr/bin/python3',['scripts/approve-test-host-permission.py',new URL(issuerOrigin!).hostname],{timeout:25000})
  let diagnostic=''
  child.stdout.on('data',data=>{diagnostic+=data;process.stdout.write(data)})
  child.stderr.on('data',data=>{diagnostic+=data;process.stderr.write(data)})
  const approved=new Promise<void>((resolve,reject)=>{
   child.once('error',reject)
   child.once('close',(code,signal)=>code===0?resolve():reject(new Error(`Native test approval failed (${code??signal}): ${diagnostic}`)))
  })
  try{await Promise.race([saved,approved]);await saved}finally{if(child.exitCode===null)child.kill()}
 }else await saved.catch(async error=>{throw new Error('Profile import: '+await settings.locator('#status').innerText()+'; '+String(error))})
 return settings
}
