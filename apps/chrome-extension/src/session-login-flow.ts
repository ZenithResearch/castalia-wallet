/** Wallet-private orchestration. Preparation never signs or issues a session. */
type Command = (operation:string, value?:any)=>Promise<any>;
export async function prepareLoginReview(command:Command, request:{requested_ttl_seconds:number}, ttlSeconds?:number, inspectOnly=false) {
  const valid=(n:unknown):n is number=>Number.isSafeInteger(n)&&Number(n)>0&&Number(n)<=Math.min(3600,request.requested_ttl_seconds);
  if(!valid(request.requested_ttl_seconds)||ttlSeconds!==undefined&&!valid(ttlSeconds))throw Error('invalid_holder_session');
  let result=await command('prepare',{request,ttlSeconds});
  if(result.options&&ttlSeconds===undefined&&!inspectOnly){
    const maximum=result.options.maximum_ttl_seconds;
    if(!valid(maximum))throw Error('invalid_holder_session');
    result=await command('prepare',{request,ttlSeconds:maximum});
    if(result.options)throw Error('invalid_holder_session');
  }
  return result;
}

/** Invoked by the Wallet-owned Send request / Check original request button.
 * The signer owns the exact null-intent request and its retained recovery ID. */
export async function sendGeneralAccessRequest(command:Command, critical:(operation:string)=>Promise<any>, sendOriginal=false) {
  await command('prepareAccess',sendOriginal);
  return critical('approveAccess');
}
