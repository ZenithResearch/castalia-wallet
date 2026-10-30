/** Local presentation only. These labels never assert current server approval. */
export function grantCardPresentation(record:any, now=Math.floor(Date.now()/1000)) {
  const c=record.grant??record,service=String(record.service??c.service),validity=c.validity;
  let status='Saved in Wallet';
  if(validity.mode==='dated'&&now>=validity.not_after)status='Expired';
  else if(now<validity.not_before)status='Not yet valid';
  const count=c.permissions.length;
  return {title:service.includes(':')?service.slice(0,service.indexOf(':')):service,service,issuer:String(c.issuer),status,
    permissionCount:`${count} permission${count===1?'':'s'}`,
    validity:validity.mode==='until_revoked'?'Until revoked':`Ends ${new Date(validity.not_after*1000).toLocaleString()}`};
}
