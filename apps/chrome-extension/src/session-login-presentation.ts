/** Presentation only. Unknown fields remain visible; this never evaluates rights. */
const labels:Record<string,string>={list:'Browse',get:'Read',relationships:'Read connections'};
export function permissionPresentation(permission:any){
 const operation=String(permission?.operation??'unrecognized'),parts=operation.split('.'),verb=parts.pop()!;
 const label=labels[verb]?labels[verb]+' · '+parts.join(' · '):'Operation: '+operation;
 const details=Object.fromEntries(Object.entries(permission??{}).filter(([key])=>key!=='operation'));
 return {label,restrictions:JSON.stringify(details,null,2)};
}
