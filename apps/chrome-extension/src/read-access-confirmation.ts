declare const chrome: any;
const requestId = new URL(location.href).searchParams.get("request");
const approve = document.getElementById("approve") as HTMLButtonElement,
  deny = document.getElementById("deny") as HTMLButtonElement,
  status = document.getElementById("status")!;
const send = (message: unknown): Promise<any> =>
  new Promise((resolve, reject) =>
    chrome.runtime.sendMessage(message, (r: any) =>
      chrome.runtime.lastError || !r?.ok
        ? reject(new Error(r?.error ?? "approval_unavailable"))
        : resolve(r),
    ),
  );
async function decide(approved: boolean) {
  approve.disabled = deny.disabled = true;
  try {
    await send({
      type: "RESOLVE_READ_ACCESS_CONFIRMATION",
      requestId,
      approved,
    });
  } catch {
    status.textContent =
      "This request is no longer available. Return to the application and connect again.";
  }
}
approve.onclick = () => void decide(true);
deny.onclick = () => void decide(false);
void (async () => {
  try {
    if (!requestId) throw new Error("approval_unavailable");
    const { summary } = await send({
      type: "GET_READ_ACCESS_CONFIRMATION",
      requestId,
    });
    if(summary.kind==='access_request') {
      const titles:Record<string,string>={'access.request':'Send access request?','access.status':'Check request status?','access.inbox':'Open access inbox?','access.review':'Review grant selection?','access.decide':'Approve access decision?'};
      document.getElementById('heading')!.textContent=titles[summary.operation]??'Review access request';
      document.getElementById('explanation')!.textContent='Sign the exact request below for this server. Requesting or reviewing permissions does not itself issue a credential. The server checks your authority separately.';
      document.getElementById('expiry-label')!.textContent='Approval expires';
      document.getElementById('details-label')!.textContent='Exact request details';
      document.querySelector('details')!.open=true;
      approve.textContent=summary.operation==='access.request'?'Send request':summary.operation==='access.decide'?'Approve decision':'Continue';
    }
    if(summary.kind==='holder_grant'){
      document.getElementById('heading')!.textContent=summary.save?'Save grant in Wallet?':'Use saved grant?';
      document.getElementById('explanation')!.textContent='Wallet will produce a short-lived credential for this same Wallet within the permissions below. It cannot delegate access to another Wallet. Saving keeps an encrypted copy for future use and Wallet database backup.';
      document.getElementById('details-label')!.textContent='Granted permissions and current-resource scope';
      document.querySelector('details')!.open=true;
      approve.textContent=summary.save?'Save grant and connect':'Use saved grant';
    }
    if (summary.membershipIncluded) {
      document.getElementById('membership-disclosure')!.hidden = false;
      document.getElementById('membership-disclosure')!.textContent = 'An active membership proof from your selected Wallet profile will accompany this request.';
    }
    document.getElementById("origin")!.textContent =
      `Requested by ${summary.origin}`;
    document.getElementById("receiver")!.textContent = summary.receiver;
    document.getElementById("expires")!.textContent = new Date(
      summary.expires_at * 1000,
    ).toLocaleString();
    document.getElementById("permissions")!.textContent = JSON.stringify(
      summary.kind==='access_request'?summary.details:summary.permissions,
      null,
      2,
    );
    approve.disabled = deny.disabled = false;
  } catch {
    status.textContent = "This request is no longer available.";
  }
})();
export {};
