import { parseProviderProfile, type ProviderProfileV1 } from '@castalia-wallet/provider-types'
declare const chrome: any
const status = document.getElementById('status')!
const requestId = new URL(location.href).searchParams.get('request')
function node<K extends keyof HTMLElementTagNameMap>(tag: K, text?: string) {
  const e = document.createElement(tag)
  if (text !== undefined) e.textContent = text
  return e
}
function error(e: unknown) {
  status.textContent = e instanceof Error ? e.message : 'Provider operation failed'
}
function send(message: unknown): Promise<any> {
  return new Promise((resolve, reject) =>
    chrome.runtime.sendMessage(message, (r: any) => {
      const e =
        chrome.runtime.lastError?.message ??
        (r?.ok ? undefined : (r?.error ?? 'Wallet unavailable'))
      if (e) reject(new Error(e))
      else resolve(r)
    }),
  )
}
function button(text: string, action: () => Promise<unknown>) {
  const b = node('button', text)
  b.type = 'button'
  b.addEventListener('click', () => {
    b.disabled = true
    status.textContent = ''
    void action()
      .catch(error)
      .finally(() => {
        b.disabled = false
      })
  })
  return b
}
function details(parent: HTMLElement, profile: ProviderProfileV1) {
  parent.append(
    node('h2', profile.display_name),
    node('p', 'Applies only to these application origins:'),
    node('pre', profile.origins.join('\n')),
  )
  if (profile.membership) {
    parent.append(
      node('h3', 'Membership issuer'),
      node('pre', profile.membership.issuer_origin),
      node('pre', JSON.stringify(profile.membership.roots, null, 2)),
    )
  }
  if (profile.presentations.length)
    parent.append(
      node('h3', 'Request credential authorities'),
      node('pre', JSON.stringify(profile.presentations, null, 2)),
    )
}
function choices(parent: HTMLElement, profile: ProviderProfileV1) {
  const membership = node('input'),
    presentations = node('input')
  for (const [input, label, enabled] of [
    [
      membership,
      'Trust this provider for membership enrollment and proof verification',
      !!profile.membership,
    ],
    [
      presentations,
      'Trust these authorities for the specified request credentials',
      !!profile.presentations.length,
    ],
  ] as const) {
    input.type = 'checkbox'
    input.disabled = !enabled
    const l = node('label')
    l.append(input, document.createTextNode(' ' + label))
    parent.append(l)
  }
  return { membership, presentations }
}
// Must begin synchronously in the click handler to preserve Chrome's user gesture.
function hostPermission(profile: ProviderProfileV1, enabled: boolean): Promise<void> {
  if (!enabled || !profile.membership) return Promise.resolve()
  return new Promise((resolve, reject) =>
    chrome.permissions.request(
      { origins: [profile.membership!.issuer_origin + '/*'] },
      (granted: boolean) => {
        if (chrome.runtime.lastError || !granted)
          reject(new Error('Issuer host permission was not granted'))
        else resolve()
      },
    ),
  )
}
async function refresh() {
  const result = await send({ type: 'PROFILE_SETTINGS_GET' }),
    list = document.getElementById('profiles')!
  list.replaceChildren()
  if (!result.profiles.length)
    list.append(
      node('p', 'No trusted providers. You can connect sites and use custody without enrolling.'),
    )
  for (const p of result.profiles) {
    const row = node('article')
    details(row, p.profile)
    row.append(
      node(
        'p',
        p.active
          ? 'Trusted · revision ' + p.revision
          : 'Trust removed · retained proofs are preserved',
      ),
    )
    if (p.active) {
      row.append(
        button('Remove trust', async () => {
          await send({
            type: 'PROFILE_SETTINGS_REMOVE',
            profileId: p.id,
            expectedRevision: p.revision,
          })
          await refresh()
        }),
      )
      if (p.profile.membership) {
        row.append(
          node(
            'p',
            'Compatibility selection for older applications (choose explicitly for each origin):',
          ),
        )
        for (const origin of p.profile.origins)
          row.append(
            button(
              (result.legacy[origin] === p.id ? 'Selected: ' : 'Use for: ') + origin,
              async () => {
                await send({
                  type: 'PROFILE_SETTINGS_BIND_LEGACY',
                  origin,
                  profileId: p.id,
                  expectedRevision: p.revision,
                })
                await refresh()
              },
            ),
          )
      }
    }
    row.append(
      button('Review replacement', async () => {
        ;(document.getElementById('profile-json') as HTMLTextAreaElement).value = JSON.stringify(
          p.profile,
          null,
          2,
        )
        showPreview({ id: p.id, expectedRevision: p.revision })
      }),
    )
    list.append(row)
  }
}
function showPreview(edit?: { id: string; expectedRevision: number }) {
  const profile = parseProviderProfile(
    JSON.parse((document.getElementById('profile-json') as HTMLTextAreaElement).value),
  )
  const area = document.getElementById('preview-details')!
  area.replaceChildren()
  details(area, profile)
  const c = choices(area, profile)
  area.append(
    button('Approve selected purposes', () => {
      const purposes = { membership: c.membership.checked, presentations: c.presentations.checked }
      return hostPermission(profile, purposes.membership)
        .then(() =>
          send({ type: 'PROFILE_SETTINGS_SAVE', profile, purposes, ...(edit ? { edit } : {}) }),
        )
        .then(async () => {
          area.replaceChildren()
          ;(document.getElementById('profile-json') as HTMLTextAreaElement).value = ''
          await refresh()
          status.textContent = 'Provider trust saved.'
        })
    }),
  )
}
async function start() {
  if (!requestId) {
    document.getElementById('settings')!.hidden = false
    document.getElementById('preview')!.addEventListener('click', () => {
      try {
        showPreview()
      } catch (e) {
        error(e)
      }
    })
    await refresh()
    return
  }
  const { summary } = await send({ type: 'GET_PROVIDER_APPROVAL', requestId })
  const area = document.getElementById('approval')!
  area.hidden = false
  document.getElementById('title')!.textContent =
    summary.operation === 'connect'
      ? 'Connect this site'
      : summary.operation === 'propose'
        ? 'Review provider trust'
        : 'Join membership'
  area.append(node('p', 'Requesting site: ' + summary.origin))
  let c: ReturnType<typeof choices> | undefined
  if (summary.profile) {
    details(area, summary.profile)
    if (summary.operation === 'propose') c = choices(area, summary.profile)
  }
  if (summary.memberKey)
    area.append(node('p', 'Membership holder:'), node('code', summary.memberKey))
  area.append(
    node(
      'p',
      summary.operation === 'connect'
        ? 'Allow this site to request your public identity and separately approved signatures. No membership enrollment or issuer trust is included.'
        : summary.operation === 'propose'
          ? 'Choose each purpose you intend to trust. Receiver eligibility and execution policy remain independent.'
          : 'Sign the fixed membership enrollment request and send it only to the displayed issuer.',
    ),
  )
  area.append(
    button('Cancel', async () => {
      await send({ type: 'RESOLVE_PROVIDER_APPROVAL', requestId, approved: false })
      window.close()
    }),
    button(
      summary.operation === 'connect'
        ? 'Connect'
        : summary.operation === 'propose'
          ? 'Approve selected purposes'
          : 'Join membership',
      () => {
        const purposes = {
          membership: c?.membership.checked === true,
          presentations: c?.presentations.checked === true,
        }
        return hostPermission(summary.profile, purposes.membership)
          .then(() =>
            send({ type: 'RESOLVE_PROVIDER_APPROVAL', requestId, approved: true, purposes }),
          )
          .then(() => {
            window.close()
          })
      },
    ),
  )
}
void start().catch(error)
