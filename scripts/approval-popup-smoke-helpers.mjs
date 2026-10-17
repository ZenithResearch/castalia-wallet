/** Click a completing approval; callers must still await and assert the request result. */
export async function clickClosingApproval(popup, buttonName, caller) {
  try {
    await popup.getByRole('button', {name: buttonName, exact: true}).click()
  } catch (error) {
    // Chrome may close the completed popup before acknowledging its click.
    // Never mask a live popup error, caller loss, timeout, or missing result.
    if (!popup.isClosed() || caller.isClosed() || !String(error).includes('Target page, context or browser has been closed')) throw error
  }
}
