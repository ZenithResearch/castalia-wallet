/** Optional, capability-negotiated data-only disclosure. The page provides no
 * source, destination or selection. Wallet choices and consent are separate.
 * The returned UTF-8 JSON is castalia.feeds-section.v1, not authority. Receiving
 * hosts must validate/review it and atomically save locally without activation.
 */
export interface SelectedFeedsProviderV1 {
  selectFeeds?(): Promise<string>
}
export const SELECTED_FEEDS_CAPABILITY = 'selected_feeds_v1'
