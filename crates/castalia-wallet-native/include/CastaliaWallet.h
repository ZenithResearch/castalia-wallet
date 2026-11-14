#ifndef CASTALIA_WALLET_H
#define CASTALIA_WALLET_H
#include <stdint.h>
#include <stddef.h>
// ABI v1: handles are owned IDs, not dereferenceable key pointers. 0 is failure.
uint32_t castalia_abi_version(void);
// Standalone feed data projection, ABI feature v1. These process-local owned
// handles are not consent, Wallet sessions, transport capabilities or tokens.
// No input pointers are retained. Source/selection <=256KiB; origin <=2048 bytes.
// All inputs are original UTF-8. prepare returns 0 for invalid/unavailable input.
uint32_t castalia_feed_projection_abi_version(void);
uint64_t castalia_feed_projection_prepare(const uint8_t *source, size_t source_length,
    const uint8_t *selection, size_t selection_length, const uint8_t *origin, size_t origin_length);
// preview/confirm return result handles containing raw selected feeds-section
// JSON (not a session result envelope). Use castalia_result_* to copy/free them.
uint64_t castalia_feed_projection_preview(uint64_t preparation);
// A live preparation is consumed even for invalid arguments or exhausted result
// capacity. 0 is failure; callers must never retry the consumed preparation.
uint64_t castalia_feed_projection_confirm(uint64_t preparation,
    const uint8_t *source, size_t source_length, const uint8_t *origin, size_t origin_length);
void castalia_feed_projection_free(uint64_t preparation);
// Additive portable application-key custody, separate from the root Wallet.
// Profile and closed JSON commands/results equal the holder-session-agent v1
// protocol. Returned result handles use castalia_result_* below. No key pointers.
// Drop/free ends all local sessions; it does not confirm server-side revocation.
uint32_t castalia_holder_session_abi_version(void);
uint64_t castalia_holder_session_new(const uint8_t *profile, size_t length);
uint64_t castalia_holder_session_invoke(uint64_t custody, const uint8_t *bytes, size_t length);
void castalia_holder_session_free(uint64_t custody);
uint64_t castalia_session_new(void);
void castalia_session_free(uint64_t session);
uint64_t castalia_session_invoke(uint64_t session, const uint8_t *bytes, size_t length);
size_t castalia_result_length(uint64_t result);
size_t castalia_result_copy(uint64_t result, uint8_t *destination, size_t capacity);
void castalia_result_free(uint64_t result);
#endif
