#ifndef CASTALIA_WALLET_H
#define CASTALIA_WALLET_H
#include <stdint.h>
#include <stddef.h>
// ABI v1: handles are owned IDs, not dereferenceable key pointers. 0 is failure.
uint32_t castalia_abi_version(void);
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
