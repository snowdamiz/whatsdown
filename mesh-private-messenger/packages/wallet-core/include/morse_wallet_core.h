#ifndef MORSE_WALLET_CORE_H
#define MORSE_WALLET_CORE_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Custom Morse wallet, not TrustWallet. No network or token/blind-RSA API. */
#define MORSE_WALLET_ABI_VERSION 1
#define MORSE_WALLET_RECORD_BYTES 44
#define MORSE_WALLET_MAX_PACKET_BYTES 1232

enum MorseWalletStatus {
  MORSE_WALLET_OK = 0,
  MORSE_WALLET_INVALID = 1,
  MORSE_WALLET_NOT_FOUND = 2,
  MORSE_WALLET_STORAGE = 3,
  MORSE_WALLET_CANCELLED = 4,
  MORSE_WALLET_EXHAUSTED = 5,
  MORSE_WALLET_INTERNAL = 6,
  MORSE_WALLET_BUFFER_TOO_SMALL = 7
};
enum MorseWalletOperation {
  MORSE_WALLET_CREATE = 1,       /* empty -> payment public key[32] */
  MORSE_WALLET_ADDRESS = 2,      /* empty -> payment public key[32] */
  MORSE_WALLET_SIGN_QUOTE = 3,   /* CQT224 || recent_blockhash[32] -> signed packet */
  MORSE_WALLET_RESERVE_BOUNTY = 4, /* empty -> index:u64LE || public key[32] */
  MORSE_WALLET_MOVE_BOUNTY = 5   /* native BWT166 -> signed two-signer packet */
};

/* Privileged native-only callbacks. Never forward records to Mesh or JS.
 * load returns the UNSEALED internal record into a Rust-owned buffer. Native
 * storage MUST seal it at rest using the platform credential store. replace
 * atomically commits a sealed replacement and acknowledges only after durable
 * persistence. acquire/release serialize across all app processes sharing the
 * seed. A process mutex alone does not satisfy that contract.
 *
 * acquire/release return 0 on success; load also returns 2 for a genuinely
 * absent wallet; all other callback failures return nonzero. No delete/reset
 * operation is provided. Callback/context lifetime need only cover this call.
 */
typedef int32_t (*MorseWalletLock)(void *context);
typedef int32_t (*MorseWalletLoad)(void *context, uint8_t *record,
                                  uint64_t capacity, uint64_t *written);
typedef int32_t (*MorseWalletReplace)(void *context, const uint8_t *record,
                                     uint64_t length);
/* Explicit native user authorization. 1=create (intent=public key[32]);
 * 3=payment (intent=CQT224 || payer[32] || recent_blockhash[32], 288 bytes).
 * 5=bounty movement (intent=BWT166 || fee_payer[32], 198 bytes). BWT166 is:
 * 01 B W T, reserved_index:u64BE, finder[32], destination_owner[32], mint[32],
 * amount:u64BE, recent_blockhash[32], issued_seconds:u64BE,
 * expiry_seconds:u64BE (issued+300), purpose:u8, token_decimals:u8 (0..18).
 * It creates the recipient ATA idempotently and transfers only from the SDK's
 * already-reserved finder ATA; the payment key pays fees and both keys sign.
 * Warn that movement publicly links the one-time address, destination and
 * fee-paying wallet. This operation never exports either secret key.
 * Display asset, exact amount, destination, quote reference and expiry, and
 * the fact that the payment is public. Return 0 only after actual confirmation;
 * cancellation/background dismissal returns nonzero. Never auto-approve.
 * Store locks are released before the prompt. Rust reconstructs the exact
 * canonical payment message before prompting; there is no arbitrary sign API.
 */
typedef int32_t (*MorseWalletAuthorize)(void *context, uint32_t operation,
                                       const uint8_t *intent, uint64_t length);
typedef struct MorseWalletCallbacksV1 {
  uint32_t abi_version;
  uint32_t struct_size;
  void *context;
  MorseWalletLock acquire;
  MorseWalletLoad load;
  MorseWalletReplace replace;
  MorseWalletLock release;
  MorseWalletAuthorize authorize;
  uint8_t usdc_mint[32]; /* native release configuration, never caller supplied */
  uint8_t purpose;       /* 0 live / 1 test, native release configuration */
  uint8_t reserved[7];   /* zero */
} MorseWalletCallbacksV1;

/* No seed import/export, raw sign, swaps, RPC or account identifiers. Output
 * contains public data only; caller owns it. written is zero on every failure.
 * Reserve commits before returning an address; failed/unknown attempts may
 * burn an index. Paths: payment m/44'/501'/0'/0'; bounty
 * m/44'/501'/2147483647'/index'. Never restore an older seed/counter snapshot.
 */
int32_t morse_wallet_call(const MorseWalletCallbacksV1 *callbacks,
                          uint32_t operation, const uint8_t *input,
                          uint64_t input_length, uint8_t *output,
                          uint64_t output_capacity, uint64_t *written);


/* Pure native-only UTF-8 confirmation formatter, at most 2048 bytes, no NUL
 * terminator. operation 1 takes proposed public key[32]; operation 3 takes the
 * 288-byte payment intent; operation 5 takes the 198-byte bounty intent above.
 * This does not approve, sign or access storage.
 * It may be called reentrantly from authorize. written=0 and output unchanged
 * on failure; all buffers and written must be valid and mutually nonoverlapping.
 * Purpose describes credits, not the Solana cluster or whether funds are real.
 */
int32_t morse_wallet_authorization_text(uint32_t operation,
                          const uint8_t *intent, uint64_t length,
                          uint8_t *output, uint64_t capacity, uint64_t *written);

#ifdef __cplusplus
}
#endif
#endif
