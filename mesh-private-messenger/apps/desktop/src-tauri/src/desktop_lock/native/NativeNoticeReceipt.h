#ifndef MORSE_NATIVE_NOTICE_RECEIPT_H
#define MORSE_NATIVE_NOTICE_RECEIPT_H
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// Native-only atomic projection of the accepted Protection receipt. Neither
// account_generation nor this struct is serialized into app events/IPC.
typedef struct {
    uint64_t revision;
    uint64_t window_id;
    uint64_t page_id;
    uint64_t account_generation;
    bool has_owner;
    // True only for Verified Disabled with no admitted auth/policy request.
    // Pending, Enabled, Unavailable, boot and closed receipts are restrictive.
    bool verified_disabled;
} MDNativeNoticeReceipt;

typedef struct {
    void *context;
    void (*retain)(void *context);
    void (*release)(void *context);
    void (*receipt)(void *context, MDNativeNoticeReceipt receipt);
    void (*invalidate)(void *context, uint64_t window_id, uint64_t page_id);
    void (*close)(void *context);
} MDNoticeBrokerHooks;

// Main only, once per Protection context. On success one hook context retain
// transfers to Protection. Refusal transfers nothing. An initial restrictive
// receipt (revision zero) is delivered before any later publication admission.
// receipt/invalidate/close execute synchronously under the existing native
// Protection gate: cheap latches only, no Core/controller/policy calls, external
// completion, object destruction or OS work. Queue retained teardown afterward.
// Final hook-context release occurs on Main outside every Protection gate.
bool MDNativeProtectionInstallNoticeBroker(void *protection, MDNoticeBrokerHooks hooks);

// Fixed native callback only. publication_context is borrowed for this call;
// callback owns any retention needed by queued work. It receives the current
// accepted receipt while the original Protection gate is still held and may
// only select/copy bounded content and queue work. It must not call Core,
// policy/controller admission, JS, native UI or synchronous external callbacks.
typedef bool (*MDNativeNoticePublish)(void *publication_context, MDNativeNoticeReceipt receipt);

// Main only. The original native owner/account generation must match the live
// receiver and accepted receipt, with nonzero revision and no closed/boot error.
// No caller revision or latest-owner repair exists. Original scope/account/Core
// preparation runs before this function, outside its gate. A restrictive receipt
// is allowed to publish generic content containing no private scope/details.
// Every queued OS enqueue rechecks its captured receipt in the broker. A late
// completion after restriction/removal scrubs that exact owned request/delivered
// ID; this cannot undo a banner the OS already displayed.
bool MDNativeProtectionPublishNotice(void *protection, uint64_t original_window_id,
    uint64_t original_page_id, uint64_t original_account_generation,
    void *publication_context, MDNativeNoticePublish publish);
// Native intent removal is a distinct private action. It is admitted even when
// verified_disabled is false (enabled but freshly unlocked), and additionally
// requires the actual current primary to permit private action at this receipt
// revision. Original scope/account/Core preparation remains outside the gate.
// The fixed callback only copies/removes one bounded retained native intent;
// it cannot run Core/policy, JS, OS/UI, external completion or destruction here.
// Ordinary lock keeps the broker's one cold intent. Account-generation change
// and close retire it; restrictive generic tap payloads can name inbox only.
typedef bool (*MDNativeNoticeConsume)(void *consumption_context, MDNativeNoticeReceipt receipt);
bool MDNativeProtectionConsumeNotice(void *protection, uint64_t original_window_id,
    uint64_t original_page_id, uint64_t original_account_generation,
    void *consumption_context, MDNativeNoticeConsume consume);
#ifdef __cplusplus
}
#endif
#endif
