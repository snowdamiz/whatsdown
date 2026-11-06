#ifndef MORSE_DESKTOP_PROTECTION_BRIDGE_H
#define MORSE_DESKTOP_PROTECTION_BRIDGE_H
#include <stdbool.h>
#include <stdint.h>
#include "PrivateJob.h"
#include "NativeNoticeReceipt.h"
#ifdef __cplusplus
extern "C" {
#endif
// Internal native-only bridge. Window/webview values are SDK object handles
// obtained from Tauri; they are never accepted from IPC arguments/headers.
typedef struct {
    void *context;
    void (*retain)(void *context);
    void (*release)(void *context);
    void (*lifecycle)(void *context, uint64_t window, uint64_t page, uint32_t event);
    void (*auth_reply)(void *context, uint64_t sequence, uint32_t result);
    void (*public_action)(void *context, uint64_t window, uint64_t page, uint64_t revision, uint32_t action);
} MDNativeCallbacks;
bool MDNativeAuthenticationAvailable(void);
bool MDNativeProtectionOpenPayment(void *context, MDPrivateScope scope, const uint8_t *url, uint64_t length);
void *MDNativeProtectionCreate(MDNativeCallbacks callbacks);
// Attach, receiver, retirement and reopen are main-thread operations. Attach immediately
// covers the actual view before any public/native callback can show the window.
bool MDNativeProtectionAttach(void *context, void *window, void *webview, uint64_t window_id, uint64_t page_id);
bool MDNativeProtectionReceiver(void *context, void *window, void *webview, uint64_t *window_id, uint64_t *page_id);
// Main-thread native preview admission derives the current original owner from
// the actual requesting view and restrictive presentation, never a JS label.
bool MDNativeProtectionPrivateReceiver(void *context,void *webview,uint64_t *window_id,uint64_t *page_id);
void MDNativeProtectionRetirePage(void *context, uint64_t window_id, uint64_t page_id);
bool MDNativeProtectionReopen(void *context);
bool MDNativeProtectionFocusPublic(void *context);
bool MDNativeProtectionHide(void *context, uint64_t window_id, uint64_t page_id);
bool MDNativeProtectionWindowAction(void *context, uint64_t window_id, uint64_t page_id, uint64_t revision, uint32_t action);
bool MDNativeProtectionCopyText(void *context, MDPrivateScope scope, const uint8_t *text, uint64_t length);
// Native-derived historical key only; no IPC accepts a key or script. Accepted
// jobs own reply_context and deliver exactly one closed result, including close.
typedef void (*MDLegacyResult)(void *reply_context,uint32_t status,const uint8_t *bytes,uint64_t length);
bool MDNativeProtectionLegacy(void *context,MDPrivateScope scope,const uint8_t *key,uint64_t length,bool read,void *reply_context,MDLegacyResult reply);
#ifdef __OBJC__
// Native-only, main-thread admission. Auxiliary objects are single-use and
// must be registered before presentation; no raw-window JS command exists.
void *MDNativeProtectionPrimary(void *context, uint64_t window_id, uint64_t page_id);
bool MDNativeProtectionBindAuxiliary(void *context, uint64_t window_id, uint64_t page_id, void *window, void (^retire)(void));
void MDNativeProtectionReleaseAuxiliary(void *context, uint64_t window_id, uint64_t page_id, void *window);
#endif
bool MDNativeProtectionForeground(void *context);
// Receipt and cancellation are thread-safe, do not wait for policy/Core IO,
// and retain the original monotone registry/cover retirement semantics.
void MDNativeProtectionApply(void *context, uint64_t revision, uint64_t window_id, uint64_t page_id,
    bool has_owner, bool uncover, uint32_t phase, uint64_t request_sequence,
    uint64_t account_generation, bool notice_private_allowed);
bool MDNativeProtectionBegin(void *context, uint64_t window_id, uint64_t page_id, uint64_t sequence);
void MDNativeProtectionCancel(void *context, uint64_t sequence);
void MDNativeProtectionClose(void *context);
void MDNativeProtectionBootFailed(void *context);
void MDNativeProtectionRelease(void *context);
// Trusted native work only. Unlike Tauri run_on_main_thread, this always posts
// a later Main turn, so outer recursive native gates have returned first.
void MDNativeProtectionDeferMain(void *work, void (*run)(void *work));
#ifdef __cplusplus
}
#endif
#endif

bool MDNativeProtectionForgetLegacy(void *context,MDPrivateScope cleanup,const uint8_t *key,uint64_t length,void *replyContext,MDLegacyResult reply);
