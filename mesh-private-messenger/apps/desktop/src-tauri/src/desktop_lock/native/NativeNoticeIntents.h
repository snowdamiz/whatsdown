#ifndef MORSE_NATIVE_NOTICE_INTENTS_H
#define MORSE_NATIVE_NOTICE_INTENTS_H
#include "NativeNoticeReceipt.h"
#include <stddef.h>

typedef struct MDNativeNoticeIntents MDNativeNoticeIntents;
typedef enum {
    MDNoticeIntentNone = 0,
    MDNoticeIntentInbox = 1,
    MDNoticeIntentScope = 2
} MDNoticeIntentKind;
typedef struct {
    MDNoticeIntentKind kind;
    size_t scope_length;
    char scope[71];
} MDNoticeIntent;

MDNativeNoticeIntents *MDNativeNoticeIntentsCreate(void);
void MDNativeNoticeIntentsDestroy(MDNativeNoticeIntents *intents);
// Thread-safe fixed-size latches. Safe under the native Protection gate: no
// allocation, callback, owner lookup, Core access, or object destruction.
void MDNativeNoticeIntentsReceipt(MDNativeNoticeIntents *intents, MDNativeNoticeReceipt receipt);
void MDNativeNoticeIntentsClose(MDNativeNoticeIntents *intents);
// Only the native publisher/delegate may call these after matching an owned
// opaque OS request. Scope and generation come from its native record, never
// from notification userInfo, JS, or a caller-supplied account identifier.
bool MDNativeNoticeIntentsRecordPrivate(MDNativeNoticeIntents *intents,
    uint64_t original_account_generation, const char *scope, size_t length);
bool MDNativeNoticeIntentsRecordGeneric(MDNativeNoticeIntents *intents, uint64_t original_account_generation);
// Must run inside MDNativeProtectionConsumeNotice's fixed admitted callback.
// Exact receipt equality prevents stale callbacks from taking newer work.
// An ordinary lock preserves the slot; a different account or close erases it.
bool MDNativeNoticeIntentsConsume(MDNativeNoticeIntents *intents,
    MDNativeNoticeReceipt admitted_receipt, MDNoticeIntent *output);
#endif
