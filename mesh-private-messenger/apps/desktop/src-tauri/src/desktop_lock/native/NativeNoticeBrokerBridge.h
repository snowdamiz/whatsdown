#ifndef MORSE_NATIVE_NOTICE_BROKER_BRIDGE_H
#define MORSE_NATIVE_NOTICE_BROKER_BRIDGE_H
#include "PrivateJob.h"
#include "NativeNoticeIntents.h"
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// Native app-lifetime wake only; the Rust side emits exactly
// app-lock-notice-pending {version:1}, never account/scope/title/body.
typedef struct {
    void *context;
    void (*retain)(void *context);
    void (*release)(void *context);
    void (*wake)(void *context);
} MDNativeNoticeWake;
// Main only, before Protection's first receipt. Success returns +1 native
// broker ownership and retains wake until final Main destruction. Refusal before hook installation
// preserves the prior delegate and transfers no ongoing wake ownership. If SDK
// activation fails after installation, a closed inert broker/wake can remain
// retained by Protection until teardown; notifications stay unavailable.
void *MDNativeNoticeBrokerCreate(void *protection, MDNativeNoticeWake wake);
// Main only. Spans are borrowed for this call and copied before final gate.
// Title<=4096/body<=8192 bytes, UTF8 without NUL; scope is exact chat/group
// syntax. The original NotificationAction is retained in a native authorization
// outside Protection gate, checked there, and retained by accepted queued work.
// False transfers no ongoing caller scope or callback ownership. True means
// bounded native work accepted, not OS delivery. Captured account may be zero.
bool MDNativeNoticeBrokerPublish(void *protection, void *broker,
    MDPrivateScope original_action, uint64_t original_account_generation,
    const uint8_t *title, uint64_t title_length,
    const uint8_t *body, uint64_t body_length,
    const uint8_t *scope, uint64_t scope_length);
// Main only. Uses the same original action/account and actual private-consume
// Protection gate. Always zeros output before refusal; the returned fixed
// native intent is caller-owned and must be wiped after encoding/retirement.
bool MDNativeNoticeBrokerConsume(void *protection, void *broker,
    MDPrivateScope original_action, uint64_t original_account_generation,
    MDNoticeIntent *output);
// Retirement polls original authorizations only on Main and outside gates.
void MDNativeNoticeBrokerRetireInvalid(void *broker);
// Cheap synchronous thread-safe latch; actual OS/authorization teardown is
// queued to Main, outside Protection/controller gates.
void MDNativeNoticeBrokerClose(void *broker);
// Consumes one owned broker reference, closes admission synchronously, and
// transfers final close/release to Main. Never use the pointer after transfer.
void MDNativeNoticeBrokerRelease(void *broker);
#if defined(MD_NATIVE_TEST_PORTS) && defined(__OBJC__)
@class MDNativeNoticeBroker;
// Only the OS factory is controlled; real broker/gate logic remains active.
void MDNativeNoticeBrokerSetFactoryForTest(MDNativeNoticeBroker *(^factory)(void (^wake)(void)));
#endif
#ifdef __cplusplus
}
#endif
#endif
