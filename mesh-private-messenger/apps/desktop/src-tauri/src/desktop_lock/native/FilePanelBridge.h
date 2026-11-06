#ifndef MORSE_FILE_PANEL_BRIDGE_H
#define MORSE_FILE_PANEL_BRIDGE_H
#include <stdbool.h>
#include <stdint.h>
#include "PrivateJob.h"
// All pointers are native-only. Result rows borrow the original scoped NSURL
// and bounded path/name/MIME bytes only during the callback. Rust retains the
// URL owner before copying and keeps it in ChosenSource/ChosenDestination.
typedef struct {
    void *owner;
    const uint8_t *path;uint64_t path_length;
    const uint8_t *name;uint64_t name_length;
    const uint8_t *mime;uint64_t mime_length;
} MDNativeFileSelection;
typedef struct {
    void *context;
    void (*retain)(void *context);
    void (*release)(void *context);
    // status0 selections,1 cancelled,2 unavailable. No raw OS error is exposed.
    void (*reply)(void *context,uint32_t status,const MDNativeFileSelection *rows,uint64_t count);
} MDNativePanelCallbacks;
void *MDNativeFilePanelsCreate(void *protection);
void MDNativeFilePanelsClose(void *registry);
void MDNativeFilePanelsRelease(void *registry);
// Main-thread preparation queues OS construction after the receiving turn.
// Register any native request on_cancel before returning from that turn.
// NULL means no accepted job/callback. Success transfers
// a +1 finite cancel token; callbacks and scope remain retained until OS drain.
// Sources0 attachment,1 avatar,2 backup. No raw path comes from a caller.
void *MDNativeFilePanelsOpen(void *registry,MDPrivateScope scope,uint32_t purpose,MDNativePanelCallbacks callbacks);
void *MDNativeFilePanelsSave(void *registry,MDPrivateScope scope,const uint8_t *name,uint64_t name_length,const uint8_t *mime,uint64_t mime_length,MDNativePanelCallbacks callbacks);
// Exact original job only; safe from a worker. Cancellation cannot free its
// reservation while the original OS driver is still draining.
void MDNativeFilePanelCancel(void *token);
void MDNativeFilePanelTokenRelease(void *token);
void MDNativeFileURLRetain(void *owner);
void MDNativeFileURLRelease(void *owner);
#if defined(MD_NATIVE_TEST_PORTS) && defined(__OBJC__)
#import "NativeFilePanels.h"
void MDNativeFilePanelsSetTestDriver(void *registry,id<MDFilePanelDriver> (^factory)(uint32_t purpose,bool save));
#endif
#endif
