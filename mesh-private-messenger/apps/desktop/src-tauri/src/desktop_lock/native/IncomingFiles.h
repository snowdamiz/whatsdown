#ifndef MORSE_INCOMING_FILES_H
#define MORSE_INCOMING_FILES_H
#include "FilePanelBridge.h"
// Native-only callbacks borrow selected NSURL custody during sources(). The
// receiver must retain each row.owner before returning or crossing an await.
typedef struct {
    const void *context;
    void (*retain)(const void *);
    void (*release)(const void *);
    bool (*sources)(const void *,const MDNativeFileSelection *,uint64_t);
    void (*dragging)(const void *,bool);
} MDNativeIncomingCallbacks;
// Main only; original actual WK/window, original private scope. Failure does
// not transfer ownership. Accepted +1 token is finite and must be released.
void *MDNativeIncomingSubscribe(void *protection,void *window,void *view,MDPrivateScope scope,MDNativeIncomingCallbacks callbacks);
// Synchronous close latch; monitor/scope/callback destruction is later Main.
void MDNativeIncomingClose(void *token);
void MDNativeIncomingRelease(void *token);
#if defined(MD_NATIVE_TEST_PORTS) && defined(__OBJC__)
#import <AppKit/AppKit.h>
// Replaces only the system pasteboard read. Native event/focus/ownership checks
// and actual NSURL custody are production code; no real clipboard is touched.
BOOL MDNativeIncomingPasteForTest(void *token,NSEvent *event,NSArray<NSURL *> *(^readURLs)(void));
NSView *MDNativeIncomingDropViewForTest(void *token);
BOOL MDNativeIncomingDropForTest(void *token,id<NSDraggingInfo> info,NSArray<NSURL *> *(^readURLs)(void));
#endif
#endif
