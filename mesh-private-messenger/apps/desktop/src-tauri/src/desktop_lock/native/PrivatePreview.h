#ifndef MORSE_PRIVATE_PREVIEW_H
#define MORSE_PRIVATE_PREVIEW_H
#include <stdbool.h>
#include <stdint.h>
// Every non-null payload transfers one retained original Rust PreviewReply.
// Its bytes are immutable and valid until release; current uses the actual WK
// argument, original stored private scope and current native presentation.
typedef struct {
    void *context;
    void (*release)(void *context);
    bool (*current)(void *context,void *actual_webview);
    const uint8_t *bytes;
    uint64_t length;
    const uint8_t *mime;
    uint64_t mime_length;
} MDPreviewPayload;
typedef void (*MDPreviewComplete)(void *job,MDPreviewPayload payload);
typedef struct {
    void *context;
    void (*retain)(void *context);
    void (*release)(void *context);
    // Native-only start on the main thread. Must reply exactly once, even on
    // worker failure; retained job is opaque and cannot nominate another task.
    void (*start)(void *context,void *actual_webview,const uint8_t *handle,uint64_t length,void *job,MDPreviewComplete complete);
} MDPreviewProvider;
// Main-thread +1 WKWebViewConfiguration. Preserves default website data store;
// adds only this fixed native handler. No JS command accepts a configuration.
void *MDPrivatePreviewConfiguration(MDPreviewProvider provider);
#endif
#if defined(MD_NATIVE_TEST_PORTS) && defined(__OBJC__)
#import <WebKit/WebKit.h>
// Same handler/task/budget implementation, avoiding a real WK process in the
// deferred provider fixture. Configuration/default data store is SDK compile only.
id<WKURLSchemeHandler> MDPrivatePreviewHandlerForTest(MDPreviewProvider provider);
#endif
