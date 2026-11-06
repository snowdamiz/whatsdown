#ifndef MORSE_DESKTOP_PRIVATE_JOB_H
#define MORSE_DESKTOP_PRIVATE_JOB_H
#include <stdbool.h>
#include <stdint.h>
// Internal native port only. The receiving WKWebView and lease were captured
// before dispatch; neither identity comes from caller-owned metadata.
typedef struct {
    const void *context;
    void (*retain)(const void *);
    void (*release)(const void *);
    bool (*current)(const void *);
    uint64_t window_id;
    uint64_t page_id;
} MDPrivateScope;
#endif
