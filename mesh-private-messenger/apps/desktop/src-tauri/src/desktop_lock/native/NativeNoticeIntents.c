#include "NativeNoticeIntents.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct MDNativeNoticeIntents {
    pthread_mutex_t mutex;
    bool closed;
    MDNativeNoticeReceipt receipt;
    MDNoticeIntent pending;
};

static void erase(void *buffer, size_t length) {
    volatile unsigned char *p = buffer;
    while (length--) *p++ = 0;
}

static bool same_receipt(MDNativeNoticeReceipt a, MDNativeNoticeReceipt b) {
    return a.revision == b.revision && a.window_id == b.window_id && a.page_id == b.page_id
        && a.account_generation == b.account_generation && a.has_owner == b.has_owner
        && a.verified_disabled == b.verified_disabled;
}

static bool ready(const MDNativeNoticeIntents *s) {
    return !s->closed && s->receipt.revision != 0 && s->receipt.has_owner
        && s->receipt.window_id != 0 && s->receipt.page_id != 0;
}

static bool valid_scope(const char *p, size_t length) {
    if (!p) return false;
    size_t prefix;
    if (length == 37 && memcmp(p, "chat/", 5) == 0) prefix = 5;
    else if (length == 70 && memcmp(p, "group/", 6) == 0) prefix = 6;
    else return false;
    for (size_t i = prefix; i < length; i++)
        if (!(p[i] >= '0' && p[i] <= '9') && !(p[i] >= 'a' && p[i] <= 'f')) return false;
    return true;
}

MDNativeNoticeIntents *MDNativeNoticeIntentsCreate(void) {
    MDNativeNoticeIntents *s = calloc(1, sizeof(*s));
    if (s && pthread_mutex_init(&s->mutex, NULL) != 0) { free(s); return NULL; }
    return s;
}

void MDNativeNoticeIntentsDestroy(MDNativeNoticeIntents *s) {
    if (!s) return;
    // The owner retires all callbacks before destroying this native context.
    MDNativeNoticeIntentsClose(s);
    pthread_mutex_destroy(&s->mutex);
    erase(s, sizeof(*s));
    free(s);
}

void MDNativeNoticeIntentsReceipt(MDNativeNoticeIntents *s, MDNativeNoticeReceipt receipt) {
    pthread_mutex_lock(&s->mutex);
    if (!s->closed && receipt.revision > s->receipt.revision) {
        if (receipt.account_generation != s->receipt.account_generation) erase(&s->pending, sizeof(s->pending));
        s->receipt = receipt;
    }
    pthread_mutex_unlock(&s->mutex);
}

void MDNativeNoticeIntentsClose(MDNativeNoticeIntents *s) {
    pthread_mutex_lock(&s->mutex);
    s->closed = true;
    erase(&s->pending, sizeof(s->pending));
    erase(&s->receipt, sizeof(s->receipt));
    pthread_mutex_unlock(&s->mutex);
}

bool MDNativeNoticeIntentsRecordPrivate(MDNativeNoticeIntents *s, uint64_t generation,
                                      const char *scope, size_t length) {
    if (!valid_scope(scope, length)) return false;
    pthread_mutex_lock(&s->mutex);
    bool accepted = ready(s) && generation == s->receipt.account_generation;
    if (accepted) {
        erase(&s->pending, sizeof(s->pending));
        s->pending.kind = MDNoticeIntentScope;
        s->pending.scope_length = length;
        memcpy(s->pending.scope, scope, length);
    }
    pthread_mutex_unlock(&s->mutex);
    return accepted;
}

bool MDNativeNoticeIntentsRecordGeneric(MDNativeNoticeIntents *s, uint64_t generation) {
    pthread_mutex_lock(&s->mutex);
    bool accepted = ready(s) && generation == s->receipt.account_generation;
    if (accepted) {
        erase(&s->pending, sizeof(s->pending));
        s->pending.kind = MDNoticeIntentInbox;
    }
    pthread_mutex_unlock(&s->mutex);
    return accepted;
}

bool MDNativeNoticeIntentsConsume(MDNativeNoticeIntents *s, MDNativeNoticeReceipt receipt,
                                MDNoticeIntent *output) {
    erase(output, sizeof(*output));
    pthread_mutex_lock(&s->mutex);
    bool accepted = ready(s) && same_receipt(receipt, s->receipt);
    if (accepted) {
        *output = s->pending;
        erase(&s->pending, sizeof(s->pending));
    }
    pthread_mutex_unlock(&s->mutex);
    return accepted;
}
