#ifndef MORSE_NATIVE_NOTIFICATIONS_BRIDGE_H
#define MORSE_NATIVE_NOTIFICATIONS_BRIDGE_H
#include "PrivateJob.h"
typedef void (*MDNotificationPermissionComplete)(void *reply_context,uint32_t status);
// Create/admit/retire/close are native main-thread operations. Release can run
// on any thread and transfers final closure/release to the main queue.
void *MDNativeNotificationsCreate(void);
bool MDNativeNotificationsAuthorization(void *context,MDPrivateScope scope,bool request,
    void *reply_context,MDNotificationPermissionComplete reply);
void MDNativeNotificationsRetireInvalid(void *context);
void MDNativeNotificationsClose(void *context);
void MDNativeNotificationsRelease(void *context);
#if defined(MD_NATIVE_TEST_PORTS) && defined(__OBJC__)
@class MDNativeNotifications;
void *MDNativeNotificationsRetainForTest(MDNativeNotifications *service);
#endif
#endif
