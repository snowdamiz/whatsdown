#import "NativeNotifications.h"
#import "NativeNotificationsBridge.h"

void *MDNativeNotificationsCreate(void) {
    NSCAssert([NSThread isMainThread],@"native permission construction");
    // UNUserNotificationCenter can refuse unavailable application contexts.
    // No request/scope/reply has been transferred at this construction boundary.
    @try { return (__bridge_retained void *)[MDNativeNotifications new]; }
    @catch (__unused NSException *error) { return NULL; }
}
bool MDNativeNotificationsAuthorization(void *context,MDPrivateScope scope,bool request,
    void *reply_context,MDNotificationPermissionComplete reply) {
    NSCAssert([NSThread isMainThread],@"native permission receiving boundary");
    if (context==NULL || reply_context==NULL || reply==NULL) return false;
    MDNativeNotifications *service=(__bridge MDNativeNotifications *)context;
    return [service authorizationForScope:scope requestPermission:request reply:^(MDNotificationPermission result) {
        reply(reply_context,(uint32_t)result);
    }];
}
void MDNativeNotificationsRetireInvalid(void *context) {
    NSCAssert([NSThread isMainThread],@"native permission retirement boundary");
    if (context!=NULL) [(__bridge MDNativeNotifications *)context retireInvalid];
}
void MDNativeNotificationsClose(void *context) {
    NSCAssert([NSThread isMainThread],@"native permission closure boundary");
    if (context!=NULL) [(__bridge MDNativeNotifications *)context close];
}
void MDNativeNotificationsRelease(void *context) {
    if (context==NULL) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        MDNativeNotifications *service=(__bridge_transfer MDNativeNotifications *)context;
        [service close];
    });
}
#if defined(MD_NATIVE_TEST_PORTS)
void *MDNativeNotificationsRetainForTest(MDNativeNotifications *service) {
    NSCAssert([NSThread isMainThread],@"native permission fixture ownership");
    return (__bridge_retained void *)service;
}
#endif
