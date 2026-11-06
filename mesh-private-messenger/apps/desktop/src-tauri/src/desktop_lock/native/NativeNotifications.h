#import <Foundation/Foundation.h>
#import <UserNotifications/UserNotifications.h>
#import "PrivateJob.h"

NS_ASSUME_NONNULL_BEGIN
typedef NS_ENUM(uint32_t, MDNotificationPermission) {
    MDNotificationPermissionAllowed = 0,
    MDNotificationPermissionDenied = 1,
    MDNotificationPermissionRetired = 2,
    MDNotificationPermissionUnavailable = 3,
};
typedef void (^MDNotificationPermissionReply)(MDNotificationPermission result);
typedef void (^MDNotificationReadSettings)(void (^reply)(UNAuthorizationStatus status));
typedef void (^MDNotificationRequestPermission)(void (^reply)(BOOL granted, BOOL failed));

// Main-thread native permission boundary. This answers only actual OS permission;
// the receiving layer separately checks account identity and stores local opt-in.
@interface MDNativeNotifications : NSObject
- (instancetype)init;
// YES transfers the original scope and exactly one deferred main-queue reply.
// NO starts no OS work and transfers no callback ownership.
- (BOOL)authorizationForScope:(MDPrivateScope)scope requestPermission:(BOOL)request
                        reply:(MDNotificationPermissionReply)reply;
- (void)retireInvalid;
- (void)close;
#if defined(MD_NATIVE_TEST_PORTS)
- (instancetype)initWithSettings:(MDNotificationReadSettings)settings
                         request:(MDNotificationRequestPermission)request
                         timeout:(void (^)(dispatch_block_t))timeout;
#endif
@end
NS_ASSUME_NONNULL_END
