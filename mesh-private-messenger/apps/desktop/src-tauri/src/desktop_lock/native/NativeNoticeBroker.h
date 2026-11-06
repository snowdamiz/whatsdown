#import <Foundation/Foundation.h>
#import <UserNotifications/UserNotifications.h>
#import "NativeNoticeIntents.h"
#import "PrivateJob.h"

NS_ASSUME_NONNULL_BEGIN
@protocol MDNoticePort <NSObject>
@property(nonatomic, readonly) BOOL ownsDelegate;
- (BOOL)activate;
- (void)add:(UNNotificationRequest *)request completion:(void (^)(NSError *_Nullable))completion;
- (void)remove:(NSArray<NSString *> *)identifiers;
@end

// Construct and finally release on Main, outside every Protection gate. This
// holds the original native NotificationAction; current() may call policy code.
@interface MDNativeNoticeAuthorization : NSObject
- (nullable instancetype)initWithScope:(MDPrivateScope)scope;
- (BOOL)matchesReceipt:(MDNativeNoticeReceipt)receipt;
- (BOOL)current;
@end

@interface MDNativeNoticeBroker : NSObject <UNUserNotificationCenterDelegate>
// Preparation does not mutate the OS delegate. Attach Protection hooks first.
+ (nullable instancetype)prepareWithWake:(dispatch_block_t)wake;
// Main only, one attempt. A failed activation requires close, never a retry.
- (BOOL)activate;
- (MDNoticeBrokerHooks)hooks;
// Main only, inside the fixed native Protection publication callback. The
// receiving layer already checked original account/Core opt-in outside its gate.
// YES accepts bounded queued work, not OS delivery. All OS calls occur later.
- (BOOL)publishTitle:(NSString *)title body:(NSString *)body scope:(NSString *)scope
       authorization:(MDNativeNoticeAuthorization *)authorization receipt:(MDNativeNoticeReceipt)receipt;
// Only within the fixed native Protection consume callback; copies native data.
- (BOOL)consumeReceipt:(MDNativeNoticeReceipt)receipt output:(MDNoticeIntent *)output;
- (void)close;
// Main only; call after local notification opt-in changes too.
- (void)retireInvalid;
#if defined(MD_NATIVE_TEST_PORTS)
- (instancetype)initWithPort:(id<MDNoticePort>)port wake:(dispatch_block_t)wake;
- (void)receiveIdentifier:(NSString *)identifier;
#endif
@end
NS_ASSUME_NONNULL_END
