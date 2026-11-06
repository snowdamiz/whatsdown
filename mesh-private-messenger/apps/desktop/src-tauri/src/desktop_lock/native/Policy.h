#import <Foundation/Foundation.h>
#include <stdint.h>

NS_ASSUME_NONNULL_BEGIN
typedef NS_ENUM(uint32_t, MDPolicyState) {
    MDPolicyDisabled, MDPolicyEnablePending, MDPolicyEnabled, MDPolicyDisablePending
};
typedef struct {
    uint8_t install[16];
    uint64_t sequence;
    MDPolicyState policy;
} MDPolicyValue;
typedef NS_ENUM(int32_t, MDPolicyStatus) {
    MDPolicyOK, MDPolicyUnreadable, MDPolicyChanged, MDPolicyBackgroundRequired
};
@protocol MDPolicyStorage <NSObject>
- (MDPolicyStatus)readMarker:(NSData * _Nullable * _Nonnull)bytes;
- (MDPolicyStatus)createMarker:(NSData *)bytes;
- (MDPolicyStatus)readRecord:(NSData * _Nullable * _Nonnull)bytes;
- (MDPolicyStatus)createRecord:(NSData *)bytes;
- (MDPolicyStatus)updateRecord:(NSData *)bytes;
@end
@interface MDInstallationPolicy : NSObject
- (instancetype)initWithStorage:(id<MDPolicyStorage>)storage makeInstall:(NSUUID *(^)(void))makeInstall;
- (MDPolicyStatus)load:(MDPolicyValue *)record;
- (MDPolicyStatus)transition:(MDPolicyValue)previous desired:(MDPolicyState)desired result:(MDPolicyValue *)record;
@end

// Native storage is a separate installation namespace, never a Mesh/wallet
// alias. Construction and every operation must run off main. No UI is allowed.
@interface MDPolicyMarker : NSObject
- (nullable instancetype)initWithDirectory:(NSURL *)directory;
- (MDPolicyStatus)read:(NSData * _Nullable * _Nonnull)bytes;
- (MDPolicyStatus)create:(NSData *)bytes;
@end
@interface MDKeychainPolicyStorage : NSObject <MDPolicyStorage>
- (nullable instancetype)initWithService:(NSString *)service directory:(NSURL *)directory;
@end
NS_ASSUME_NONNULL_END
