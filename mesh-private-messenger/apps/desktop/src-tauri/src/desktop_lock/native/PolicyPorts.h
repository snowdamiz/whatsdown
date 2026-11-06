#import "Policy.h"

NS_ASSUME_NONNULL_BEGIN
// Native IO boundary. Production uses SecItem calls; component tests record the
// exact dictionaries without touching any Keychain. Not an IPC/caller option.
@protocol MDKeychainAccess <NSObject>
- (int32_t)copyMatching:(NSDictionary *)query result:(id _Nullable * _Nonnull)object;
- (int32_t)add:(NSDictionary *)query;
- (int32_t)update:(NSDictionary *)query attributes:(NSDictionary *)attributes;
@end
@interface MDKeychainPolicyStorage (NativePorts)
- (nullable instancetype)initWithService:(NSString *)service directory:(NSURL *)directory nativeCalls:(id<MDKeychainAccess>)calls;
@end
NS_ASSUME_NONNULL_END
