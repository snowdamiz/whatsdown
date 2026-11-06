#import "Policy.h"

NS_ASSUME_NONNULL_BEGIN
typedef NS_ENUM(int32_t, MDProcessOwnerStatus) {
    MDProcessOwnerOK, MDProcessOwnerBusy, MDProcessOwnerUnreadable
};
// This app-lifetime guard must precede policy/Core/controller construction.
// Anchor storage is a separate data-protection Keychain service, never the
// installation policy record or a Mesh/wallet alias. Acquiring runs off main.
@interface MDProcessOwner : NSObject
+ (nullable instancetype)acquireInDirectory:(NSURL *)directory
                             anchorStorage:(id<MDPolicyStorage>)anchorStorage
                                    status:(MDProcessOwnerStatus *)status;
@property(nonatomic, readonly) BOOL current;
// Caller owns the returned CLOEXEC FD. Never reopens the directory path.
- (int)duplicateOwnedDirectory;
- (void)close;
#if defined(MD_OWNER_TEST_PORTS)
// Read-only kernel flag observation; absent from the product compilation.
- (BOOL)testDescriptorsCloseOnExec;
#endif
@end
NS_ASSUME_NONNULL_END
