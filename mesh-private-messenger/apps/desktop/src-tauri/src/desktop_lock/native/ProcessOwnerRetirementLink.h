#import <Foundation/Foundation.h>

struct MeshNativeGeneration;
NS_ASSUME_NONNULL_BEGIN

// Native-only ownership, never a request handle or effect permit. One link can
// belong to one ProcessOwner registration. Bind while retaining this wrapper.
__attribute__((objc_subclassing_restricted))
@interface MDProcessOwnerRetirementLink : NSObject
- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;
// On success transfers the sole C owning reference and clears *generation.
// On failure the caller still owns it. The frozen ABI has no generation retain.
- (nullable instancetype)initTakingGeneration:(const struct MeshNativeGeneration *_Nullable *_Nonnull)generation;
@property(nonatomic, readonly) const struct MeshNativeGeneration *generation;
@end

NS_ASSUME_NONNULL_END
