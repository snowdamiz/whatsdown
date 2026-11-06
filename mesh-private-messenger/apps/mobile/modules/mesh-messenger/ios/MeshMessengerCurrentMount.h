#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

// Native provenance only. This opaque snapshot does not grant protected access.
@interface MeshMessengerCurrentMountSnapshot : NSObject
- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;
- (BOOL)isCurrent;
@end

@interface MeshMessengerCurrentMount : NSObject
- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;
+ (nullable MeshMessengerCurrentMountSnapshot *)captureWithFactory:(NSObject *)factory
                                                            root:(UIView *)root
                                                           owner:(UIView *)owner
    NS_SWIFT_NAME(capture(factory:root:owner:));
@end

NS_ASSUME_NONNULL_END
