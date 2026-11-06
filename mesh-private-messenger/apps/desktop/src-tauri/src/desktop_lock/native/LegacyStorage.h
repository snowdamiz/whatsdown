#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import "PrivateJob.h"
NS_ASSUME_NONNULL_BEGIN
// Native-only OS adapter: the body is fixed and keys are derived by the native
// account/DB boundary, never accepted from IPC as script or filesystem input.
typedef void (^MDLegacyEvaluationReply)(id _Nullable value,NSError * _Nullable error);
typedef void (^MDLegacyEvaluate)(NSView *view,NSString *body,NSDictionary<NSString *,id> *arguments,MDLegacyEvaluationReply reply);
typedef void (^MDLegacyReply)(uint32_t status,const uint8_t * _Nullable bytes,NSUInteger length);
// Status is a closed native result: value=0, absent=1, removed=2,
// retired=3, unavailable/schema/OS failure=4. No OS error text crosses this port.
@interface MDLegacyStorage : NSObject
- (instancetype)init;
// begin/retirement and callbacks are main-thread operations. Evaluation does
// not retain the job through its completion block; the bounded registry does.
- (BOOL)beginView:(NSView *)view scope:(MDPrivateScope)scope key:(NSString *)key read:(BOOL)read
       admission:(BOOL (^)(void))admission reply:(MDLegacyReply)reply;
- (void)retireInvalid;
- (void)close;
#if defined(MD_NATIVE_TEST_PORTS)
// Controlled external WK operation/timeout scheduler only. The real registry,
// scope retention, callback and retirement logic remain unchanged.
- (instancetype)initWithEvaluate:(MDLegacyEvaluate)evaluate timeout:(void (^)(dispatch_block_t))timeout;
#endif
@end
NS_ASSUME_NONNULL_END
