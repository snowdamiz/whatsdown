#import "LegacyStorage.h"
#import <WebKit/WebKit.h>
#include <string.h>

static const NSUInteger MDLegacyMaximumValue=16794632;
@class MDLegacyJob;
@interface MDLegacyStorage ()
@property(nonatomic,strong) NSMutableSet<MDLegacyJob *> *jobs;
@property(nonatomic,copy) MDLegacyEvaluate evaluate;
@property(nonatomic,copy) void (^timeout)(dispatch_block_t);
@property(nonatomic) BOOL closed,retiring;
- (instancetype)initWithOS:(MDLegacyEvaluate)evaluate timeout:(void (^)(dispatch_block_t))timeout;
@end
@interface MDLegacyJob : NSObject
@property(nonatomic,weak) MDLegacyStorage *storage;
@property(nonatomic) MDPrivateScope scope;
@property(nonatomic,strong,nullable) NSView *view;
@property(nonatomic,copy,nullable) BOOL (^admission)(void);
@property(nonatomic,copy,nullable) MDLegacyReply reply;
@property(nonatomic) BOOL read,finished;
- (BOOL)current;
- (void)finish:(uint32_t)status value:(nullable NSString *)value;
@end
@implementation MDLegacyJob
- (BOOL)current {
    MDLegacyStorage *storage=_storage;BOOL (^admission)(void)=_admission;
    if (_finished || storage==nil || storage.closed || admission==nil) return NO;
    // The callback can retire this job and release its stored scope. A separate
    // native hold spans that entire call, including its return continuation.
    MDPrivateScope temporary=_scope;temporary.retain(temporary.context);BOOL admitted=NO;
    @try { admitted=admission() && !_finished && _storage==storage && !storage.closed; }
    @finally { temporary.release(temporary.context); }
    return admitted && !_finished && _storage==storage && !storage.closed;
}
- (void)finish:(uint32_t)status value:(NSString *)value {
    NSAssert([NSThread isMainThread],@"native legacy completion");
    if (_finished) return;
    _finished=YES;[_storage.jobs removeObject:self];
    MDLegacyReply reply=_reply;_reply=nil;
    BOOL (^admission)(void)=_admission;_admission=nil;
    __attribute__((objc_precise_lifetime)) NSView *view=_view;_view=nil;
    MDPrivateScope scope=_scope;_scope=(MDPrivateScope){0};
    NSMutableData *bytes=nil;
    if (status==0) {
        if (value==nil || [value lengthOfBytesUsingEncoding:NSUTF8StringEncoding]>MDLegacyMaximumValue) status=4;
        else { bytes=[[value dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];if (bytes==nil) status=4; }
    }
    // Registry controls are retired before callback reentry, while immutable
    // original view/scope stay alive through drain. Recheck after conversion
    // and any ownership cleanup before publishing a private result.
    if (status<=2 && (admission==nil || !admission() || _storage==nil || _storage.closed)) { status=3;if (bytes.length) memset(bytes.mutableBytes,0,bytes.length);bytes=nil; }
    if (reply != nil) reply(status,bytes.bytes,bytes.length);
    if (bytes.length) memset(bytes.mutableBytes,0,bytes.length);
    if (scope.context != NULL && scope.release != NULL) scope.release(scope.context);
    (void)view;
}
@end
@implementation MDLegacyStorage
- (instancetype)init {
    return [self initWithOS:^(NSView *view,NSString *body,NSDictionary<NSString *,id> *arguments,MDLegacyEvaluationReply reply) {
        if (![view isKindOfClass:WKWebView.class]) { reply(nil,[NSError errorWithDomain:@"MorseLegacyUnavailable" code:1 userInfo:nil]);return; }
        [(WKWebView *)view callAsyncJavaScript:body arguments:arguments inFrame:nil
            inContentWorld:[WKContentWorld worldWithName:@"MorseNativePrivateStorage.v1"] completionHandler:reply];
    } timeout:^(dispatch_block_t work) { dispatch_after(dispatch_time(DISPATCH_TIME_NOW,30*NSEC_PER_SEC),dispatch_get_main_queue(),work); }];
}
- (instancetype)initWithOS:(MDLegacyEvaluate)evaluate timeout:(void (^)(dispatch_block_t))timeout {
    if ((self=[super init])) { _jobs=[NSMutableSet new];_evaluate=[evaluate copy];_timeout=[timeout copy]; }return self;
}
#if defined(MD_NATIVE_TEST_PORTS)
- (instancetype)initWithEvaluate:(MDLegacyEvaluate)evaluate timeout:(void (^)(dispatch_block_t))timeout {
    return [self initWithOS:evaluate timeout:timeout];
}
#endif
- (BOOL)beginView:(NSView *)view scope:(MDPrivateScope)scope key:(NSString *)key read:(BOOL)read
       admission:(BOOL (^)(void))admission reply:(MDLegacyReply)reply {
    NSAssert([NSThread isMainThread],@"native legacy admission");
    if (_closed || _jobs.count>=64 || scope.context==NULL || scope.retain==NULL || scope.release==NULL ||
        scope.current==NULL || view==nil || key.length==0 || key.length>8192 || admission==nil || reply==nil || !admission()) return NO;
    // Admission can synchronously retire/reenter this same registry.
    if (_closed || _jobs.count>=64) return NO;
    MDLegacyJob *job=[MDLegacyJob new];job.storage=self;job.scope=scope;scope.retain(scope.context);
    job.view=view;job.admission=admission;job.reply=reply;job.read=read;[_jobs addObject:job];
    __weak MDLegacyJob *weakJob=job;
    _timeout(^{ MDLegacyJob *held=weakJob;if (held != nil) [held finish:3 value:nil]; });
    if (![job current]) { [job finish:3 value:nil];return YES; }
    // Fixed script and separately serialized native-derived argument. A named
    // isolated world prevents page-world monkey-patching of Storage methods.
    NSString *body=read ? @"return window.localStorage.getItem(key);" : @"window.localStorage.removeItem(key); return null;";
    _evaluate(view,body,@{@"key":[key copy]},^(id value,NSError *error) {
        MDLegacyJob *held=weakJob;if (held==nil || held.finished) return;
        if (![held current]) { [held finish:3 value:nil];return; }
        if (error!=nil) { [held finish:4 value:nil];return; }
        if (held.read && [value isKindOfClass:NSString.class]) [held finish:0 value:value];
        else if (value==NSNull.null) [held finish:held.read?1:2 value:nil];
        else [held finish:4 value:nil];
    });
    return YES;
}
- (void)retireInvalid {
    NSAssert([NSThread isMainThread],@"native legacy retirement");
    if (_retiring) return;
    _retiring=YES;
    @try { for (MDLegacyJob *job in [_jobs copy]) if (![job current]) [job finish:3 value:nil]; }
    @finally { _retiring=NO; }
}
- (void)close {
    NSAssert([NSThread isMainThread],@"native legacy close");
    _closed=YES;
    for (MDLegacyJob *job in [_jobs copy]) [job finish:3 value:nil];
}
@end
