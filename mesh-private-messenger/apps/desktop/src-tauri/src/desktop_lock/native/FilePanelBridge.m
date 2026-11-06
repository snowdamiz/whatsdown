#import "FilePanelBridge.h"
#import "NativeFilePanels.h"
#import "ProtectionBridge.h"
#import <stdatomic.h>
#include <string.h>

@interface MDPanelBudgetSlot : NSObject
+ (nullable instancetype)reserve;
@end
static NSLock *MDPanelBudgetLock;
static NSUInteger MDPanelBudgetCount;
@implementation MDPanelBudgetSlot
+ (instancetype)reserve {
    static dispatch_once_t once;dispatch_once(&once,^{ MDPanelBudgetLock=[NSLock new]; });
    [MDPanelBudgetLock lock];BOOL allowed=MDPanelBudgetCount<4;if (allowed) MDPanelBudgetCount++;[MDPanelBudgetLock unlock];
    return allowed?[MDPanelBudgetSlot new]:nil;
}
- (void)dealloc { [MDPanelBudgetLock lock];NSCAssert(MDPanelBudgetCount>0,@"global panel slot balance");MDPanelBudgetCount--;[MDPanelBudgetLock unlock]; }
@end
@class MDPanelBridgeJob;
@interface MDPanelCancelToken : NSObject {
    atomic_bool _cancelled;
}
@property(nonatomic,weak) MDPanelBridgeJob *job;
- (BOOL)cancelled;
- (void)cancel;
@end
@interface MDPanelBridgeRegistry : NSObject
@property(nonatomic,strong) NSLock *gate;
@property(nonatomic,strong) id protection;
@property(nonatomic,strong) NSMutableDictionary<NSValue *,MDPanelBridgeJob *> *jobs;
@property(nonatomic) BOOL closed;
#if defined(MD_NATIVE_TEST_PORTS)
@property(nonatomic,copy) id<MDFilePanelDriver> (^testDriver)(uint32_t,bool);
#endif
- (BOOL)isClosed;
- (nullable MDPanelBudgetSlot *)reserve;
- (void)remove:(MDPanelBridgeJob *)job;
@end
@interface MDPanelBridgeJob : NSObject
@property(nonatomic,strong) MDPanelBridgeRegistry *registry;
@property(nonatomic,strong) MDNativeFilePanel *panel;
@property(nonatomic,strong) MDPanelCancelToken *token;
@property(nonatomic,strong) MDPanelBudgetSlot *slot;
@property(nonatomic) MDPrivateScope scope;
@property(nonatomic) MDNativePanelCallbacks callbacks;
@property(nonatomic) BOOL bound,replied,drained,unavailable;
- (void)finish;
- (void)reply:(nullable NSArray<MDScopedFileURL *> *)selected;
@end
@implementation MDPanelCancelToken
- (instancetype)init { if ((self=[super init])) atomic_init(&_cancelled,false);return self; }
- (BOOL)cancelled { return atomic_load_explicit(&_cancelled,memory_order_acquire); }
- (void)cancel {
    if (atomic_exchange_explicit(&_cancelled,true,memory_order_acq_rel)) return;
    MDPanelBridgeJob *job=_job;
    dispatch_async(dispatch_get_main_queue(),^{ [job.panel cancel]; });
}
@end
@implementation MDPanelBridgeRegistry
- (instancetype)init { if ((self=[super init])) { _gate=[NSLock new];_jobs=[NSMutableDictionary new]; }return self; }
- (BOOL)isClosed { [_gate lock];BOOL closed=_closed;[_gate unlock];return closed; }
- (MDPanelBudgetSlot *)reserve {
    if (self.isClosed) return nil;
    MDPanelBudgetSlot *slot=[MDPanelBudgetSlot reserve];
    if (self.isClosed) return nil;
    return slot;
}
- (void)remove:(MDPanelBridgeJob *)job {
    NSAssert(NSThread.isMainThread,@"exact original native panel retirement");
    NSValue *key=[NSValue valueWithPointer:(__bridge const void *)job];
    if (_jobs[key]!=job) return;
    // Removal/destruction has no gate held. The process-wide slot remains
    // held by the exact job until all OS callback frames release that job.
    [_jobs removeObjectForKey:key];
}
@end
@implementation MDPanelBridgeJob
- (void)dealloc {
    if (_scope.context!=NULL) _scope.release(_scope.context);
    if (_callbacks.context!=NULL) _callbacks.release(_callbacks.context);
}
- (void)finish { if (_replied && _drained) [_registry remove:self]; }
- (void)reply:(NSArray<MDScopedFileURL *> *)selected {
    NSAssert(NSThread.isMainThread,@"original panel result and native URL custody");
    if (_replied) return;_replied=YES;
    if (!_bound) _drained=YES;
    if (_token.cancelled || _registry.isClosed) selected=nil;
    MDNativeFileSelection rows[10]={0};NSMutableArray<NSMutableData *> *buffers=[NSMutableArray new];
    uint32_t status=_unavailable?2:(selected==nil?1:0);NSUInteger count=selected.count;
    if (count>10 || (selected!=nil && count==0)) status=2;
    if (status==0) {
        for (NSUInteger i=0;i<count;i++) {
            MDScopedFileURL *value=selected[i];char path[4097];
            if (![value.url getFileSystemRepresentation:path maxLength:sizeof(path)]) { status=2;break; }
            NSMutableData *p=[[NSData dataWithBytes:path length:strlen(path)] mutableCopy];
            NSMutableData *name=[[value.filename dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
            NSMutableData *mime=[[value.mime dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
            if (p.length==0 || p.length>4096 || name.length==0 || name.length>255 || mime.length==0 || mime.length>127) { status=2;break; }
            [buffers addObjectsFromArray:@[p,name,mime]];
            rows[i]=(MDNativeFileSelection){(__bridge void *)value,p.bytes,p.length,name.bytes,name.length,mime.bytes,mime.length};
        }
    }
    @try { _callbacks.reply(_callbacks.context,status,status==0?rows:NULL,status==0?count:0); }
    @finally {
        for (NSMutableData *buffer in buffers) if (buffer.length) memset(buffer.mutableBytes,0,buffer.length);
        [self finish];
    }
}
@end
void *MDNativeFilePanelsCreate(void *protection) {
    if (protection==NULL) return NULL;
    MDPanelBridgeRegistry *registry=[MDPanelBridgeRegistry new];registry.protection=(__bridge id)protection;
    return (__bridge_retained void *)registry;
}
void MDNativeFilePanelsClose(void *raw) {
    if (raw==NULL) return;MDPanelBridgeRegistry *registry=(__bridge MDPanelBridgeRegistry *)raw;
    [registry.gate lock];BOOL first=!registry.closed;registry.closed=YES;[registry.gate unlock];
    if (first) dispatch_async(dispatch_get_main_queue(),^{
        NSArray<MDPanelBridgeJob *> *jobs=registry.jobs.allValues;
        for (MDPanelBridgeJob *job in jobs) [job.token cancel];
    });
}
void MDNativeFilePanelsRelease(void *raw) {
    if (raw==NULL) return;MDNativeFilePanelsClose(raw);
    dispatch_async(dispatch_get_main_queue(),^{ CFRelease(raw); });
}
static void *MDPanelStart(void *raw,MDPrivateScope scope,uint32_t purpose,NSString *name,NSString *mime,MDNativePanelCallbacks callbacks) {
    if (!NSThread.isMainThread || raw==NULL || scope.context==NULL || scope.retain==NULL || scope.release==NULL || scope.current==NULL ||
        callbacks.context==NULL || callbacks.retain==NULL || callbacks.release==NULL || callbacks.reply==NULL || purpose>2) return NULL;
    MDPanelBridgeRegistry *registry=(__bridge MDPanelBridgeRegistry *)raw;
    // A temporary scope retain spans this side-effectful check; no registry or
    // protection gate is held while policy/controller admission may retire.
    scope.retain(scope.context);BOOL admitted=NO;
    @try { admitted=!registry.isClosed && scope.current(scope.context); }
    @finally { scope.release(scope.context); }
    if (!admitted) return NULL;
    MDPanelBudgetSlot *slot=[registry reserve];if (slot==nil) return NULL;
    __attribute__((objc_precise_lifetime)) MDPanelBridgeJob *job=[MDPanelBridgeJob new];
    job.slot=slot;job.registry=registry;job.token=[MDPanelCancelToken new];job.token.job=job;
    scope.retain(scope.context);job.scope=scope;callbacks.retain(callbacks.context);job.callbacks=callbacks;
    registry.jobs[[NSValue valueWithPointer:(__bridge const void *)job]]=job;
    NSWindow *primary=(__bridge NSWindow *)MDNativeProtectionPrimary((__bridge void *)registry.protection,scope.window_id,scope.page_id);
    if (primary==nil) { job.replied=YES;job.drained=YES;[job finish];return NULL; }
    // Both blocks keep exact old registry/job/context. Nothing uses a label or
    // looks up a successor receiver after an asynchronous native boundary.
    __weak MDPanelBridgeJob *weakJob=job;
    job.panel=[[MDNativeFilePanel alloc] initWithPrimary:primary bind:^BOOL(NSWindow *window,dispatch_block_t retire) {
        MDPanelBridgeJob *held=weakJob;if (held==nil || held.token.cancelled || held.registry.isClosed) return NO;
        if (!held.scope.current(held.scope.context) || held.token.cancelled || held.registry.isClosed) return NO;
        BOOL bound=MDNativeProtectionBindAuxiliary((__bridge void *)held.registry.protection,held.scope.window_id,held.scope.page_id,(__bridge void *)window,retire);
        // Native bind can reenter lifecycle. Do not start OS work from a closed
        // original lease or leave an auxiliary registered after final refusal.
        if (bound && (held.token.cancelled || held.registry.isClosed || !held.scope.current(held.scope.context))) {
            MDNativeProtectionReleaseAuxiliary((__bridge void *)held.registry.protection,held.scope.window_id,held.scope.page_id,(__bridge void *)window);bound=NO;
        }
        held.bound=bound;return bound;
    } release:^(NSWindow *window) {
        MDPanelBridgeJob *held=weakJob;if (held==nil) return;
        MDNativeProtectionReleaseAuxiliary((__bridge void *)held.registry.protection,held.scope.window_id,held.scope.page_id,(__bridge void *)window);
        held.drained=YES;[held finish];
    }];
    // Return the cancel token before any OS panel construction. A request
    // broker registers its on_cancel callback in the same receiving-main turn,
    // before this queued block can run. Cancel-before-insertion is a tombstone.
    dispatch_async(dispatch_get_main_queue(),^{
        if (job.token.cancelled || job.registry.isClosed || !job.scope.current(job.scope.context) ||
            job.token.cancelled || job.registry.isClosed) {
            job.drained=YES;[job reply:nil];return;
        }
        BOOL started=NO;
        @try {
#if defined(MD_NATIVE_TEST_PORTS)
            if (registry.testDriver!=nil) {
                id<MDFilePanelDriver> driver=registry.testDriver(purpose,name!=nil);
                started=[job.panel beginTestDriver:driver purpose:(MDFilePurpose)purpose reply:^(NSArray *selected) { [job reply:selected]; }];
            } else
#endif
            {
                started=name==nil?[job.panel open:(MDFilePurpose)purpose reply:^(NSArray *selected) { [job reply:selected]; }]:
                    [job.panel saveName:name mime:mime reply:^(NSArray *selected) { [job reply:selected]; }];
            }
        } @catch (NSException *error) {
            (void)error;started=YES;job.unavailable=YES;[job.token cancel];[job reply:nil];
            // Unknown partially-started OS work retains its slot until genuine
            // drain. An exception never authorizes guessed early retirement.
        }
        if (!started) { job.unavailable=YES;job.drained=YES;[job reply:nil]; }
    });
    return (__bridge_retained void *)job.token;
}
void *MDNativeFilePanelsOpen(void *raw,MDPrivateScope scope,uint32_t purpose,MDNativePanelCallbacks callbacks) { return MDPanelStart(raw,scope,purpose,nil,nil,callbacks); }
void *MDNativeFilePanelsSave(void *raw,MDPrivateScope scope,const uint8_t *name,uint64_t nameLength,const uint8_t *mime,uint64_t mimeLength,MDNativePanelCallbacks callbacks) {
    if (name==NULL || nameLength==0 || nameLength>255 || mime==NULL || mimeLength==0 || mimeLength>127) return NULL;
    NSString *n=[[NSString alloc] initWithBytes:name length:(NSUInteger)nameLength encoding:NSUTF8StringEncoding];
    NSString *m=[[NSString alloc] initWithBytes:mime length:(NSUInteger)mimeLength encoding:NSUTF8StringEncoding];
    if (n==nil || m==nil) return NULL;return MDPanelStart(raw,scope,2,n,m,callbacks);
}
void MDNativeFilePanelCancel(void *raw) { if (raw!=NULL) [(__bridge MDPanelCancelToken *)raw cancel]; }
void MDNativeFilePanelTokenRelease(void *raw) { if (raw!=NULL) CFRelease(raw); }
void MDNativeFileURLRetain(void *raw) { if (raw!=NULL) CFRetain(raw); }
void MDNativeFileURLRelease(void *raw) { if (raw!=NULL) dispatch_async(dispatch_get_main_queue(),^{ CFRelease(raw); }); }

#if defined(MD_NATIVE_TEST_PORTS)
void MDNativeFilePanelsSetTestDriver(void *raw,id<MDFilePanelDriver> (^factory)(uint32_t,bool)) {
    NSCAssert(NSThread.isMainThread,@"fixed test OS driver");
    ((__bridge MDPanelBridgeRegistry *)raw).testDriver=factory;
}
#endif
