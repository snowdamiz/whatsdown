#import "PrivatePreview.h"
#import <WebKit/WebKit.h>
#import <AppKit/AppKit.h>

// This process-wide budget includes cancelled workers and NSData retained by
// WebKit, not merely tasks still visible in one handler dictionary. It grants
// no private authority; original-scope admission remains in the Rust payload.
@interface MDPreviewSlot : NSObject
+ (nullable instancetype)reserve;
@end
static NSLock *MDBudgetLock;
static NSUInteger MDBudgetUsed;
@implementation MDPreviewSlot
+ (instancetype)reserve {
    static dispatch_once_t once;dispatch_once(&once,^{ MDBudgetLock=[NSLock new]; });
    [MDBudgetLock lock];BOOL allowed=MDBudgetUsed<4;if (allowed) MDBudgetUsed++;[MDBudgetLock unlock];
    return allowed?[MDPreviewSlot new]:nil;
}
- (void)dealloc { [MDBudgetLock lock];NSCAssert(MDBudgetUsed>0,@"preview reservation balance");MDBudgetUsed--;[MDBudgetLock unlock]; }
@end
@interface MDPreviewOwner : NSObject
@property(nonatomic) MDPreviewPayload payload;
@end
@implementation MDPreviewOwner
- (void)dealloc { if (_payload.context!=NULL && _payload.release!=NULL) _payload.release(_payload.context); }
@end
@class MDPreviewHandler;
@interface MDPreviewTask : NSObject
@property(nonatomic,strong,nullable) id<WKURLSchemeTask> task;
@property(nonatomic,strong) WKWebView *view;
@property(nonatomic,strong) MDPreviewSlot *slot;
@property(nonatomic,weak) MDPreviewHandler *handler;
@property(nonatomic,strong) NSValue *identity;
@property(nonatomic) BOOL stopped;
- (BOOL)current:(MDPreviewOwner *)payload;
- (void)stop;
- (void)fail;
- (void)complete:(MDPreviewOwner *)owner;
@end
@interface MDPreviewHandler : NSObject<WKURLSchemeHandler>
@property(nonatomic) MDPreviewProvider provider;
@property(nonatomic,strong) NSMutableDictionary<NSValue *,MDPreviewTask *> *tasks;
@end
static void MDPreviewDelivered(void *raw,MDPreviewPayload payload) {
    MDPreviewTask *job=(__bridge_transfer MDPreviewTask *)raw;
    MDPreviewOwner *owner=[MDPreviewOwner new];owner.payload=payload;
    dispatch_async(dispatch_get_main_queue(),^{ [job complete:owner]; });
}
@implementation MDPreviewTask
- (BOOL)current:(MDPreviewOwner *)owner {
    if (_stopped || _task==nil || _handler.tasks[_identity]!=self || owner.payload.context==NULL || owner.payload.current==NULL) return NO;
    // Strong local owner/view span policy admission, which may reenter task
    // stop, page retirement, successor construction or payload release.
    WKWebView *view=_view;BOOL current=owner.payload.current(owner.payload.context,(__bridge void *)view);
    return current && !_stopped && _task!=nil && _handler.tasks[_identity]==self && _view==view;
}
- (void)stop {
    _stopped=YES;_task=nil;
    MDPreviewHandler *handler=_handler;
    if (handler.tasks[_identity]==self) [handler.tasks removeObjectForKey:_identity];
}
- (void)fail {
    id<WKURLSchemeTask> task=_task;[self stop];
    if (task!=nil) [task didFailWithError:[NSError errorWithDomain:@"MorsePrivatePreview" code:1 userInfo:nil]];
}
- (void)complete:(MDPreviewOwner *)owner {
    NSAssert(NSThread.isMainThread,@"original WK scheme completion");
    if (_stopped) return;
    MDPreviewPayload payload=owner.payload;
    if (payload.bytes==NULL || payload.length==0 || payload.length>16777216 || payload.mime==NULL || payload.mime_length==0 || payload.mime_length>64 || ![self current:owner]) { [self fail];return; }
    NSString *mime=[[NSString alloc] initWithBytes:payload.mime length:(NSUInteger)payload.mime_length encoding:NSUTF8StringEncoding];
    if (![@[@"image/jpeg",@"image/png",@"image/webp",@"image/gif",@"image/avif",@"image/heic",@"image/heif"] containsObject:mime]) { [self fail];return; }
    MDPreviewSlot *slot=_slot;
    // No unowned second byte copy. NSData retains the immutable Rust reply and
    // reservation until WebKit releases this buffer; Rust then zeroizes it.
    NSData *data=[[NSData alloc] initWithBytesNoCopy:(void *)payload.bytes length:(NSUInteger)payload.length deallocator:^(void *bytes,NSUInteger length) { (void)bytes;(void)length;(void)owner;(void)slot; }];
    id<WKURLSchemeTask> task=_task;
    NSHTTPURLResponse *response=[[NSHTTPURLResponse alloc] initWithURL:task.request.URL statusCode:200 HTTPVersion:@"HTTP/1.1"
        headerFields:@{@"Content-Type":mime,@"Content-Length":[NSString stringWithFormat:@"%llu",(unsigned long long)payload.length],@"Cache-Control":@"no-store",@"X-Content-Type-Options":@"nosniff"}];
    if (![self current:owner]) { [self fail];return; }
    [task didReceiveResponse:response];
    if (![self current:owner]) { [self fail];return; }
    [task didReceiveData:data];
    if (![self current:owner]) { [self fail];return; }
    // Remove exact task identity before the final callback can reenter start.
    [self stop];[task didFinish];
}
@end
@implementation MDPreviewHandler
- (instancetype)init { if ((self=[super init])) _tasks=[NSMutableDictionary new];return self; }
- (void)dealloc { if (_provider.release!=NULL) _provider.release(_provider.context); }
- (void)webView:(WKWebView *)webView startURLSchemeTask:(id<WKURLSchemeTask>)task {
    NSAssert(NSThread.isMainThread,@"actual WK scheme receiver");
    NSValue *identity=[NSValue valueWithPointer:(__bridge const void *)task];
    if (_tasks[identity]!=nil) return;
    NSURLRequest *request=task.request;NSString *absolute=request.URL.absoluteString;
    NSURLComponents *url=[NSURLComponents componentsWithURL:request.URL resolvingAgainstBaseURL:NO];
    NSString *handle=url.path.length>1?[url.path substringFromIndex:1]:nil;
    NSUUID *uuid=handle.length==36?[[NSUUID alloc] initWithUUIDString:handle]:nil;
    BOOL valid=[request.HTTPMethod isEqual:@"GET"] && [url.scheme isEqual:@"morse-private"] && [url.host isEqual:@"preview"] &&
        url.user==nil && url.password==nil && url.port==nil && url.query==nil && url.fragment==nil && uuid!=nil &&
        [uuid.UUIDString.lowercaseString isEqual:handle] && [absolute isEqual:[@"morse-private://preview/" stringByAppendingString:handle]];
    MDPreviewSlot *slot=valid?[MDPreviewSlot reserve]:nil;
    if (!valid || slot==nil) { [task didFailWithError:[NSError errorWithDomain:@"MorsePrivatePreview" code:1 userInfo:nil]];return; }
    MDPreviewTask *job=[MDPreviewTask new];job.task=task;job.view=webView;job.handler=self;job.identity=identity;job.slot=slot;_tasks[identity]=job;
    __weak MDPreviewTask *weakJob=job;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,30*NSEC_PER_SEC),dispatch_get_main_queue(),^{ if (weakJob!=nil && !weakJob.stopped) [weakJob fail]; });
    NSData *bytes=[handle dataUsingEncoding:NSUTF8StringEncoding];
    _provider.start(_provider.context,(__bridge void *)webView,bytes.bytes,bytes.length,(__bridge_retained void *)job,MDPreviewDelivered);
}
- (void)webView:(WKWebView *)webView stopURLSchemeTask:(id<WKURLSchemeTask>)task {
    NSAssert(NSThread.isMainThread,@"actual WK scheme stop");
    NSValue *identity=[NSValue valueWithPointer:(__bridge const void *)task];MDPreviewTask *job=_tasks[identity];
    if (job.view==webView && job.task==task) [job stop];
}
@end
void *MDPrivatePreviewConfiguration(MDPreviewProvider provider) {
    if (!NSThread.isMainThread || provider.context==NULL || provider.retain==NULL || provider.release==NULL || provider.start==NULL) return NULL;
    provider.retain(provider.context);
    MDPreviewHandler *handler=[MDPreviewHandler new];handler.provider=provider;
    WKWebViewConfiguration *configuration=[WKWebViewConfiguration new];
    configuration.websiteDataStore=WKWebsiteDataStore.defaultDataStore;
    [configuration setURLSchemeHandler:handler forURLScheme:@"morse-private"];
    return (__bridge_retained void *)configuration;
}
#if defined(MD_NATIVE_TEST_PORTS)
id<WKURLSchemeHandler> MDPrivatePreviewHandlerForTest(MDPreviewProvider provider) {
    if (!NSThread.isMainThread || provider.context==NULL || provider.retain==NULL || provider.release==NULL || provider.start==NULL) return nil;
    provider.retain(provider.context);MDPreviewHandler *handler=[MDPreviewHandler new];handler.provider=provider;return handler;
}
#endif
