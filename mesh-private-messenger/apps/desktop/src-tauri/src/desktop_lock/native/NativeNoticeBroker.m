#import "NativeNoticeBroker.h"
#include <stdatomic.h>

static atomic_uint outstandingAdds;
static BOOL reserveAdd(void) {
    unsigned count=atomic_load(&outstandingAdds);
    while(count<32) if(atomic_compare_exchange_weak(&outstandingAdds,&count,count+1))return YES;
    return NO;
}
static BOOL sameReceipt(MDNativeNoticeReceipt a,MDNativeNoticeReceipt b) {
    return a.revision==b.revision && a.window_id==b.window_id && a.page_id==b.page_id
        && a.account_generation==b.account_generation && a.has_owner==b.has_owner
        && a.verified_disabled==b.verified_disabled;
}
static BOOL validText(NSString *text,NSUInteger maximum) {
    return text && [text lengthOfBytesUsingEncoding:NSUTF8StringEncoding]<=maximum
        && [text rangeOfString:[NSString stringWithFormat:@"%C",(unichar)0]].location==NSNotFound;
}
static BOOL validScope(NSString *scope) {
    NSData *bytes=[scope dataUsingEncoding:NSUTF8StringEncoding];
    const uint8_t *p=bytes.bytes;NSUInteger start;
    if(bytes.length==37 && memcmp(p,"chat/",5)==0)start=5;
    else if(bytes.length==70 && memcmp(p,"group/",6)==0)start=6;
    else return NO;
    for(NSUInteger i=start;i<bytes.length;i++)if(!(p[i]>='0'&&p[i]<='9')&&!(p[i]>='a'&&p[i]<='f'))return NO;
    return YES;
}
@implementation MDNativeNoticeAuthorization { MDPrivateScope _scope; }
- (instancetype)initWithScope:(MDPrivateScope)scope {
    if(!NSThread.isMainThread || !scope.context || !scope.retain || !scope.release || !scope.current || !scope.window_id || !scope.page_id)return nil;
    if((self=[super init])){_scope=scope;_scope.retain(_scope.context);}return self;
}
- (void)dealloc { if(_scope.context)_scope.release(_scope.context); }
- (BOOL)matchesReceipt:(MDNativeNoticeReceipt)receipt { return _scope.window_id==receipt.window_id && _scope.page_id==receipt.page_id; }
- (BOOL)current { return _scope.current(_scope.context); }
@end
@interface MDNoticeJob : NSObject
@property(nonatomic,copy) NSString *identifier;
@property(nonatomic,copy,nullable) NSString *title;
@property(nonatomic,copy,nullable) NSString *body;
@property(nonatomic,copy,nullable) NSString *scope;
@property(nonatomic) MDNativeNoticeReceipt receipt;
@property(nonatomic) BOOL privateContent;
@property(nonatomic) BOOL started;
@property(nonatomic) BOOL completed;
@property(nonatomic) BOOL retired;
@property(nonatomic) BOOL releasedBudget;
@property(nonatomic) BOOL checking;
@property(nonatomic,strong,nullable) MDNativeNoticeAuthorization *authorization;
@property(nonatomic,strong,nullable) id<MDNoticePort> heldPort;
@end
@implementation MDNoticeJob @end
// Main owns at most32 active or draining OS submissions. Completion holds weak
// references, so a port retaining its completion cannot form an ownership cycle.
static NSMutableSet<MDNoticeJob *> *ownedAdds;
static void releaseJob(MDNoticeJob *job) {
    if(!job.releasedBudget){job.releasedBudget=YES;atomic_fetch_sub(&outstandingAdds,1);[ownedAdds removeObject:job];job.heldPort=nil;}
}

@interface MDSystemNoticePort : NSObject <MDNoticePort>
@property(nonatomic,strong) UNUserNotificationCenter *center;
@property(nonatomic,weak) id<UNUserNotificationCenterDelegate> owner;
@property(nonatomic,weak) id<UNUserNotificationCenterDelegate> previous;
@end
@implementation MDSystemNoticePort
- (BOOL)ownsDelegate { return _owner && _center.delegate==_owner; }
- (BOOL)activate {
    if(!_owner || _center.delegate!=_previous)return NO;
    _center.delegate=_owner;return self.ownsDelegate;
}
- (void)add:(UNNotificationRequest *)request completion:(void (^)(NSError *))completion { [_center addNotificationRequest:request withCompletionHandler:completion]; }
- (void)remove:(NSArray<NSString *> *)identifiers {
    [_center removePendingNotificationRequestsWithIdentifiers:identifiers];
    [_center removeDeliveredNotificationsWithIdentifiers:identifiers];
}
@end

@interface MDNativeNoticeBroker () {
    NSLock *_mutex;
    MDNativeNoticeReceipt _receipt;
    BOOL _closed;
    BOOL _invalidated;
    BOOL _activationAttempted;
    MDNativeNoticeIntents *_intents;
    id<MDNoticePort> _port;
    dispatch_block_t _wake;
    NSMutableDictionary<NSString *,MDNoticeJob *> *_jobs;
    NSMutableArray<NSString *> *_order;
}
- (instancetype)initWithPort:(id<MDNoticePort>)port wake:(dispatch_block_t)wake;
- (void)acceptReceipt:(MDNativeNoticeReceipt)receipt;
- (void)invalidateWindow:(uint64_t)window page:(uint64_t)page;
- (void)retireStaleJobs;
- (void)receiveIdentifier:(NSString *)identifier;
@end
static void retainBroker(void *raw) { CFRetain(raw); }
static void releaseBroker(void *raw) { CFRelease(raw); }
static void brokerReceipt(void *raw,MDNativeNoticeReceipt r) { [(__bridge MDNativeNoticeBroker *)raw acceptReceipt:r]; }
static void brokerInvalidate(void *raw,uint64_t window,uint64_t page) { [(__bridge MDNativeNoticeBroker *)raw invalidateWindow:window page:page]; }
static void brokerClose(void *raw) { [(__bridge MDNativeNoticeBroker *)raw close]; }

@implementation MDNativeNoticeBroker
+ (instancetype)prepareWithWake:(dispatch_block_t)wake {
    if(!NSThread.isMainThread)return nil;
    @try {
        MDSystemNoticePort *port=[MDSystemNoticePort new];port.center=UNUserNotificationCenter.currentNotificationCenter;
        MDNativeNoticeBroker *broker=[[self alloc] initWithPort:port wake:wake];
        if(!broker)return nil;
        port.previous=port.center.delegate;port.owner=broker;
        return broker;
    } @catch(__unused NSException *exception) { return nil; }
}
- (instancetype)initWithPort:(id<MDNoticePort>)port wake:(dispatch_block_t)wake {
    if(!NSThread.isMainThread)return nil;
    if((self=[super init])) {
        _intents=MDNativeNoticeIntentsCreate();if(!_intents)return nil;
        if(!ownedAdds)ownedAdds=[NSMutableSet new];
        _mutex=[NSLock new];_port=port;_wake=[wake copy];_jobs=[NSMutableDictionary new];_order=[NSMutableArray new];
    }
    return self;
}
- (BOOL)activate {
    if(!NSThread.isMainThread)return NO;
    [_mutex lock];BOOL admitted=!_closed && !_activationAttempted;
    if(admitted)_activationAttempted=YES;[_mutex unlock];
    if(!admitted || ![_port activate])return NO;
    [_mutex lock];BOOL open=!_closed;[_mutex unlock];return open && _port.ownsDelegate;
}
- (void)dealloc { for(MDNoticeJob *job in _jobs.allValues)[self retire:job];MDNativeNoticeIntentsDestroy(_intents); }
- (MDNoticeBrokerHooks)hooks { return (MDNoticeBrokerHooks){(__bridge void *)self,retainBroker,releaseBroker,brokerReceipt,brokerInvalidate,brokerClose}; }
- (void)acceptReceipt:(MDNativeNoticeReceipt)receipt {
    [_mutex lock];BOOL changed=!_closed && receipt.revision>_receipt.revision;
    if(changed) { _receipt=receipt;_invalidated=NO;MDNativeNoticeIntentsReceipt(_intents,receipt); }
    [_mutex unlock];
    if(changed)dispatch_async(dispatch_get_main_queue(),^{[self retireStaleJobs];});
}
- (void)invalidateWindow:(uint64_t)window page:(uint64_t)page {
    [_mutex lock];BOOL changed=!_closed && _receipt.window_id==window && _receipt.page_id==page;
    if(changed)_invalidated=YES;[_mutex unlock];
    if(changed)dispatch_async(dispatch_get_main_queue(),^{[self retireStaleJobs];});
}
- (BOOL)matches:(MDNativeNoticeReceipt)receipt {
    [_mutex lock];BOOL current=!_closed && !_invalidated && _receipt.revision!=0
        && _receipt.has_owner && sameReceipt(receipt,_receipt);[_mutex unlock];return current;
}
- (void)releaseBudget:(MDNoticeJob *)job {
    releaseJob(job);
}
- (void)retire:(MDNoticeJob *)job {
    job.retired=YES;
    [_jobs removeObjectForKey:job.identifier];[_order removeObject:job.identifier];
    job.title=nil;job.body=nil;job.scope=nil;job.authorization=nil;
    if(job.started)[_port remove:@[job.identifier]];else [self releaseBudget:job];
}
- (BOOL)fresh:(MDNoticeJob *)job {
    if(job.retired || job.checking)return NO;
    job.checking=YES;
    MDNativeNoticeAuthorization *held __attribute__((objc_precise_lifetime))=job.authorization;
    BOOL current=[held current];
    job.checking=NO;
    return current && !job.retired && _port.ownsDelegate && [self matches:job.receipt];
}
- (void)retireStaleJobs {
    NSAssert(NSThread.isMainThread,@"native notice Main");
    for(MDNoticeJob *job in _jobs.allValues)if(![self fresh:job])[self retire:job];
}
- (BOOL)publishTitle:(NSString *)title body:(NSString *)body scope:(NSString *)scope authorization:(MDNativeNoticeAuthorization *)authorization receipt:(MDNativeNoticeReceipt)receipt {
    if(!NSThread.isMainThread || !validText(title,4096) || !validText(body,8192) || !validScope(scope)
        || ![authorization matchesReceipt:receipt] || ![self matches:receipt] || !reserveAdd())return NO;
    MDNoticeJob *job=[MDNoticeJob new];job.identifier=NSUUID.UUID.UUIDString.lowercaseString;job.receipt=receipt;
    job.authorization=authorization;job.privateContent=receipt.verified_disabled;job.heldPort=_port;[ownedAdds addObject:job];
    if(job.privateContent){job.title=title;job.body=body;job.scope=scope;}
    // At most32 queued/adding jobs exist process-wide. Retained completed
    // routing records are trimmed to128 on Main, outside the Protection gate.
    _jobs[job.identifier]=job;[_order addObject:job.identifier];
    dispatch_async(dispatch_get_main_queue(),^{[self enqueue:job];});return YES;
}
- (void)enqueue:(MDNoticeJob *)job {
    if(![self fresh:job]){[self retire:job];return;}
    while(_jobs.count>128) {
        MDNoticeJob *old=nil;for(NSString *identifier in _order){MDNoticeJob *candidate=_jobs[identifier];if(candidate.completed){old=candidate;break;}}
        if(!old)break;[self retire:old];
    }
    UNMutableNotificationContent *content=[UNMutableNotificationContent new];
    content.title=job.privateContent?job.title:@"Morse";
    content.body=job.privateContent?job.body:@"New encrypted activity";
    content.userInfo=@{@"morseNotice":@"v1"};content.sound=UNNotificationSound.defaultSound;
    UNNotificationRequest *request=[UNNotificationRequest requestWithIdentifier:job.identifier content:content trigger:nil];
    if(![self fresh:job]){[self retire:job];return;}
    job.started=YES;
    __weak MDNativeNoticeBroker *weakSelf=self;
    __weak MDNoticeJob *weakJob=job;
    [job.heldPort add:request completion:^(NSError *error){dispatch_async(dispatch_get_main_queue(),^{
        MDNoticeJob *held=weakJob;if(!held || held.completed)return;
        MDNativeNoticeBroker *owner=weakSelf;id<MDNoticePort> port=held.heldPort;
        held.completed=YES;releaseJob(held);
        if(owner){if(error || ![owner fresh:held])[owner retire:held];}
        else [port remove:@[held.identifier]];
    });}];
    job.title=nil;job.body=nil;
}
- (void)receiveIdentifier:(NSString *)identifier {
    if(!NSThread.isMainThread || !_port.ownsDelegate)return;
    MDNoticeJob *job=_jobs[identifier];if(!job || job.retired)return;
    BOOL accepted;
    if(job.privateContent)accepted=MDNativeNoticeIntentsRecordPrivate(_intents,job.receipt.account_generation,job.scope.UTF8String,[job.scope lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
    else accepted=MDNativeNoticeIntentsRecordGeneric(_intents,job.receipt.account_generation);
    [self retire:job];
    if(accepted)_wake();
}
- (BOOL)consumeReceipt:(MDNativeNoticeReceipt)receipt output:(MDNoticeIntent *)output { return MDNativeNoticeIntentsConsume(_intents,receipt,output); }
- (void)retireInvalid { if(NSThread.isMainThread)[self retireStaleJobs]; }
- (void)close {
    [_mutex lock];_closed=YES;MDNativeNoticeIntentsClose(_intents);[_mutex unlock];
    dispatch_async(dispatch_get_main_queue(),^{[self retireStaleJobs];});
}
- (void)userNotificationCenter:(UNUserNotificationCenter *)center willPresentNotification:(UNNotification *)notification withCompletionHandler:(void (^)(UNNotificationPresentationOptions))completionHandler {
    (void)center;NSString *identifier=notification.request.identifier;
    dispatch_async(dispatch_get_main_queue(),^{MDNoticeJob *job=self->_jobs[identifier];completionHandler(job && [self fresh:job]?(UNNotificationPresentationOptionBanner|UNNotificationPresentationOptionSound):0);});
}
- (void)userNotificationCenter:(UNUserNotificationCenter *)center didReceiveNotificationResponse:(UNNotificationResponse *)response withCompletionHandler:(void (^)(void))completionHandler {
    (void)center;NSString *identifier=response.notification.request.identifier;
    dispatch_async(dispatch_get_main_queue(),^{[self receiveIdentifier:identifier];completionHandler();});
}
@end
