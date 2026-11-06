#import "NativeNotifications.h"

// Main-queue ownership spans all service instances, including retired jobs
// whose actual OS request has not called back yet.
static NSUInteger MDNotificationPermissionReservations=0;
@class MDAuthorizationJob;
@interface MDNativeNotifications ()
@property(nonatomic,strong) NSMutableSet<MDAuthorizationJob *> *jobs;
@property(nonatomic,copy) MDNotificationReadSettings settings;
@property(nonatomic,copy) MDNotificationRequestPermission request;
@property(nonatomic,copy) void (^timeout)(dispatch_block_t);
@property(nonatomic) BOOL closed,retiring;
- (instancetype)initWithOSSettings:(MDNotificationReadSettings)settings
                           request:(MDNotificationRequestPermission)request
                           timeout:(void (^)(dispatch_block_t))timeout;
@end
@interface MDAuthorizationJob : NSObject
@property(nonatomic,weak) MDNativeNotifications *owner;
@property(nonatomic) MDPrivateScope scope;
@property(nonatomic,copy,nullable) MDNotificationPermissionReply reply;
@property(nonatomic) BOOL finished,reserved,wantsPermission;
@property(nonatomic) NSUInteger pendingCalls;
- (BOOL)current;
- (void)finish:(MDNotificationPermission)result;
- (void)readSettingsAfterPrompt:(BOOL)prompted;
- (void)requestPermission;
- (void)releaseDrainedReservation;
@end

@implementation MDAuthorizationJob
- (BOOL)current {
    MDNativeNotifications *owner=_owner;
    if (_finished || owner==nil || owner.closed) return NO;
    MDPrivateScope original=_scope;
    original.retain(original.context);
    BOOL valid=NO;
    @try { valid=original.current(original.context); }
    @finally { original.release(original.context); }
    return valid && !_finished && _owner==owner && !owner.closed;
}
- (void)releaseDrainedReservation {
    if (_reserved && _finished && _pendingCalls==0) {
        NSAssert(MDNotificationPermissionReservations>0,@"native permission reservation");
        _reserved=NO;
        MDNotificationPermissionReservations--;
    }
}
- (void)finish:(MDNotificationPermission)result {
    NSAssert([NSThread isMainThread],@"native permission completion");
    if (_finished) return;
    _finished=YES;
    [_owner.jobs removeObject:self];
    MDPrivateScope original=_scope;
    _scope=(MDPrivateScope){0};
    MDNotificationPermissionReply reply=_reply;
    _reply=nil;
    __weak MDNativeNotifications *weakOwner=_owner;
    [self releaseDrainedReservation];
    // A caller can retire from inside a registry callback. Both the external
    // reply and final scope release happen only after that stack unwinds.
    dispatch_async(dispatch_get_main_queue(), ^{
        MDNativeNotifications *owner=weakOwner;
        MDNotificationPermission value=result;
        if (value!=MDNotificationPermissionRetired &&
            (owner==nil || owner.closed || !original.current(original.context) || owner.closed))
            value=MDNotificationPermissionRetired;
        if (reply) reply(value);
        original.release(original.context);
    });
}
- (void)readSettingsAfterPrompt:(BOOL)prompted {
    if (![self current]) { [self finish:MDNotificationPermissionRetired]; return; }
    MDNotificationReadSettings settings=_owner.settings;
    _pendingCalls++;
    __block BOOL delivered=NO;
    settings(^(UNAuthorizationStatus status) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (delivered) return;
            delivered=YES;
            self.pendingCalls--;
            if (self.finished) { [self releaseDrainedReservation]; return; }
            if (![self current]) { [self finish:MDNotificationPermissionRetired]; return; }
            switch (status) {
                case UNAuthorizationStatusAuthorized:
                case UNAuthorizationStatusProvisional:
                    [self finish:MDNotificationPermissionAllowed]; break;
                case UNAuthorizationStatusDenied:
                    [self finish:MDNotificationPermissionDenied]; break;
                case UNAuthorizationStatusNotDetermined:
                    if (self.wantsPermission && !prompted) [self requestPermission];
                    else [self finish:MDNotificationPermissionDenied];
                    break;
                default: [self finish:MDNotificationPermissionUnavailable]; break;
            }
        });
    });
}
- (void)requestPermission {
    if (![self current]) { [self finish:MDNotificationPermissionRetired]; return; }
    MDNotificationRequestPermission request=_owner.request;
    _pendingCalls++;
    __block BOOL delivered=NO;
    request(^(BOOL granted,BOOL failed) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (delivered) return;
            delivered=YES;
            self.pendingCalls--;
            if (self.finished) { [self releaseDrainedReservation]; return; }
            if (![self current]) { [self finish:MDNotificationPermissionRetired]; return; }
            if (failed) [self finish:MDNotificationPermissionUnavailable];
            else if (!granted) [self finish:MDNotificationPermissionDenied];
            else [self readSettingsAfterPrompt:YES];
        });
    });
}
@end

@implementation MDNativeNotifications
- (instancetype)init {
    UNUserNotificationCenter *center=[UNUserNotificationCenter currentNotificationCenter];
    return [self initWithOSSettings:^(void (^reply)(UNAuthorizationStatus)) {
        [center getNotificationSettingsWithCompletionHandler:^(UNNotificationSettings *settings) {
            reply(settings.authorizationStatus);
        }];
    } request:^(void (^reply)(BOOL,BOOL)) {
        [center requestAuthorizationWithOptions:UNAuthorizationOptionAlert|UNAuthorizationOptionSound|UNAuthorizationOptionBadge
                             completionHandler:^(BOOL granted,NSError *error) { reply(granted,error!=nil); }];
    } timeout:^(dispatch_block_t work) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,30*NSEC_PER_SEC),dispatch_get_main_queue(),work);
    }];
}
- (instancetype)initWithOSSettings:(MDNotificationReadSettings)settings
                           request:(MDNotificationRequestPermission)request
                           timeout:(void (^)(dispatch_block_t))timeout {
    NSAssert([NSThread isMainThread],@"native permission owner");
    if ((self=[super init])) {
        _jobs=[NSMutableSet new]; _settings=[settings copy]; _request=[request copy]; _timeout=[timeout copy];
    }
    return self;
}
#if defined(MD_NATIVE_TEST_PORTS)
- (instancetype)initWithSettings:(MDNotificationReadSettings)settings
                         request:(MDNotificationRequestPermission)request
                         timeout:(void (^)(dispatch_block_t))timeout {
    return [self initWithOSSettings:settings request:request timeout:timeout];
}
#endif
- (BOOL)authorizationForScope:(MDPrivateScope)scope requestPermission:(BOOL)request
                        reply:(MDNotificationPermissionReply)reply {
    NSAssert([NSThread isMainThread],@"native permission admission");
    if (_closed || MDNotificationPermissionReservations>=4 || scope.context==NULL ||
        scope.retain==NULL || scope.release==NULL || scope.current==NULL ||
        scope.window_id==0 || scope.page_id==0 || reply==nil) return NO;
    MDAuthorizationJob *job=[MDAuthorizationJob new];
    MDNotificationPermissionReservations++;
    job.reserved=YES; job.owner=self; job.scope=scope; scope.retain(scope.context);
    job.wantsPermission=request; job.reply=reply;
    [_jobs addObject:job];
    __weak MDAuthorizationJob *weakJob=job;
    _timeout(^{ [weakJob finish:MDNotificationPermissionRetired]; });
    dispatch_async(dispatch_get_main_queue(), ^{ [job readSettingsAfterPrompt:NO]; });
    return YES;
}
- (void)retireInvalid {
    NSAssert([NSThread isMainThread],@"native permission retirement");
    if (_closed || _retiring) return;
    _retiring=YES;
    @try {
        for (MDAuthorizationJob *job in _jobs.allObjects)
            if (![job current]) [job finish:MDNotificationPermissionRetired];
    } @finally { _retiring=NO; }
}
- (void)close {
    NSAssert([NSThread isMainThread],@"native permission shutdown");
    _closed=YES;
    for (MDAuthorizationJob *job in _jobs.allObjects) [job finish:MDNotificationPermissionRetired];
}
- (void)dealloc { [self close]; }
@end
