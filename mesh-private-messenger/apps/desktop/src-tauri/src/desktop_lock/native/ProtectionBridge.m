#import "ProtectionBridge.h"
#import "Protection.h"
#import "LegacyStorage.h"

@interface MDNativeCallbackOwner : NSObject
@property(nonatomic) MDNativeCallbacks callbacks;
@end
@implementation MDNativeCallbackOwner
- (void)dealloc { if (_callbacks.release != NULL) _callbacks.release(_callbacks.context); }
@end
// Hook context release is always deferred, including deallocation from an
// outer recursive Protection callback. No root broker destructor runs in gate.
@interface MDNoticeHookOwner : NSObject
@property(nonatomic) MDNoticeBrokerHooks hooks;
@end
@implementation MDNoticeHookOwner
- (void)dealloc {
    MDNoticeBrokerHooks hooks=_hooks;
    if(hooks.release!=NULL)dispatch_async(dispatch_get_main_queue(),^{hooks.release(hooks.context);});
}
@end
@interface MDNativeProtectionContext : NSObject
@property(nonatomic, strong) NSRecursiveLock *gate;
@property(nonatomic, strong) MDNativeCallbackOwner *callbacks;
@property(nonatomic, strong) MDAuthRegistry *registry;
@property(nonatomic, strong) MDCoverAdapter *cover;
@property(nonatomic, strong) MDAppKitSurface *surface;
@property(nonatomic, strong) MDWindowLifecycle *lifecycle;
@property(nonatomic, weak) NSWindow *window;
@property(nonatomic, weak) NSView *webview;
@property(nonatomic) uint64_t windowID;
@property(nonatomic) uint64_t pageID;
@property(nonatomic) uint64_t revision;
@property(nonatomic) BOOL closed;
@property(nonatomic) BOOL bootFailed;
@property(nonatomic,strong) MDLegacyStorage *legacy;
@property(nonatomic,strong) MDNoticeHookOwner *notice;
@property(nonatomic) uint64_t noticeWindow,noticePage,noticeAccount;
@property(nonatomic) BOOL noticeHasOwner,noticePrivate;
// Fixed native OS operations. The isolated SDK fixture replaces these two
// operations before any copy; no script or IPC can supply either block.
@property(nonatomic, copy) dispatch_block_t copyClear;
@property(nonatomic, copy) BOOL (^copyWrite)(NSString *text);
@end
@implementation MDNativeProtectionContext
@end
// Receipt/owner refusal is immediate. Private-scope destruction waits until
// the native callback frame and any outer recursive gate have returned. Capture
// the original registry rather than resolving a newer context at teardown time.
static void MDLegacyRetireLater(MDLegacyStorage *legacy,BOOL close) {
    dispatch_async(dispatch_get_main_queue(),^{ if (close) [legacy close];else [legacy retireInvalid]; });
}
static MDNativeProtectionContext *MDProtection(void *raw) { return (__bridge MDNativeProtectionContext *)raw; }
static BOOL MDMatches(MDNativeProtectionContext *context, uint64_t window, uint64_t page) {
    return !context.closed && context.surface != nil && context.windowID == window && context.pageID == page;
}
void *MDNativeProtectionCreate(MDNativeCallbacks callbacks) {
    if (callbacks.context == NULL || callbacks.retain == NULL || callbacks.release == NULL ||
        callbacks.lifecycle == NULL || callbacks.auth_reply == NULL || callbacks.public_action == NULL) return NULL;
    @autoreleasepool {
        callbacks.retain(callbacks.context);
        MDNativeProtectionContext *context = [MDNativeProtectionContext new];
        context.gate = [NSRecursiveLock new];context.callbacks = [MDNativeCallbackOwner new];context.callbacks.callbacks = callbacks;
        context.registry = [[MDAuthRegistry alloc] initWithDispatch:MDMainDispatch() factory:^{ return [MDLocalAuthContext new]; }];
        context.cover = [[MDCoverAdapter alloc] initWithDispatch:MDMainDispatch()];
        context.legacy = [MDLegacyStorage new];
        context.copyClear = ^{ [NSPasteboard.generalPasteboard clearContents]; };
        context.copyWrite = ^BOOL(NSString *text) { return [NSPasteboard.generalPasteboard setString:text forType:NSPasteboardTypeString]; };
        return (__bridge_retained void *)context;
    }
}
bool MDNativeProtectionAttach(void *raw, void *windowRaw, void *webviewRaw, uint64_t windowID, uint64_t pageID) {
    if (raw == NULL || ![NSThread isMainThread] || windowID == 0 || pageID == 0) return false;
    MDNativeProtectionContext *context = MDProtection(raw);
    NSWindow *window = (__bridge NSWindow *)windowRaw; NSView *webview = (__bridge NSView *)webviewRaw;
    if (![window isKindOfClass:NSWindow.class] || ![webview isKindOfClass:NSView.class] || webview.window != window || webview.superview == nil) return false;
    [context.gate lock];
    if (context.closed || pageID <= context.pageID) { [context.gate unlock]; return false; }
    MDWindowLifecycle *oldLifecycle = context.lifecycle;MDLegacyStorage *legacy=context.legacy;
    if(context.surface!=nil && context.notice!=nil)
        context.notice.hooks.invalidate(context.notice.hooks.context,context.windowID,context.pageID);
    [context.registry cancelForSurface:context.surface];
    [oldLifecycle close];
    [context.surface retire];
    context.window = window;context.webview = webview;context.windowID = windowID;context.pageID = pageID;
    MDAppKitSurface *surface = [[MDAppKitSurface alloc] initWithWindow:window webview:webview];
    context.surface = surface;
    if (context.bootFailed) [surface setPublicStatus:@"Private messages are unavailable. Close the app and try again." unlock:nil cancel:nil];
    __weak MDNativeProtectionContext *weakContext = context;
    context.lifecycle = [[MDWindowLifecycle alloc] initWithSurface:surface registry:context.registry
        center:NSNotificationCenter.defaultCenter workspaceCenter:NSWorkspace.sharedWorkspace.notificationCenter
        application:NSApp workspace:NSWorkspace.sharedWorkspace event:^(MDLifecycleEvent event) {
            MDNativeProtectionContext *held = weakContext;
            [held.gate lock]; BOOL current = held != nil && MDMatches(held,windowID,pageID); [held.gate unlock];
            if (current) { MDNativeCallbacks target = held.callbacks.callbacks; target.lifecycle(target.context,windowID,pageID,(uint32_t)event); }
        }];
    [context.gate unlock];MDLegacyRetireLater(legacy,NO);return true;
}
bool MDNativeProtectionReceiver(void *raw, void *windowRaw, void *webviewRaw, uint64_t *windowID, uint64_t *pageID) {
    if (raw == NULL || ![NSThread isMainThread] || windowID == NULL || pageID == NULL) return false;
    MDNativeProtectionContext *context = MDProtection(raw);[context.gate lock];
    BOOL current = !context.closed && context.surface.current && context.window == (__bridge NSWindow *)windowRaw && context.webview == (__bridge NSView *)webviewRaw;
    if (current) { *windowID = context.windowID;*pageID = context.pageID; }
    [context.gate unlock];return current;
}
bool MDNativeProtectionPrivateReceiver(void *raw,void *webviewRaw,uint64_t *windowID,uint64_t *pageID) {
    if (raw==NULL || !NSThread.isMainThread || windowID==NULL || pageID==NULL) return false;
    MDNativeProtectionContext *context=MDProtection(raw);NSView *view=(__bridge NSView *)webviewRaw;
    [context.gate lock];
    BOOL current=!context.closed && !context.bootFailed && context.webview==view && view!=nil &&
        context.window==view.window && [context.surface permitsPrivateActionAtRevision:context.revision];
    if (current) { *windowID=context.windowID;*pageID=context.pageID; }
    [context.gate unlock];return current;
}
void MDNativeProtectionRetirePage(void *raw, uint64_t windowID, uint64_t pageID) {
    if (raw == NULL || ![NSThread isMainThread]) return;
    MDNativeProtectionContext *context = MDProtection(raw);[context.gate lock];
    BOOL current = MDMatches(context,windowID,pageID); MDAppKitSurface *surface = current ? context.surface : nil;
    MDWindowLifecycle *lifecycle = current ? context.lifecycle : nil;
    MDLegacyStorage *legacy=current ? context.legacy : nil;
    if(current && context.notice!=nil)context.notice.hooks.invalidate(context.notice.hooks.context,windowID,pageID);
    if (current) { context.surface = nil;context.lifecycle = nil;context.window = nil;context.webview = nil; }
    [context.gate unlock];
    if (!current) return;
    MDLegacyRetireLater(legacy,NO);
    [context.registry cancelForSurface:surface];
    [lifecycle close];[surface retire];
}
bool MDNativeProtectionReopen(void *raw) {
    if (raw == NULL || ![NSThread isMainThread]) return false;
    MDNativeProtectionContext *context = MDProtection(raw);[context.gate lock];
    BOOL shown = !context.closed && [context.surface reopenCovered];
    [context.gate unlock];return shown;
}
bool MDNativeProtectionFocusPublic(void *raw) {
    if (raw == NULL || ![NSThread isMainThread]) return false;
    MDNativeProtectionContext *context = MDProtection(raw);[context.gate lock];
    BOOL shown = !context.closed && [context.surface focusPublicCover];
    [context.gate unlock];return shown;
}
bool MDNativeProtectionForeground(void *raw) {
    if (raw == NULL || ![NSThread isMainThread]) return false;
    MDNativeProtectionContext *context = MDProtection(raw);[context.gate lock];
    BOOL foreground = !context.closed && context.surface.foreground;
    [context.gate unlock];return foreground;
}
bool MDNativeProtectionHide(void *raw,uint64_t windowID,uint64_t pageID) {
    if (raw == NULL || ![NSThread isMainThread]) return false;
    MDNativeProtectionContext *context = MDProtection(raw);[context.gate lock];
    BOOL current = MDMatches(context,windowID,pageID);
    if (current) [context.surface hideGroup];
    [context.gate unlock];return current;
}
bool MDNativeProtectionWindowAction(void *raw,uint64_t windowID,uint64_t pageID,uint64_t revision,uint32_t action) {
    if (raw == NULL || ![NSThread isMainThread]) return false;
    MDNativeProtectionContext *context = MDProtection(raw);[context.gate lock];
    BOOL allowed = MDMatches(context,windowID,pageID) && !context.bootFailed && context.revision == revision &&
        [context.surface performWindowAction:action revision:revision];
    [context.gate unlock];return allowed;
}
bool MDNativeProtectionCopyText(void *raw,MDPrivateScope scope,const uint8_t *bytes,uint64_t length) {
    if (raw == NULL || ![NSThread isMainThread] || scope.context == NULL || scope.current == NULL ||
        length > 1048576 || (length != 0 && bytes == NULL)) return false;
    NSString *text=[[NSString alloc] initWithBytes:bytes length:(NSUInteger)length encoding:NSUTF8StringEncoding];
    if (text == nil) return false;
    MDNativeProtectionContext *context=MDProtection(raw);[context.gate lock];
    // Receipt/revocation and this short synchronous OS publication have one
    // native ordering. No Core work, policy record read/write, or queued UI
    // runs inside the gate. The held lease checks its current native owner.
    // A completed explicit user copy is retained, matching the mobile policy.
    BOOL current=MDMatches(context,scope.window_id,scope.page_id) && !context.bootFailed && scope.current(scope.context);
    current=current && MDMatches(context,scope.window_id,scope.page_id) &&
        [context.surface permitsPrivateActionAtRevision:context.revision];
    BOOL copied=NO;
    if (current) {
        context.copyClear();
        // The OS call may reenter native lifecycle before the new value is
        // written. Recheck both the held lease and native owner/receipt.
        if (scope.current(scope.context) && MDMatches(context,scope.window_id,scope.page_id) &&
            [context.surface permitsPrivateActionAtRevision:context.revision]) {
            copied=context.copyWrite(text);
        }
    }
    [context.gate unlock];return copied;
}
static bool MDProtectionLegacy(void *raw,MDPrivateScope scope,const uint8_t *bytes,uint64_t length,bool read,bool cleanup,void *replyContext,MDLegacyResult reply) {
    if (raw==NULL || ![NSThread isMainThread] || replyContext==NULL || reply==NULL || bytes==NULL || length==0 || length>8192) return false;
    NSString *key=[[NSString alloc] initWithBytes:bytes length:(NSUInteger)length encoding:NSUTF8StringEncoding];
    if (key==nil) return false;
    MDNativeProtectionContext *context=MDProtection(raw);[context.gate lock];
    NSView *view=context.webview;
    __weak MDNativeProtectionContext *weakContext=context;
    BOOL (^admission)(void)=^BOOL {
        MDNativeProtectionContext *held=weakContext;if (held==nil) return NO;[held.gate lock];
        BOOL current=MDMatches(held,scope.window_id,scope.page_id) && !held.bootFailed && held.webview==view &&
            (cleanup || [held.surface permitsPrivateActionAtRevision:held.revision]);
        [held.gate unlock];
        // Native policy loss may synchronously publish/retire. Do not call or
        // release its context under this gate, nor poll it after cheap refusal.
        if (!current || scope.context==NULL || scope.current==NULL || !scope.current(scope.context)) return NO;
        [held.gate lock];
        current=MDMatches(held,scope.window_id,scope.page_id) && !held.bootFailed && held.webview==view &&
            (cleanup || [held.surface permitsPrivateActionAtRevision:held.revision]);
        [held.gate unlock];return current;
    };
    MDLegacyStorage *legacy=context.legacy;[context.gate unlock];
    return [legacy beginView:view scope:scope key:key read:read admission:admission reply:^(uint32_t status,const uint8_t *value,NSUInteger count) {
        reply(replyContext,status,value,(uint64_t)count);
    }];
}
bool MDNativeProtectionLegacy(void *raw,MDPrivateScope scope,const uint8_t *bytes,uint64_t length,bool read,void *replyContext,MDLegacyResult reply) {
    return MDProtectionLegacy(raw,scope,bytes,length,read,false,replyContext,reply);
}
bool MDNativeProtectionForgetLegacy(void *raw,MDPrivateScope cleanup,const uint8_t *bytes,uint64_t length,void *replyContext,MDLegacyResult reply) {
    return MDProtectionLegacy(raw,cleanup,bytes,length,false,true,replyContext,reply);
}
void *MDNativeProtectionPrimary(void *raw,uint64_t windowID,uint64_t pageID) {
    if (raw == NULL || ![NSThread isMainThread]) return NULL;
    MDNativeProtectionContext *context = MDProtection(raw);[context.gate lock];
    NSWindow *window = MDMatches(context,windowID,pageID) && !context.bootFailed && context.surface.current &&
        context.surface.foreground ? context.window : nil;
    [context.gate unlock];return (__bridge void *)window;
}
bool MDNativeProtectionBindAuxiliary(void *raw,uint64_t windowID,uint64_t pageID,void *windowRaw,void (^retire)(void)) {
    if (raw == NULL || ![NSThread isMainThread]) return false;
    NSWindow *window = (__bridge NSWindow *)windowRaw;
    if (![window isKindOfClass:NSWindow.class] || retire == nil) return false;
    MDNativeProtectionContext *context = MDProtection(raw);[context.gate lock];
    BOOL allowed = MDMatches(context,windowID,pageID) && !context.bootFailed &&
        [context.surface bindAuxiliaryWindow:window revision:context.revision retire:retire];
    [context.gate unlock];return allowed;
}
void MDNativeProtectionReleaseAuxiliary(void *raw,uint64_t windowID,uint64_t pageID,void *windowRaw) {
    if (raw == NULL || ![NSThread isMainThread]) return;
    MDNativeProtectionContext *context = MDProtection(raw);[context.gate lock];
    if (MDMatches(context,windowID,pageID)) [context.surface releaseAuxiliaryWindow:(__bridge NSWindow *)windowRaw];
    [context.gate unlock];
}
static NSString *MDStatus(uint32_t phase) {
    switch (phase) {
        case 0:return @"Starting private messages…";case 1:return @"Preparing private messages…";
        case 2:return @"Private messages locked";case 3:return @"Waiting for device authentication…";
        case 4:return @"Preparing private messages…";case 5:return @"Private messages";
        default:return @"Private messages are unavailable. Close the app and try again.";
    }
}
void MDNativeProtectionApply(void *raw,uint64_t revision,uint64_t windowID,uint64_t pageID,bool hasOwner,bool uncover,uint32_t phase,uint64_t sequence,uint64_t accountGeneration,bool noticePrivate) {
    if (raw == NULL || revision == 0) return;
    MDNativeProtectionContext *context = MDProtection(raw);[context.gate lock];
    if (context.closed || revision <= context.revision) { [context.gate unlock];return; }
    context.revision = revision;MDLegacyStorage *legacy=context.legacy;
    context.noticeWindow=windowID;context.noticePage=pageID;context.noticeAccount=accountGeneration;
    context.noticeHasOwner=hasOwner && MDMatches(context,windowID,pageID) && !context.bootFailed;
    context.noticePrivate=context.noticeHasOwner && noticePrivate;
    if(context.notice!=nil)context.notice.hooks.receipt(context.notice.hooks.context,
        (MDNativeNoticeReceipt){revision,windowID,pageID,accountGeneration,context.noticeHasOwner,context.noticePrivate});
    MDAppKitSurface *surface = hasOwner && MDMatches(context,windowID,pageID) ? context.surface : nil;
    [context.gate unlock];
    [context.cover applyRevision:revision surface:surface uncover:uncover];
    MDLegacyRetireLater(legacy,NO);
    MDMainDispatch()(^{
        [context.gate lock];
        if (!MDMatches(context,windowID,pageID) || context.revision != revision || context.surface != surface) { [context.gate unlock];return; }
        __weak MDNativeProtectionContext *weakContext = context;
        dispatch_block_t unlock = phase == 2 ? ^{
            MDNativeProtectionContext *held = weakContext;[held.gate lock];
            BOOL current = held != nil && MDMatches(held,windowID,pageID) && held.revision == revision && held.surface.foreground;
            [held.gate unlock];
            if (current) { MDNativeCallbacks target = held.callbacks.callbacks;target.public_action(target.context,windowID,pageID,revision,0); }
        } : nil;
        dispatch_block_t cancel = phase == 3 && sequence > 0 ? ^{
            MDNativeProtectionContext *held = weakContext;[held.gate lock];
            BOOL current = held != nil && MDMatches(held,windowID,pageID) && held.revision == revision;
            [held.gate unlock];
            if (current) { MDNativeCallbacks target = held.callbacks.callbacks;target.public_action(target.context,windowID,pageID,revision,1); }
        } : nil;
        [surface setPublicStatus:MDStatus(phase) unlock:unlock cancel:cancel];
        [context.gate unlock];
    });
}
bool MDNativeProtectionBegin(void *raw,uint64_t windowID,uint64_t pageID,uint64_t sequence) {
    if (raw == NULL || sequence == 0) return false;
    MDNativeProtectionContext *context = MDProtection(raw);[context.gate lock];
    MDAppKitSurface *surface = !context.bootFailed && MDMatches(context,windowID,pageID) ? context.surface : nil;
    [context.gate unlock];
    if (surface == nil) { [context.registry cancel:sequence];return false; }
    __weak MDNativeProtectionContext *weakContext = context;
    [context.registry begin:sequence surface:surface reply:^(MDAuthReply reply) {
        MDNativeProtectionContext *held = weakContext;
        if (held == nil) return;
        MDNativeCallbacks target = held.callbacks.callbacks;target.auth_reply(target.context,sequence,(uint32_t)reply);
    }];return true;
}
void MDNativeProtectionCancel(void *raw,uint64_t sequence) { if (raw != NULL) [MDProtection(raw).registry cancel:sequence]; }
void MDNativeProtectionBootFailed(void *raw) {
    if (raw == NULL) return;
    MDNativeProtectionContext *context = MDProtection(raw);[context.gate lock];
    if (context.closed || context.bootFailed) { [context.gate unlock];return; }
    context.bootFailed = YES;context.revision = UINT64_MAX;
    context.noticePrivate=NO;context.noticeHasOwner=NO;
    if(context.notice!=nil)context.notice.hooks.close(context.notice.hooks.context);
    MDAppKitSurface *surface = context.surface;MDLegacyStorage *legacy=context.legacy;[context.gate unlock];
    [context.registry close];
    [context.cover applyRevision:UINT64_MAX surface:surface uncover:NO];
    MDLegacyRetireLater(legacy,YES);
    MDMainDispatch()(^{
        [surface setPublicStatus:@"Private messages are unavailable. Close the app and try again." unlock:nil cancel:nil];
    });
}
void MDNativeProtectionClose(void *raw) {
    if (raw == NULL) return;
    MDNativeProtectionContext *context = MDProtection(raw);[context.gate lock];
    if (context.closed) { [context.gate unlock];return; }
    context.closed = YES;context.noticePrivate=NO;context.noticeHasOwner=NO;
    if(context.notice!=nil)context.notice.hooks.close(context.notice.hooks.context);
    MDAppKitSurface *surface = context.surface;MDWindowLifecycle *lifecycle = context.lifecycle;MDLegacyStorage *legacy=context.legacy;
    context.surface = nil;context.lifecycle = nil;context.window = nil;context.webview = nil;[context.gate unlock];
    [context.registry close];MDLegacyRetireLater(legacy,YES);
    MDMainDispatch()(^{ [lifecycle close];[surface retire]; });
}
void MDNativeProtectionRelease(void *raw) { if (raw != NULL) CFRelease(raw); }

// A native publisher is installed before the first accepted Presentation. It
// retains one original root broker; later registration cannot replay old state.
bool MDNativeProtectionInstallNoticeBroker(void *raw,MDNoticeBrokerHooks hooks) {
    if(raw==NULL || !NSThread.isMainThread || hooks.context==NULL || hooks.retain==NULL ||
       hooks.release==NULL || hooks.receipt==NULL || hooks.invalidate==NULL || hooks.close==NULL)return false;
    hooks.retain(hooks.context);
    MDNoticeHookOwner *owner=[MDNoticeHookOwner new];owner.hooks=hooks;
    MDNativeProtectionContext *context=MDProtection(raw);[context.gate lock];
    BOOL accepted=!context.closed && !context.bootFailed && context.revision==0 && context.notice==nil;
    if(accepted){context.notice=owner;hooks.receipt(hooks.context,(MDNativeNoticeReceipt){0});}
    [context.gate unlock];return accepted;
}
static MDNativeNoticeReceipt MDNoticeReceipt(MDNativeProtectionContext *context) {
    return(MDNativeNoticeReceipt){context.revision,context.noticeWindow,context.noticePage,
        context.noticeAccount,context.noticeHasOwner,context.noticePrivate};
}
static BOOL MDNoticeAdmitted(MDNativeProtectionContext *context,uint64_t window,uint64_t page,
    uint64_t account,MDNativeNoticeReceipt receipt,BOOL consume) {
    if(context.closed || context.bootFailed || context.notice==nil || receipt.revision==0 ||
       !receipt.has_owner || receipt.window_id!=window || receipt.page_id!=page ||
       receipt.account_generation!=account || !MDMatches(context,window,page))return NO;
    MDAppKitSurface *surface=context.surface;
    BOOL allowed=surface.current && (!consume || [surface permitsPrivateActionAtRevision:receipt.revision]);
    // Even a readonly SDK/test fact can reenter a restrictive transition.
    return allowed && !context.closed && !context.bootFailed && context.surface==surface &&
        MDMatches(context,window,page) && context.revision==receipt.revision &&
        context.noticeWindow==window && context.noticePage==page && context.noticeAccount==account && context.noticeHasOwner;
}
bool MDNativeProtectionPublishNotice(void *raw,uint64_t window,uint64_t page,uint64_t account,
    void *publication,MDNativeNoticePublish publish) {
    if(raw==NULL || !NSThread.isMainThread || publication==NULL || publish==NULL)return false;
    MDNativeProtectionContext *context=MDProtection(raw);[context.gate lock];
    MDNativeNoticeReceipt receipt=MDNoticeReceipt(context);
    BOOL accepted=MDNoticeAdmitted(context,window,page,account,receipt,NO) && publish(publication,receipt);
    [context.gate unlock];return accepted;
}
bool MDNativeProtectionConsumeNotice(void *raw,uint64_t window,uint64_t page,uint64_t account,
    void *consumption,MDNativeNoticeConsume consume) {
    if(raw==NULL || !NSThread.isMainThread || consumption==NULL || consume==NULL)return false;
    MDNativeProtectionContext *context=MDProtection(raw);[context.gate lock];
    MDNativeNoticeReceipt receipt=MDNoticeReceipt(context);
    BOOL accepted=MDNoticeAdmitted(context,window,page,account,receipt,YES) && consume(consumption,receipt);
    [context.gate unlock];return accepted;
}

void MDNativeProtectionDeferMain(void *work,void (*run)(void *work)) {
    if(work==NULL || run==NULL)return;
    dispatch_async(dispatch_get_main_queue(),^{run(work);});
}

bool MDNativeAuthenticationAvailable(void) {
    @autoreleasepool {
        LAContext *auth=[LAContext new];
        BOOL available=[auth canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:nil];
        [auth invalidate]; return available;
    }
}
bool MDNativeProtectionOpenPayment(void *raw,MDPrivateScope scope,const uint8_t *bytes,uint64_t length) {
    if (raw==NULL || !NSThread.isMainThread || scope.context==NULL || scope.current==NULL || bytes==NULL || length==0 || length>7100) return false;
    NSString *text=[[NSString alloc] initWithBytes:bytes length:(NSUInteger)length encoding:NSUTF8StringEncoding];
    NSURL *url=text==nil ? nil : [NSURL URLWithString:text];
    if (url==nil || !([url.scheme isEqualToString:@"lightning"] || [url.scheme isEqualToString:@"solana"])) return false;
    MDNativeProtectionContext *context=MDProtection(raw); [context.gate lock];
    BOOL current=MDMatches(context,scope.window_id,scope.page_id) && !context.bootFailed && scope.current(scope.context) &&
        [context.surface permitsPrivateActionAtRevision:context.revision];
    BOOL opened=current && [NSWorkspace.sharedWorkspace openURL:url];
    [context.gate unlock]; return opened;
}
