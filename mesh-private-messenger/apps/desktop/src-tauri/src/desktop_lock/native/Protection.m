#import "Protection.h"
#import <objc/runtime.h>

MDDispatch MDMainDispatch(void) {
    return ^(dispatch_block_t work) {
        if ([NSThread isMainThread]) work();
        else dispatch_async(dispatch_get_main_queue(), work);
    };
}

@implementation MDLocalAuthContext {
    LAContext *_context;
}
- (instancetype)init {
    if ((self = [super init])) {
        _context = [LAContext new];
        _context.touchIDAuthenticationAllowableReuseDuration = 0;
    }
    return self;
}
- (void)evaluate:(MDReply)reply {
    [_context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
        localizedReason:@"Unlock private messages" reply:^(BOOL success, NSError *error) {
            MDAuthReply result = MDAuthFailed;
            if (success) result = MDAuthApproved;
            else if ([error.domain isEqualToString:LAErrorDomain] &&
                (error.code == LAErrorUserCancel || error.code == LAErrorAppCancel || error.code == LAErrorSystemCancel))
                result = MDAuthCancelled;
            reply(result);
        }];
}
- (void)invalidate { [_context invalidate]; }
- (void)dealloc { [_context invalidate]; }
@end

@interface MDAuthEntry : NSObject
@property(nonatomic) uint64_t sequence;
@property(nonatomic, strong) id<MDProtectionSurface> surface;
@property(nonatomic, copy) MDReply reply;
@property(nonatomic, strong, nullable) id<MDAuthContext> context;
@end
@implementation MDAuthEntry
@end

@implementation MDAuthRegistry {
    NSRecursiveLock *_lock;
    MDDispatch _dispatch;
    MDContextFactory _factory;
    MDAuthEntry *_pending;
    uint64_t _retiredThrough;
    uint64_t _highestBegin;
    BOOL _closed;
}
- (instancetype)initWithDispatch:(MDDispatch)dispatch factory:(MDContextFactory)factory {
    if ((self = [super init])) {
        _lock = [NSRecursiveLock new]; _dispatch = [dispatch copy]; _factory = [factory copy];
    }
    return self;
}
- (void)begin:(uint64_t)sequence surface:(id<MDProtectionSurface>)surface reply:(MDReply)reply {
    [_lock lock];
    if (_closed || sequence == 0 || sequence <= _retiredThrough || sequence <= _highestBegin) {
        [_lock unlock]; return;
    }
    _highestBegin = sequence;
    MDAuthEntry *old = _pending;
    MDAuthEntry *entry = [MDAuthEntry new];
    entry.sequence = sequence; entry.surface = surface; entry.reply = reply;
    _pending = entry;
    [_lock unlock];
    _dispatch(^{
        [old.context invalidate];
        [self->_lock lock];
        BOOL admitted = !self->_closed && self->_pending == entry && entry.surface.current && entry.surface.foreground;
        if (!admitted && self->_pending == entry) {
            self->_pending = nil; self->_retiredThrough = MAX(self->_retiredThrough, sequence);
        }
        [self->_lock unlock];
        if (!admitted) return;
        // Allocation may reenter or race cancellation. No lock spans the factory.
        id<MDAuthContext> context = self->_factory();
        [self->_lock lock];
        if (self->_closed || self->_pending != entry || sequence <= self->_retiredThrough || !entry.surface.current || !entry.surface.foreground) {
            [self->_lock unlock]; [context invalidate]; return;
        }
        entry.context = context;
        if (context == nil) {
            self->_pending = nil; self->_retiredThrough = MAX(self->_retiredThrough, sequence);
            [self->_lock unlock]; entry.reply(MDAuthFailed); return;
        }
        // This is only the nonblocking SDK evaluation invocation on main. The
        // short recursive lock serializes cancel versus context insertion/begin;
        // it is never held while waiting for OS authentication or controller IO.
        __weak MDAuthRegistry *weakSelf = self;
        __weak MDAuthEntry *weakEntry = entry;
        __weak id<MDAuthContext> weakContext = context;
        [context evaluate:^(MDAuthReply result) {
            MDAuthRegistry *registry = weakSelf;
            MDAuthEntry *completed = weakEntry;
            id<MDAuthContext> completedContext = weakContext;
            if (registry == nil || completed == nil || completedContext == nil) return;
            registry->_dispatch(^{
                [registry->_lock lock];
                BOOL current = !registry->_closed && registry->_pending == completed &&
                    completed.context == completedContext && completed.surface.current && sequence > registry->_retiredThrough;
                if (current) {
                    registry->_pending = nil;
                    registry->_retiredThrough = MAX(registry->_retiredThrough, sequence);
                }
                [registry->_lock unlock];
                if (current) { [completedContext invalidate]; completed.reply(result); }
            });
        }];
        [_lock unlock];
    });
}
- (void)cancel:(uint64_t)sequence {
    [_lock lock];
    _retiredThrough = MAX(_retiredThrough, sequence);
    MDAuthEntry *old = _pending.sequence <= sequence ? _pending : nil;
    if (old != nil) _pending = nil;
    [_lock unlock];
    _dispatch(^{ [old.context invalidate]; });
}
- (void)cancelForSurface:(id<MDProtectionSurface>)surface {
    [_lock lock];
    MDAuthEntry *old = _pending.surface == surface ? _pending : nil;
    if (old != nil) { _pending = nil; _retiredThrough = MAX(_retiredThrough, old.sequence); }
    [_lock unlock];
    _dispatch(^{ [old.context invalidate]; });
}
- (void)close {
    [_lock lock]; _closed = YES;
    MDAuthEntry *old = _pending; _pending = nil;
    [_lock unlock];
    _dispatch(^{ [old.context invalidate]; });
}
@end

@implementation MDCoverAdapter {
    NSRecursiveLock *_lock;
    MDDispatch _dispatch;
    uint64_t _revision;
    id<MDProtectionSurface> _surface;
    NSMutableArray<id<MDProtectionSurface>> *_retired;
}
- (instancetype)initWithDispatch:(MDDispatch)dispatch {
    if ((self = [super init])) {
        _lock = [NSRecursiveLock new]; _dispatch = [dispatch copy]; _retired = [NSMutableArray new];
    }
    return self;
}
- (void)applyRevision:(uint64_t)revision surface:(id<MDProtectionSurface>)surface uncover:(BOOL)uncover {
    [_lock lock];
    if (revision == 0 || revision <= _revision) { [_lock unlock]; return; }
    _revision = revision;
    if (_surface != nil && _surface != surface) {
        if ([_surface respondsToSelector:@selector(recordRevision:uncover:)]) [_surface recordRevision:revision uncover:NO];
        [_retired addObject:_surface];
    }
    _surface = surface;
    if ([surface respondsToSelector:@selector(recordRevision:uncover:)]) [surface recordRevision:revision uncover:uncover];
    [_lock unlock];
    _dispatch(^{
        [self->_lock lock];
        if (self->_revision != revision) { [self->_lock unlock]; return; }
        NSArray<id<MDProtectionSurface>> *retired = [self->_retired copy];
        [self->_retired removeAllObjects];
        for (id<MDProtectionSurface> old in retired) [old retire];
        if (self->_revision == revision && self->_surface == surface) {
            if (uncover && surface.current && surface.foreground) {
                if ([surface respondsToSelector:@selector(uncoverRevision:)]) [surface uncoverRevision:revision];
                else [surface uncover];
                // A reentrant newer restrictive presentation must win too.
                if (self->_revision != revision || self->_surface != surface || !surface.current || !surface.foreground)
                    [surface cover];
            } else [surface cover];
        }
        [self->_lock unlock];
    });
}
@end

// Public native cover receives focus instead of a hidden private responder. It
// never forwards keyboard input back into the protected view's responder chain.
@interface MDLockedView : NSBox
@property(nonatomic, strong) NSTextField *status;
@property(nonatomic, strong) NSButton *unlockButton;
@property(nonatomic, strong) NSButton *cancelButton;
@property(nonatomic, copy) dispatch_block_t unlockAction;
@property(nonatomic, copy) dispatch_block_t cancelAction;
- (void)configure:(NSString *)status unlock:(dispatch_block_t)unlock cancel:(dispatch_block_t)cancel;
@end
@implementation MDLockedView
- (BOOL)acceptsFirstResponder { return YES; }
- (instancetype)initWithFrame:(NSRect)frame {
    if ((self = [super initWithFrame:frame])) {
        _status = [NSTextField labelWithString:@"Starting private messages…"];
        _status.translatesAutoresizingMaskIntoConstraints = NO;
        _unlockButton = [NSButton buttonWithTitle:@"Unlock with device authentication" target:self action:@selector(unlock:)];
        _cancelButton = [NSButton buttonWithTitle:@"Cancel" target:self action:@selector(cancel:)];
        _unlockButton.translatesAutoresizingMaskIntoConstraints = NO;
        _cancelButton.translatesAutoresizingMaskIntoConstraints = NO;
        _unlockButton.hidden = YES; _cancelButton.hidden = YES;
        [self addSubview:_status]; [self addSubview:_unlockButton]; [self addSubview:_cancelButton];
        [NSLayoutConstraint activateConstraints:@[
            [_status.centerXAnchor constraintEqualToAnchor:self.centerXAnchor],
            [_status.centerYAnchor constraintEqualToAnchor:self.centerYAnchor constant:-24],
            [_unlockButton.centerXAnchor constraintEqualToAnchor:self.centerXAnchor],
            [_unlockButton.topAnchor constraintEqualToAnchor:_status.bottomAnchor constant:16],
            [_cancelButton.centerXAnchor constraintEqualToAnchor:self.centerXAnchor],
            [_cancelButton.topAnchor constraintEqualToAnchor:_unlockButton.bottomAnchor constant:12]
        ]];
    }
    return self;
}
- (void)configure:(NSString *)status unlock:(dispatch_block_t)unlock cancel:(dispatch_block_t)cancel {
    _status.stringValue = status; _unlockAction = [unlock copy]; _cancelAction = [cancel copy];
    _unlockButton.hidden = unlock == nil; _unlockButton.enabled = unlock != nil;
    _cancelButton.hidden = cancel == nil; _cancelButton.enabled = cancel != nil;
}
- (void)unlock:(id)sender { (void)sender; if (_unlockAction != nil) _unlockAction(); }
- (void)cancel:(id)sender { (void)sender; if (_cancelAction != nil) _cancelAction(); }
- (void)keyDown:(NSEvent *)event {
    // Never advance focus into the private responder chain. Native public
    // controls work while the WKWebView remains hidden and AX-inaccessible.
    if (event.keyCode == 53) { [self cancel:nil]; return; }
    if (event.keyCode == 36 || event.keyCode == 76) { [self unlock:nil]; return; }
    if (event.keyCode == 48) {
        NSView *target = !_unlockButton.hidden ? _unlockButton : (!_cancelButton.hidden ? _cancelButton : self);
        (void)[self.window makeFirstResponder:target];
    }
}
- (void)keyUp:(NSEvent *)event { (void)event; }
@end

static NSString *const MDGroupFocusChanged = @"MorsePrivateGroupFocusChanged";
static NSString *const MDGroupHidden = @"MorsePrivateGroupHidden";
static NSString *const MDGroupUnavailable = @"MorsePrivateGroupUnavailable";
static const void *MDGroupOwnerKey = &MDGroupOwnerKey;
static const void *MDOriginalWindowMenuKey = &MDOriginalWindowMenuKey;
@interface MDGroupOwner : NSObject
@property(nonatomic, weak) MDAppKitSurface *surface;
@end
@implementation MDGroupOwner
@end
@interface MDAuxiliaryWindow : NSObject
@property(nonatomic, strong) NSWindow *window;
@property(nonatomic, copy) dispatch_block_t retire;
@end
@implementation MDAuxiliaryWindow
@end
@interface MDAppKitSurface () <NSWindowDelegate>
- (void)hideGroupNotifying:(BOOL)notify;
- (void)coverNotifying:(BOOL)notify;
- (instancetype)initWithWindow:(NSWindow *)window webview:(NSView *)webview observedForeground:(BOOL (^)(NSWindow *window))observation;
@end
@implementation MDAppKitSurface {
    __weak NSWindow *_window;
    __weak NSView *_webview;
    __weak NSView *_parent;
    MDLockedView *_cover;
    NSWindow *_publicWindow;
    NSMutableArray<MDAuxiliaryWindow *> *_auxiliaries;
    NSLock *_receiptLock;
    uint64_t _receiptRevision;
    BOOL _receiptUncover;
    BOOL (^_observedForeground)(NSWindow *window);
    BOOL _retired, _covered, _unavailable, _exchange, _wantedVisible, _wasExcluded;
}
- (instancetype)initWithWindow:(NSWindow *)window webview:(NSView *)webview {
    return [self initWithWindow:window webview:webview observedForeground:^BOOL(NSWindow *candidate) {
        return NSApp.active && candidate.keyWindow;
    }];
}
#if defined(MD_NATIVE_TEST_PORTS)
- (instancetype)initWithWindow:(NSWindow *)window webview:(NSView *)webview testForegroundObservation:(BOOL (^)(NSWindow *window))observation {
    return [self initWithWindow:window webview:webview observedForeground:observation];
}
#endif
- (instancetype)initWithWindow:(NSWindow *)window webview:(NSView *)webview observedForeground:(BOOL (^)(NSWindow *window))observation {
    NSParameterAssert([NSThread isMainThread]);
    NSParameterAssert(window != nil && webview != nil && webview.window == window && webview.superview != nil);
    if ((self = [super init])) {
        _window = window;_webview = webview;_parent = webview.superview;
        NSNumber *originalMenu = objc_getAssociatedObject(window,MDOriginalWindowMenuKey);
        if (originalMenu == nil) {
            originalMenu = @(window.excludedFromWindowsMenu);
            objc_setAssociatedObject(window,MDOriginalWindowMenuKey,originalMenu,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
        _wasExcluded = originalMenu.boolValue;
        _auxiliaries = [NSMutableArray new];
        _receiptLock = [NSLock new];
        _observedForeground = [observation copy];
        _publicWindow = [[NSWindow alloc] initWithContentRect:[window contentRectForFrameRect:window.frame]
            styleMask:NSWindowStyleMaskTitled|NSWindowStyleMaskClosable|NSWindowStyleMaskMiniaturizable|NSWindowStyleMaskResizable
            backing:NSBackingStoreBuffered defer:NO];
        _publicWindow.releasedWhenClosed = NO;_publicWindow.title = window.title;_publicWindow.minSize = window.minSize;
        _publicWindow.delegate = self;_publicWindow.sharingType = NSWindowSharingNone;
        _cover = [[MDLockedView alloc] initWithFrame:_publicWindow.contentView.bounds];
        _cover.boxType = NSBoxCustom;_cover.borderWidth = 0;_cover.titlePosition = NSNoTitle;
        _cover.fillColor = NSColor.windowBackgroundColor;_cover.autoresizingMask = NSViewWidthSizable|NSViewHeightSizable;
        _cover.accessibilityElement = YES;_cover.accessibilityRole = NSAccessibilityGroupRole;
        _cover.accessibilityLabel = @"Private messages locked";_publicWindow.contentView = _cover;
        MDGroupOwner *owner = [MDGroupOwner new];owner.surface = self;
        objc_setAssociatedObject(window,MDGroupOwnerKey,owner,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(webview,MDGroupOwnerKey,owner,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [self cover];
    }return self;
}
- (NSWindow *)publicWindow { return _publicWindow; }
- (id)windowIdentity { return _window ?: self; }
- (BOOL)current {
    MDGroupOwner *owner = objc_getAssociatedObject(_window,MDGroupOwnerKey);
    MDGroupOwner *viewOwner = objc_getAssociatedObject(_webview,MDGroupOwnerKey);
    return !_retired && owner.surface == self && viewOwner.surface == self && _window != nil && _webview != nil && _parent != nil &&
        _webview.window == _window && _webview.superview == _parent;
}
- (BOOL)ownsWindow:(id)window {
    if (!self.current) return NO;
    if (window == _window || window == _publicWindow) return YES;
    for (MDAuxiliaryWindow *entry in _auxiliaries) if (entry.window == window) return YES;
    return NO;
}
- (BOOL)exchangingWindows { return _exchange; }
- (void)recordRevision:(uint64_t)revision uncover:(BOOL)uncover {
    [_receiptLock lock];
    if (revision > _receiptRevision) { _receiptRevision = revision;_receiptUncover = uncover; }
    [_receiptLock unlock];
}
- (BOOL)permitsRevision:(uint64_t)revision {
    [_receiptLock lock];BOOL permitted = revision != 0 && revision == _receiptRevision && _receiptUncover;[_receiptLock unlock];
    return permitted;
}
- (void)denyReceipt {
    [_receiptLock lock];_receiptUncover = NO;[_receiptLock unlock];
}
- (BOOL)eligibleRevision:(uint64_t)revision { return self.current && !_unavailable && [self permitsRevision:revision] && self.foreground; }
- (BOOL)foreground {
    if (!self.current || _unavailable) return NO;
    if (_covered) return _publicWindow.visible && !_publicWindow.miniaturized && _observedForeground(_publicWindow);
    if (_window.visible && !_window.miniaturized && _observedForeground(_window)) return YES;
    for (MDAuxiliaryWindow *entry in _auxiliaries)
        if (entry.window.visible && !entry.window.miniaturized && _observedForeground(entry.window)) return YES;
    return NO;
}
- (void)retireAuxiliaries {
    NSArray<MDAuxiliaryWindow *> *retired = [_auxiliaries copy];[_auxiliaries removeAllObjects];
    for (MDAuxiliaryWindow *entry in retired) {
        entry.window.accessibilityHidden = YES;[entry.window orderOut:nil];entry.retire();
    }
}
- (BOOL)bindAuxiliaryWindow:(NSWindow *)window revision:(uint64_t)revision retire:(dispatch_block_t)retire {
    NSAssert([NSThread isMainThread],@"native auxiliary admission");
    if (!self.current || _covered || _unavailable || _exchange || !self.foreground || window == _window ||
        window == _publicWindow || retire == nil || ![self permitsRevision:revision]) return NO;
    if (objc_getAssociatedObject(window,MDGroupOwnerKey) != nil) return NO;
    for (MDAuxiliaryWindow *entry in _auxiliaries) if (entry.window == window) return NO;
    MDGroupOwner *owner = [MDGroupOwner new];owner.surface = self;
    objc_setAssociatedObject(window,MDGroupOwnerKey,owner,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    MDAuxiliaryWindow *entry = [MDAuxiliaryWindow new];entry.window = window;entry.retire = retire;[_auxiliaries addObject:entry];return YES;
}
- (void)releaseAuxiliaryWindow:(NSWindow *)window {
    NSAssert([NSThread isMainThread],@"native auxiliary release");
    NSIndexSet *indices = [_auxiliaries indexesOfObjectsPassingTest:^BOOL(MDAuxiliaryWindow *entry,NSUInteger index,BOOL *stop) {
        (void)index;(void)stop;return entry.window == window;
    }];[_auxiliaries removeObjectsAtIndexes:indices];
}
- (BOOL)performWindowAction:(uint32_t)action revision:(uint64_t)revision {
    NSAssert([NSThread isMainThread],@"native window action");
    if (_covered || _exchange || ![self eligibleRevision:revision]) return NO;
    switch (action) {
        case 0: [_window miniaturize:nil];return YES;
        case 1: [_window zoom:nil];return YES;
        case 2: [self hideGroup];return YES;
        case 3: {
            NSEvent *event = NSApp.currentEvent;
            if (event.window != _window || (event.type != NSEventTypeLeftMouseDown && event.type != NSEventTypeLeftMouseDragged)) return NO;
            [_window performWindowDragWithEvent:event];return YES;
        }
        default:return NO;
    }
}
- (BOOL)permitsPrivateActionAtRevision:(uint64_t)revision {
    NSAssert([NSThread isMainThread],@"native private publication");
    return !_covered && !_exchange && [self eligibleRevision:revision];
}
- (BOOL)holdsPrimary {
    MDGroupOwner *owner = objc_getAssociatedObject(_window,MDGroupOwnerKey);
    return owner.surface == self;
}
- (BOOL)holdsPrivateView {
    MDGroupOwner *owner = objc_getAssociatedObject(_webview,MDGroupOwnerKey);
    return owner.surface == self;
}
- (BOOL)concealOwnedPrimary {
    // Every AppKit setter can reenter. Never use a pre-callback ownership bit
    // to hide, mutate or clear a successor's shared primary/root.
    if (![self holdsPrimary]) return NO;
    _window.accessibilityHidden = YES;if (![self holdsPrimary]) return NO;
    _window.excludedFromWindowsMenu = YES;if (![self holdsPrimary]) return NO;
    [_window orderOut:nil];if (![self holdsPrimary]) return NO;
    if ([self holdsPrivateView]) _webview.accessibilityHidden = YES;
    if (![self holdsPrimary]) return NO;
    if ([self holdsPrivateView]) _webview.hidden = YES;
    if (![self holdsPrimary]) return NO;
    (void)[_window makeFirstResponder:nil];
    return [self holdsPrimary];
}
- (void)cover {
    [self coverNotifying:YES];
}
- (void)coverNotifying:(BOOL)notify {
    NSAssert([NSThread isMainThread],@"main-thread surface");
    if (!self.current) {
        MDGroupOwner *viewOwner = objc_getAssociatedObject(_webview,MDGroupOwnerKey);
        if (viewOwner.surface == nil || viewOwner.surface == self) _webview.hidden = YES;
        viewOwner = objc_getAssociatedObject(_webview,MDGroupOwnerKey);
        if (viewOwner.surface == nil || viewOwner.surface == self) _webview.accessibilityHidden = YES;
        return;
    }
    BOOL changed = !_covered || _window.visible;
    if (_window.visible) { _wantedVisible = YES;[_publicWindow setFrame:_window.frame display:NO]; }
    _covered = YES;_exchange = YES;
    @try {
        if (![self concealOwnedPrimary]) return;
        [self retireAuxiliaries];
        if (self.current && _covered && _wantedVisible && !_publicWindow.visible) {
            [_publicWindow orderFront:nil];changed = YES;
        }
    } @finally { _exchange = NO; }
    if (changed && notify) [NSNotificationCenter.defaultCenter postNotificationName:MDGroupFocusChanged object:self];
}
- (BOOL)reopenCovered {
    NSAssert([NSThread isMainThread],@"main-thread reopen");
    if (!self.current) return NO;
    _wantedVisible = YES;[self cover];
    return self.current && _publicWindow.visible && !_window.visible && _window.accessibilityHidden;
}
- (BOOL)focusPublicCover {
    if (![self reopenCovered]) return NO;
    // This path is called only for an explicit native Dock/single-instance
    // reopen. Background cover never activates or takes key focus.
    if (NSApp.activationPolicy == NSApplicationActivationPolicyProhibited) return NO;
    if (@available(macOS 14.0,*)) [NSApp activate];
    else [NSApp activateIgnoringOtherApps:YES];
    [_publicWindow makeKeyAndOrderFront:nil];
    return self.foreground;
}
- (void)hideGroup {
    [self hideGroupNotifying:YES];
}
- (void)hideGroupNotifying:(BOOL)notify {
    if (!self.current) return;
    [self denyReceipt];
    _wantedVisible = NO;_exchange = YES;
    @try {
        _covered = YES;[self concealOwnedPrimary];
        [_publicWindow orderOut:nil];[self retireAuxiliaries];
    } @finally { _exchange = NO; }
    if (notify) [NSNotificationCenter.defaultCenter postNotificationName:MDGroupHidden object:self];
}
- (BOOL)windowShouldClose:(NSWindow *)sender {
    if (sender == _publicWindow) [self hideGroup];
    return NO;
}
- (void)setPublicStatus:(NSString *)status unlock:(dispatch_block_t)unlock cancel:(dispatch_block_t)cancel {
    if (!self.current) return;
    if (_unavailable) [_cover configure:@"Device authentication is unavailable" unlock:nil cancel:nil];
    else [_cover configure:status unlock:unlock cancel:cancel];
}
// No bare/current lookup can manufacture activation authority. Only the
// canonical adapter's immutable captured revision enters this implementation.
- (void)uncover { [self cover]; }
- (void)uncoverRevision:(uint64_t)revision {
    NSAssert([NSThread isMainThread],@"main-thread surface");
    if (![self eligibleRevision:revision]) { [self coverNotifying:NO];return; }
    if (!_covered) return;
    _exchange = YES;
    @try {
        (void)[_window makeFirstResponder:nil];
        if (![self eligibleRevision:revision]) { [self coverNotifying:NO];return; }
        NSResponder *responder = _window.firstResponder;
        if (responder != nil && responder != _window) {
            _unavailable = YES;[self denyReceipt];[self coverNotifying:NO];
            [_cover configure:@"Device authentication is unavailable" unlock:nil cancel:nil];
            [NSNotificationCenter.defaultCenter postNotificationName:MDGroupUnavailable object:self];return;
        }
        [_window setFrame:_publicWindow.frame display:NO];
        if (![self eligibleRevision:revision]) { [self coverNotifying:NO];return; }
        _webview.hidden = NO;
        if (![self eligibleRevision:revision]) { [self coverNotifying:NO];return; }
        _webview.accessibilityHidden = NO;
        if (![self eligibleRevision:revision]) { [self coverNotifying:NO];return; }
        _window.accessibilityHidden = NO;
        if (![self eligibleRevision:revision]) { [self coverNotifying:NO];return; }
        _window.excludedFromWindowsMenu = _wasExcluded;
        if (![self eligibleRevision:revision]) { [self coverNotifying:NO];return; }
        _covered = NO;[_window makeKeyAndOrderFront:nil];
        if (![self eligibleRevision:revision]) { [self coverNotifying:NO];return; }
        [_publicWindow orderOut:nil];
        if (![self eligibleRevision:revision]) { [self coverNotifying:NO];return; }
    } @finally { _exchange = NO; }
    if ([self eligibleRevision:revision]) [NSNotificationCenter.defaultCenter postNotificationName:MDGroupFocusChanged object:self];
}
- (void)retire {
    NSAssert([NSThread isMainThread],@"main-thread retirement");
    if (_retired) return;
    _retired = YES;_covered = YES;_wantedVisible = NO;_exchange = YES;[self denyReceipt];
    @try {
        [self concealOwnedPrimary];
        if ([self holdsPrimary]) objc_setAssociatedObject(_window,MDGroupOwnerKey,nil,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        if ([self holdsPrivateView]) objc_setAssociatedObject(_webview,MDGroupOwnerKey,nil,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        // No primary/root mutation follows external retirement or close
        // callbacks. A successor installed there retains its own visibility.
        [self retireAuxiliaries];[_cover configure:@"Private messages locked" unlock:nil cancel:nil];
        _publicWindow.delegate = nil;[_publicWindow orderOut:nil];[_publicWindow close];
    } @finally { _exchange = NO; }
}
@end

@implementation MDWindowLifecycle {
    id<MDProtectionSurface> _surface;
    MDAuthRegistry *_registry;
    NSNotificationCenter *_center;
    NSNotificationCenter *_workspaceCenter;
    NSMutableArray *_tokens;
    NSMutableArray *_workspaceTokens;
    MDLifecycleReply _event;
    BOOL _closed;
}
- (instancetype)initWithSurface:(id<MDProtectionSurface>)surface registry:(MDAuthRegistry *)registry
    center:(NSNotificationCenter *)center workspaceCenter:(NSNotificationCenter *)workspaceCenter
    application:(id)application workspace:(id)workspace event:(MDLifecycleReply)event {
    if ((self = [super init])) {
        _surface = surface; _registry = registry; _center = center; _workspaceCenter = workspaceCenter;
        _tokens = [NSMutableArray new]; _workspaceTokens = [NSMutableArray new]; _event = [event copy];
        NSArray *names = @[NSApplicationWillResignActiveNotification, NSApplicationDidBecomeActiveNotification,
            NSApplicationWillHideNotification, NSWindowDidResignKeyNotification, NSWindowDidBecomeKeyNotification,
            NSWindowWillMiniaturizeNotification, NSWindowWillCloseNotification, NSWorkspaceSessionDidResignActiveNotification];
        const MDLifecycleEvent events[] = {MDInactive, MDActive, MDHidden, MDInactive, MDActive, MDMinimized, MDDestroyed, MDSessionLocked};
        __weak MDWindowLifecycle *weakSelf = self;
        for (NSUInteger i = 0; i < names.count; i++) {
            BOOL workspaceEvent = i == 7;
            NSNotificationCenter *owner = workspaceEvent ? workspaceCenter : center;
            id object = i < 3 ? application : (workspaceEvent ? workspace : nil);
            MDLifecycleEvent kind = events[i];
            BOOL windowEvent = i >= 3 && i <= 6;
            BOOL windowFocus = i == 3 || i == 4;
            id token = [owner addObserverForName:names[i] object:object queue:nil usingBlock:^(NSNotification *note) {
                MDWindowLifecycle *held = weakSelf;if (held == nil) return;
                BOOL grouped = [surface respondsToSelector:@selector(ownsWindow:)];
                if (windowEvent && !(grouped ? [surface ownsWindow:note.object] : note.object == surface.windowIdentity)) return;
                if (windowFocus && grouped) {
                    // Only synchronous exchanges between the two exact owned
                    // windows suppress their intermediate key notifications.
                    // Application/session/hard loss is never suppressed.
                    if ([surface exchangingWindows]) return;
                    [held receive:surface.foreground ? MDActive : MDInactive];
                } else if (kind == MDActive && grouped) [held receive:surface.foreground ? MDActive : MDInactive];
                else [held receive:kind];
            }];
            [(workspaceEvent ? _workspaceTokens : _tokens) addObject:token];
        }
        NSArray *groupNames = @[MDGroupFocusChanged,MDGroupHidden,MDGroupUnavailable];
        const MDLifecycleEvent groupEvents[] = {MDActive,MDHidden,MDUnavailable};
        for (NSUInteger i=0;i<groupNames.count;i++) {
            MDLifecycleEvent kind = groupEvents[i];
            id token = [center addObserverForName:groupNames[i] object:surface queue:nil usingBlock:^(NSNotification *note) {
                (void)note;MDWindowLifecycle *held = weakSelf;if (held == nil) return;
                MDLifecycleEvent actual = kind == MDActive ? (surface.foreground ? MDActive : MDInactive) : kind;
                [held receive:actual alreadyCovered:YES];
            }];[_tokens addObject:token];
        }
    }
    return self;
}
- (void)receive:(MDLifecycleEvent)event { [self receive:event alreadyCovered:NO]; }
- (void)receive:(MDLifecycleEvent)event alreadyCovered:(BOOL)covered {
    NSAssert([NSThread isMainThread], @"main-thread lifecycle");
    if (_closed || !_surface.current) return;
    BOOL hard = event == MDHidden || event == MDMinimized || event == MDSessionLocked || event == MDDestroyed || event == MDUnavailable;
    if (!covered && event != MDActive) {
        if (hard && [_surface isKindOfClass:MDAppKitSurface.class]) [(MDAppKitSurface *)_surface hideGroupNotifying:NO];
        else if ([_surface isKindOfClass:MDAppKitSurface.class]) [(MDAppKitSurface *)_surface coverNotifying:NO];
        else [_surface cover];
    }
    if (hard) [_registry cancelForSurface:_surface];
    if (event == MDDestroyed) [_surface retire];
    _event(event);
}
- (void)close {
    if (_closed) return;
    _closed = YES;
    for (id token in _tokens) [_center removeObserver:token];
    for (id token in _workspaceTokens) [_workspaceCenter removeObserver:token];
    [_tokens removeAllObjects]; [_workspaceTokens removeAllObjects];
    [_registry cancelForSurface:_surface]; [_surface retire];
}
- (void)dealloc {
    for (id token in _tokens) [_center removeObserver:token];
    for (id token in _workspaceTokens) [_workspaceCenter removeObserver:token];
}
@end
