#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

NS_ASSUME_NONNULL_BEGIN
// Every instance binds one immutable native window/webview generation. Caller
// strings, window labels and JS snapshots cannot construct an authorized owner.
@protocol MDProtectionSurface <NSObject>
@property(nonatomic, readonly) id windowIdentity;
@property(nonatomic, readonly) BOOL current;
@property(nonatomic, readonly) BOOL foreground;
- (void)cover;
- (void)uncover;
- (void)retire;
@optional
- (BOOL)ownsWindow:(id)window;
- (BOOL)exchangingWindows;
- (void)hideGroup;
// Canonical cover adapter records receipt before native dispatch. A captured
// uncover may not adopt a newer presentation's authority after reentry.
- (void)recordRevision:(uint64_t)revision uncover:(BOOL)uncover;
- (void)uncoverRevision:(uint64_t)revision;
@end

typedef void (^MDDispatch)(dispatch_block_t work);
typedef NS_ENUM(NSUInteger, MDAuthReply) {
    MDAuthApproved, MDAuthCancelled, MDAuthFailed
};
typedef void (^MDReply)(MDAuthReply reply);
@protocol MDAuthContext <NSObject>
- (void)evaluate:(MDReply)reply;
- (void)invalidate;
@end
typedef id<MDAuthContext> _Nullable (^MDContextFactory)(void);

// One registry per native controller boot. Sequences are its trusted increasing
// RequestId.sequence values. Neither IDs nor approval enter through JS IPC.
@interface MDAuthRegistry : NSObject
- (instancetype)initWithDispatch:(MDDispatch)dispatch factory:(MDContextFactory)factory;
- (void)begin:(uint64_t)sequence surface:(id<MDProtectionSurface>)surface reply:(MDReply)reply;
- (void)cancel:(uint64_t)sequence;
- (void)cancelForSurface:(id<MDProtectionSurface>)surface;
- (void)close;
@end

// Real OS implementation, never selected by the host tests. Evaluation presents
// native UI only when the future reviewed Tauri binding explicitly calls begin.
@interface MDLocalAuthContext : NSObject <MDAuthContext>
@end

@interface MDCoverAdapter : NSObject
- (instancetype)initWithDispatch:(MDDispatch)dispatch;
- (void)applyRevision:(uint64_t)revision surface:(nullable id<MDProtectionSurface>)surface uncover:(BOOL)uncover;
@end

// Must be constructed on the main thread before the private webview is shown.
// Pass the actual WKWebView from pinned Tauri PlatformWebview.inner(), not the
// containing contentView returned by Window.ns_view().
@interface MDAppKitSurface : NSObject <MDProtectionSurface>
- (instancetype)initWithWindow:(NSWindow *)window webview:(NSView *)webview;
// The owned reopen path must use this instead of an unconditional show. It
// never uncovers or activates; a still-private responder keeps the window hidden.
- (BOOL)reopenCovered;
- (BOOL)focusPublicCover;
@property(nonatomic, readonly) NSWindow *publicWindow;
// Native-created private panels only, admitted before presentation. Revocation
// removes the entry before calling its nonblocking retirement callback.
- (BOOL)bindAuxiliaryWindow:(NSWindow *)window revision:(uint64_t)revision retire:(dispatch_block_t)retire;
- (void)releaseAuxiliaryWindow:(NSWindow *)window;
// Only a receiving-header-checked, exact captured presentation can perform
// normal private-window chrome actions. Show/focus is not a JS action.
- (BOOL)performWindowAction:(uint32_t)action revision:(uint64_t)revision;
// Native private publication, not an authorization source. The bridge still
// checks the held original lease and this exact native owner under its gate.
- (BOOL)permitsPrivateActionAtRevision:(uint64_t)revision;
#if defined(MD_NATIVE_TEST_PORTS)
// Readonly OS foreground facts only. Actual AppKit windows/responders and the
// production window-group implementation remain in use; never an auth result.
- (instancetype)initWithWindow:(NSWindow *)window webview:(NSView *)webview testForegroundObservation:(BOOL (^)(NSWindow *window))observation;
#endif
// Public controls remain outside the hidden private WKWebView. Blocks are
// immutable revision-bound actions, never native approval callbacks.
- (void)setPublicStatus:(NSString *)status unlock:(nullable dispatch_block_t)unlock cancel:(nullable dispatch_block_t)cancel;
@end

typedef NS_ENUM(NSUInteger, MDLifecycleEvent) {
    MDInactive, MDActive, MDHidden, MDMinimized, MDSessionLocked, MDDestroyed, MDUnavailable
};
typedef void (^MDLifecycleReply)(MDLifecycleEvent event);
@interface MDWindowLifecycle : NSObject
// Event callback must synchronously deliver to the native controller, whose
// Cover.apply receipt records the newer presentation before returning. Never
// wait on policy/Core work here. Active is observation only; it never uncovers.
- (instancetype)initWithSurface:(id<MDProtectionSurface>)surface
                      registry:(MDAuthRegistry *)registry
                        center:(NSNotificationCenter *)center
               workspaceCenter:(NSNotificationCenter *)workspaceCenter
                   application:(id)application
                     workspace:(id)workspace
                         event:(MDLifecycleReply)event;
- (void)close;
@end

MDDispatch MDMainDispatch(void);
NS_ASSUME_NONNULL_END
