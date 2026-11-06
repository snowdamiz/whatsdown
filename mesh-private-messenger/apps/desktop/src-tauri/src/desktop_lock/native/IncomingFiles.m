#import "IncomingFiles.h"
#import "NativeFilePanels.h"
#import "ProtectionBridge.h"
#include <stdatomic.h>
#include <string.h>

@interface MDScopedFileURL (IncomingConstruction)
- (nullable instancetype)initWithURL:(NSURL *)url mime:(nullable NSString *)mime;
@end
@interface MDIncomingAuthority:NSObject
@property(nonatomic) MDPrivateScope scope;
@property(nonatomic) MDNativeIncomingCallbacks callbacks;
@end
@implementation MDIncomingAuthority
- (void)dealloc {
    MDPrivateScope scope=_scope;MDNativeIncomingCallbacks callbacks=_callbacks;
    // A final Rust decrement may destroy native policy/receiver state. Never
    // perform it in a borrowed callback frame or an outer recursive gate.
    dispatch_async(dispatch_get_main_queue(),^{scope.release(scope.context);callbacks.release(callbacks.context);});
}
@end
static BOOL validCallbacks(MDPrivateScope scope,MDNativeIncomingCallbacks callbacks) {
    return scope.context!=NULL && scope.retain!=NULL && scope.release!=NULL && scope.current!=NULL &&
        scope.window_id!=0 && scope.page_id!=0 && callbacks.context!=NULL && callbacks.retain!=NULL &&
        callbacks.release!=NULL && callbacks.sources!=NULL && callbacks.dragging!=NULL;
}
static MDIncomingAuthority *authority(MDPrivateScope scope,MDNativeIncomingCallbacks callbacks) {
    MDIncomingAuthority *held=[MDIncomingAuthority new];held.scope=scope;held.callbacks=callbacks;
    scope.retain(scope.context);callbacks.retain(callbacks.context);return held;
}
static BOOL receiver(void *protection,NSWindow *window,NSView *view,MDPrivateScope scope) {
    if(!NSThread.isMainThread || protection==NULL || window==nil || view==nil || view.window!=window)return NO;
    uint64_t w=0,p=0;
    if(!MDNativeProtectionPrivateReceiver(protection,(__bridge void*)view,&w,&p) || w!=scope.window_id || p!=scope.page_id)return NO;
    // Scope polling can retire the original page. No Protection/registry gate
    // is held here, and the caller retains this authority throughout reentry.
    if(!scope.current(scope.context))return NO;
    w=0;p=0;
    return view.window==window && MDNativeProtectionPrivateReceiver(protection,(__bridge void*)view,&w,&p) && w==scope.window_id && p==scope.page_id;
}
static BOOL inputFocus(NSWindow *window,NSView *view) {
    NSResponder *responder=window.firstResponder;
    if([responder isKindOfClass:NSView.class] && [(NSView*)responder isDescendantOf:view])return YES;
    if([responder isKindOfClass:NSTextView.class]) {
        id delegate=((NSTextView*)responder).delegate;
        return [delegate isKindOfClass:NSView.class] && [(NSView*)delegate isDescendantOf:view];
    }
    return NO;
}
static BOOL emitURLs(void *protection,NSWindow *window,NSView *view,MDIncomingAuthority *held,NSArray<NSURL *> *urls) {
    if(urls.count==0 || urls.count>10 || !receiver(protection,window,view,held.scope))return NO;
    __attribute__((objc_precise_lifetime)) NSMutableArray<MDScopedFileURL*> *owned=[NSMutableArray new];
    for(NSURL *url in urls) {
        if(![url isKindOfClass:NSURL.class] || !url.isFileURL)return NO;
        MDScopedFileURL *selected=[[MDScopedFileURL alloc]initWithURL:url mime:nil];if(selected==nil)return NO;
        [owned addObject:selected];
        if(!receiver(protection,window,view,held.scope))return NO;
    }
    MDNativeFileSelection rows[10];__attribute__((objc_precise_lifetime)) NSMutableArray<NSData*> *spans=[NSMutableArray new];
    char paths[10][4097];
    for(NSUInteger i=0;i<owned.count;i++) {
        MDScopedFileURL *selected=owned[i];
        if(![selected.url getFileSystemRepresentation:paths[i] maxLength:sizeof(paths[i])])return NO;
        NSData *name=[selected.filename dataUsingEncoding:NSUTF8StringEncoding],*mime=[selected.mime dataUsingEncoding:NSUTF8StringEncoding];
        if(name.length==0 || name.length>255 || mime.length==0 || mime.length>127)return NO;
        [spans addObject:name];[spans addObject:mime];
        rows[i]=(MDNativeFileSelection){(__bridge void*)selected,(const uint8_t*)paths[i],strlen(paths[i]),name.bytes,name.length,mime.bytes,mime.length};
    }
    if(!receiver(protection,window,view,held.scope))return NO;
    return held.callbacks.sources(held.callbacks.context,rows,owned.count);
}
@class MDIncomingDropView;
@interface MDIncomingToken:NSObject {
@public atomic_bool closed;
}
@property(nonatomic) void *protection;
@property(nonatomic,strong) NSWindow *window;
@property(nonatomic,strong) NSView *view;
@property(nonatomic,strong) MDIncomingAuthority *authority;
@property(nonatomic,strong) MDIncomingDropView *dropView;
@property(nonatomic,strong) id frameObserver;
- (BOOL)current;
- (BOOL)paste:(NSEvent*)event reader:(NSArray<NSURL*>*(^)(void))reader;
- (BOOL)drop:(id<NSDraggingInfo>)info reader:(NSArray<NSURL*>*(^)(void))reader;
@end
@interface MDIncomingDropView:NSView
@property(nonatomic,weak) MDIncomingToken *token;
@end
@implementation MDIncomingDropView
- (NSView*)hitTest:(NSPoint)point {(void)point;return nil;}
- (BOOL)acceptsFirstResponder {return NO;}
- (BOOL)accepts:(id<NSDraggingInfo>)info {
    __attribute__((objc_precise_lifetime)) MDIncomingToken *token=_token;
    NSPoint point=[self convertPoint:info.draggingLocation fromView:nil];
    return token!=nil && info.draggingDestinationWindow==token.window && NSPointInRect(point,self.bounds) && [token current];
}
- (NSDragOperation)draggingEntered:(id<NSDraggingInfo>)info {
    __attribute__((objc_precise_lifetime)) MDIncomingToken *token=_token;
    if(![self accepts:info])return NSDragOperationNone;
    token.authority.callbacks.dragging(token.authority.callbacks.context,true);
    return [token current]?NSDragOperationCopy:NSDragOperationNone;
}
- (NSDragOperation)draggingUpdated:(id<NSDraggingInfo>)info {return [self draggingEntered:info];}
- (void)draggingExited:(id<NSDraggingInfo>)info {
    (void)info;__attribute__((objc_precise_lifetime)) MDIncomingToken *token=_token;
    if(token!=nil && [token current])token.authority.callbacks.dragging(token.authority.callbacks.context,false);
}
- (BOOL)prepareForDragOperation:(id<NSDraggingInfo>)info {return [self accepts:info];}
- (BOOL)performDragOperation:(id<NSDraggingInfo>)info {
    __attribute__((objc_precise_lifetime)) MDIncomingToken *token=_token;
    if(![self accepts:info])return NO;
    return [token drop:info reader:^NSArray<NSURL*>*{
        return [info.draggingPasteboard readObjectsForClasses:@[NSURL.class] options:@{NSPasteboardURLReadingFileURLsOnlyKey:@YES}];
    }];
}
@end
// Do not enable Tauri's drag handler: it automatically emits raw paths into
// JavaScript. Keep WebKit from falling through to a raw DOM File destination.
static BOOL disableDOMDrops(NSView *root,NSUInteger *remaining) {
    if(*remaining==0)return NO;--*remaining;[root unregisterDraggedTypes];
    for(NSView *child in root.subviews)if(!disableDOMDrops(child,remaining))return NO;
    return YES;
}
static NSMutableArray<MDIncomingToken*> *tokens;
static id monitor;
@implementation MDIncomingToken
- (instancetype)init {if((self=[super init]))atomic_init(&closed,false);return self;}
- (BOOL)current {
    __attribute__((objc_precise_lifetime)) MDIncomingToken *held=self;
    return !atomic_load_explicit(&held->closed,memory_order_acquire) && receiver(held.protection,held.window,held.view,held.authority.scope) && !atomic_load_explicit(&held->closed,memory_order_acquire);
}
- (BOOL)paste:(NSEvent*)event reader:(NSArray<NSURL*>*(^)(void))reader {
    __attribute__((objc_precise_lifetime)) MDIncomingToken *held=self;
    if(event.type!=NSEventTypeKeyDown || event.window!=_window || ![[event.charactersIgnoringModifiers lowercaseString]isEqualToString:@"v"] ||
        (event.modifierFlags&(NSEventModifierFlagCommand|NSEventModifierFlagControl|NSEventModifierFlagOption|NSEventModifierFlagShift))!=NSEventModifierFlagCommand ||
        ![held current] || !inputFocus(_window,_view) || ![held current])return NO;
    NSArray<NSURL*> *urls=reader();
    if(urls.count==0)return NO; // Ordinary text paste remains the native WK path.
    if(![held current] || !inputFocus(_window,_view))return YES;
    (void)emitURLs(_protection,_window,_view,_authority,urls);
    // Recognized file URLs never fall through to an unscoped DOM file paste,
    // including bounded refusal or retirement during metadata construction.
    return YES;
}
- (BOOL)drop:(id<NSDraggingInfo>)info reader:(NSArray<NSURL*>*(^)(void))reader {
    __attribute__((objc_precise_lifetime)) MDIncomingToken *held=self;
    if(![_dropView accepts:info] || ![held current])return NO;
    NSArray<NSURL*> *urls=reader();
    if(![held current] || ![_dropView accepts:info])return NO;
    _authority.callbacks.dragging(_authority.callbacks.context,false);
    return [held current] && emitURLs(_protection,_window,_view,_authority,urls);
}
- (void)dealloc {if(_protection)CFRelease(_protection);}
@end
static void installMonitor(void) {
    if(monitor!=nil)return;
    monitor=[NSEvent addLocalMonitorForEventsMatchingMask:NSEventMaskKeyDown handler:^NSEvent*(NSEvent *event) {
        NSArray<MDIncomingToken*> *snapshot=[tokens copy];
        for(MDIncomingToken *token in snapshot.reverseObjectEnumerator) {
            if(token.window!=event.window || ![token current])continue;
            BOOL consumed=[token paste:event reader:^NSArray<NSURL*>*{
                return [NSPasteboard.generalPasteboard readObjectsForClasses:@[NSURL.class] options:@{NSPasteboardURLReadingFileURLsOnlyKey:@YES}];
            }];
            return consumed?nil:event;
        }
        return event;
    }];
}
void *MDNativeIncomingSubscribe(void *protection,void *windowRaw,void *viewRaw,MDPrivateScope scope,MDNativeIncomingCallbacks callbacks) {
    if(!NSThread.isMainThread || !validCallbacks(scope,callbacks) || tokens.count>=4)return NULL;
    NSWindow *window=(__bridge NSWindow*)windowRaw;NSView *view=(__bridge NSView*)viewRaw;
    uint64_t actualWindow=0,actualPage=0;
    if(view.window!=window || !MDNativeProtectionPrivateReceiver(protection,viewRaw,&actualWindow,&actualPage) || actualWindow!=scope.window_id || actualPage!=scope.page_id)return NULL;
    __attribute__((objc_precise_lifetime)) MDIncomingAuthority *held=authority(scope,callbacks);
    if(!receiver(protection,window,view,scope))return NULL;
    if(tokens==nil)tokens=[NSMutableArray new];
    if(tokens.count>=4)return NULL; // Includes cancelled tokens until Main drains.
    MDIncomingToken *token=[MDIncomingToken new];token.protection=protection;CFRetain(protection);
    token.window=window;token.view=view;token.authority=held;
    NSUInteger remaining=1024;
    if(!disableDOMDrops(view,&remaining) || ![token current] || view.superview==nil)return NULL;
    MDIncomingDropView *drop=[[MDIncomingDropView alloc]initWithFrame:view.frame];drop.token=token;drop.autoresizingMask=NSViewWidthSizable|NSViewHeightSizable;
    drop.accessibilityHidden=YES;[drop registerForDraggedTypes:@[NSPasteboardTypeFileURL]];
    token.dropView=drop;[view.superview addSubview:drop positioned:NSWindowAbove relativeTo:view];
    view.postsFrameChangedNotifications=YES;__weak MDIncomingToken *weakToken=token;
    token.frameObserver=[NSNotificationCenter.defaultCenter addObserverForName:NSViewFrameDidChangeNotification object:view queue:nil usingBlock:^(__unused NSNotification *note){
        MDIncomingToken *current=weakToken;if(current==nil || atomic_load_explicit(&current->closed,memory_order_acquire))return;
        if(current.dropView.superview==current.view.superview)current.dropView.frame=current.view.frame;
    }];
    [tokens addObject:token];installMonitor();
    if(monitor==nil || ![token current]) { MDNativeIncomingClose((__bridge void*)token);return NULL; }
    return(__bridge_retained void*)token;
}
void MDNativeIncomingClose(void *raw) {
    if(raw==NULL)return;MDIncomingToken *token=(__bridge MDIncomingToken*)raw;
    atomic_store_explicit(&token->closed,true,memory_order_release);
    dispatch_async(dispatch_get_main_queue(),^{
        [token.dropView unregisterDraggedTypes];[token.dropView removeFromSuperview];token.dropView=nil;
        if(token.frameObserver!=nil){[NSNotificationCenter.defaultCenter removeObserver:token.frameObserver];token.frameObserver=nil;}
        [tokens removeObjectIdenticalTo:token];
        if(tokens.count==0 && monitor!=nil){[NSEvent removeMonitor:monitor];monitor=nil;}
    });
}
void MDNativeIncomingRelease(void *raw) {
    if(raw==NULL)return;MDNativeIncomingClose(raw);dispatch_async(dispatch_get_main_queue(),^{CFRelease(raw);});
}
#if defined(MD_NATIVE_TEST_PORTS)
BOOL MDNativeIncomingPasteForTest(void *raw,NSEvent *event,NSArray<NSURL*>*(^reader)(void)) {
    return raw!=NULL && [(MDIncomingToken*)(__bridge id)raw paste:event reader:reader];
}
NSView *MDNativeIncomingDropViewForTest(void *raw) {return raw?((MDIncomingToken*)(__bridge id)raw).dropView:nil;}
BOOL MDNativeIncomingDropForTest(void *raw,id<NSDraggingInfo> info,NSArray<NSURL*>*(^reader)(void)) {
    return raw!=NULL && [(MDIncomingToken*)(__bridge id)raw drop:info reader:reader];
}
#endif
