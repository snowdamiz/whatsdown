#import "NativeFilePanels.h"
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

static BOOL MDValidName(NSString *name) {
    if (name.length==0 || [name lengthOfBytesUsingEncoding:NSUTF8StringEncoding]>255 || [@[@".",@".."] containsObject:name]) return NO;
    NSMutableCharacterSet *invalid=[NSCharacterSet.controlCharacterSet mutableCopy];[invalid addCharactersInString:@"/\\"];
    return [name rangeOfCharacterFromSet:invalid].location==NSNotFound;
}
@interface MDScopedFileURL ()
@property(nonatomic,readwrite,strong) NSURL *url;
@property(nonatomic,readwrite,copy) NSString *filename;
@property(nonatomic,readwrite,copy) NSString *mime;
@property(nonatomic) BOOL accessing;
- (nullable instancetype)initWithURL:(NSURL *)url mime:(nullable NSString *)mime;
@end
@implementation MDScopedFileURL
- (instancetype)initWithURL:(NSURL *)url mime:(NSString *)mime {
    if (!url.isFileURL || !url.path.isAbsolutePath || !MDValidName(url.lastPathComponent)) return nil;
    if ((self=[super init])) {
        _url=[url copy];_accessing=[_url startAccessingSecurityScopedResource];
        // Ordinary nonsandboxed URLs return NO; subsequent descriptor capture
        // remains the authority for actual IO access, with no permission bypass.
        _filename=[url.lastPathComponent copy];
        UTType *type=nil;[_url getResourceValue:&type forKey:NSURLContentTypeKey error:nil];
        if (type==nil) type=[UTType typeWithFilenameExtension:_url.pathExtension];
        _mime=[(mime ?: type.preferredMIMEType ?: @"application/octet-stream") copy];
    }return self;
}
- (void)dealloc { if (_accessing) [_url stopAccessingSecurityScopedResource]; }
@end

#if !defined(MD_NATIVE_TEST_PORTS)
@protocol MDFilePanelDriver <NSObject>
@property(nonatomic,readonly,strong) NSWindow *window;
- (void)begin:(NSWindow *)primary completion:(void (^)(NSModalResponse))completion;
- (NSArray<NSURL *> *)selected;
- (void)cancel;
@end
#endif
@interface MDSystemFilePanel : NSObject<MDFilePanelDriver>
@property(nonatomic,strong) NSSavePanel *panel;
@end
@implementation MDSystemFilePanel
- (NSWindow *)window { return _panel; }
- (void)begin:(NSWindow *)primary completion:(void (^)(NSModalResponse))completion { [_panel beginSheetModalForWindow:primary completionHandler:completion]; }
- (NSArray<NSURL *> *)selected { return [_panel isKindOfClass:NSOpenPanel.class]?((NSOpenPanel *)_panel).URLs:(_panel.URL?@[_panel.URL]:@[]); }
- (void)cancel { [_panel cancel:nil];[_panel orderOut:nil]; }
@end

@interface MDNativeFilePanel ()
@property(nonatomic,strong) NSWindow *primary;
@property(nonatomic,copy) MDPanelBind bind;
@property(nonatomic,copy) MDPanelRelease releaseAuxiliary;
@property(nonatomic,copy,nullable) MDPanelReply reply;
@property(nonatomic,strong,nullable) id<MDFilePanelDriver> driver;
@property(nonatomic,copy,nullable) NSString *saveMIME;
@property(nonatomic) MDFilePurpose purpose;
@property(nonatomic) BOOL used,bound,active,cancelled,drained,queued,delivered;
- (BOOL)beginDriver:(id<MDFilePanelDriver>)driver purpose:(MDFilePurpose)purpose reply:(MDPanelReply)reply;
- (void)queue:(nullable NSArray<MDScopedFileURL *> *)selected;
- (void)releaseIfDrained;
@end
@implementation MDNativeFilePanel
- (instancetype)initWithPrimary:(NSWindow *)primary bind:(MDPanelBind)bind release:(MDPanelRelease)release {
    if (!NSThread.isMainThread || primary==nil || bind==nil || release==nil) return nil;
    if ((self=[super init])) { _primary=primary;_bind=[bind copy];_releaseAuxiliary=[release copy]; }return self;
}
- (BOOL)open:(MDFilePurpose)purpose reply:(MDPanelReply)reply {
    if (!NSThread.isMainThread || _used || purpose>MDFileBackup || reply==nil) return NO;
    NSOpenPanel *panel=[NSOpenPanel openPanel];panel.canChooseFiles=YES;panel.canChooseDirectories=NO;
    panel.treatsFilePackagesAsDirectories=NO;panel.resolvesAliases=NO;panel.allowsMultipleSelection=purpose==MDFileAttachments;
    panel.allowedContentTypes=purpose==MDFileAvatar?@[UTTypeImage]:@[UTTypeData];
    MDSystemFilePanel *driver=[MDSystemFilePanel new];driver.panel=panel;
    return [self beginDriver:driver purpose:purpose reply:reply];
}
- (BOOL)saveName:(NSString *)name mime:(NSString *)mime reply:(MDPanelReply)reply {
    if (!NSThread.isMainThread || _used || !MDValidName(name) || mime.length==0 || mime.length>128 || reply==nil) return NO;
    UTType *type=[UTType typeWithMIMEType:mime];if (type==nil) return NO;
    NSSavePanel *panel=[NSSavePanel savePanel];panel.nameFieldStringValue=name;panel.allowedContentTypes=@[type];panel.canCreateDirectories=YES;
    MDSystemFilePanel *driver=[MDSystemFilePanel new];driver.panel=panel;_saveMIME=[mime copy];
    return [self beginDriver:driver purpose:MDFileBackup reply:reply];
}
- (BOOL)beginDriver:(id<MDFilePanelDriver>)driver purpose:(MDFilePurpose)purpose reply:(MDPanelReply)reply {
    if (!NSThread.isMainThread || _used || driver==nil || purpose>MDFileBackup || reply==nil) return NO;
    _used=YES;_driver=driver;_purpose=purpose;_reply=[reply copy];
    __weak MDNativeFilePanel *weak=self;
    _bound=_bind(driver.window,^{ [weak cancel]; });
    if (!_bound || _cancelled) { _drained=YES;[self queue:nil];return YES; }
    _active=YES;
    [driver begin:_primary completion:^(NSModalResponse response) {
        NSAssert(NSThread.isMainThread,@"original native panel completion");
        self.active=NO;self.drained=YES;
        NSMutableArray<MDScopedFileURL *> *selected=nil;
        if (!self.cancelled && response==NSModalResponseOK) {
            NSArray<NSURL *> *urls=[self.driver selected];NSUInteger limit=self.purpose==MDFileAttachments?10:1;
            if (urls.count>0 && urls.count<=limit) {
                selected=[NSMutableArray new];
                for (NSURL *url in urls) {
                    MDScopedFileURL *held=[[MDScopedFileURL alloc] initWithURL:url mime:self.saveMIME];
                    if (held==nil || (self.purpose==MDFileAvatar && ![held.mime hasPrefix:@"image/"])) { selected=nil;break; }
                    [selected addObject:held];
                }
            }
        }
        [self queue:selected];
        // A late OS reply after cancellation still owns and releases exactly
        // its original auxiliary. Never release a successor window/page.
        dispatch_async(dispatch_get_main_queue(),^{ [self releaseIfDrained]; });
    }];return YES;
}
- (void)queue:(NSArray<MDScopedFileURL *> *)selected {
    if (_queued || _delivered) return;
    _queued=YES;
    dispatch_async(dispatch_get_main_queue(),^{
        MDPanelReply reply=self.reply;self.reply=nil;
        [self releaseIfDrained];
        self.delivered=YES;
        if (reply) reply(self.cancelled?nil:selected);
    });
}
- (void)releaseIfDrained {
    if (!_drained) return;
    if (_bound) { _bound=NO;_releaseAuxiliary(_driver.window); }
    _driver=nil;_bind=nil;_releaseAuxiliary=nil;_primary=nil;
}
- (void)cancel {
    NSAssert(NSThread.isMainThread,@"native panel retirement");
    if (_cancelled || _delivered) return;
    _cancelled=YES;
    if (_active) [_driver cancel];
    [self queue:nil];
}
#if defined(MD_NATIVE_TEST_PORTS)
- (BOOL)beginTestDriver:(id<MDFilePanelDriver>)driver purpose:(MDFilePurpose)purpose reply:(MDPanelReply)reply { return [self beginDriver:driver purpose:purpose reply:reply]; }
#endif
@end
