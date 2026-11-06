#import <AppKit/AppKit.h>
NS_ASSUME_NONNULL_BEGIN
typedef NS_ENUM(NSUInteger, MDFilePurpose) { MDFileAttachments, MDFileAvatar, MDFileBackup };
// Native-only custody. Never serialize URL/path; retain this object for all
// selected descriptor IO, including pending choices and committed exports.
@interface MDScopedFileURL : NSObject
@property(nonatomic,readonly,strong) NSURL *url;
@property(nonatomic,readonly,copy) NSString *filename;
@property(nonatomic,readonly,copy) NSString *mime;
- (instancetype)init NS_UNAVAILABLE;
@end
typedef BOOL (^MDPanelBind)(NSWindow *panel,dispatch_block_t retire);
typedef void (^MDPanelRelease)(NSWindow *panel);
typedef void (^MDPanelReply)(NSArray<MDScopedFileURL *> *_Nullable selected);
// Single-use, main-thread operation. Blocks retain the original native owner;
// they must not consult a replacement page or accept an IPC window identifier.
@interface MDNativeFilePanel : NSObject
- (instancetype)initWithPrimary:(NSWindow *)primary bind:(MDPanelBind)bind release:(MDPanelRelease)release;
- (BOOL)open:(MDFilePurpose)purpose reply:(MDPanelReply)reply;
- (BOOL)saveName:(NSString *)name mime:(NSString *)mime reply:(MDPanelReply)reply;
- (void)cancel;
@end
#if defined(MD_NATIVE_TEST_PORTS)
// Only the OS panel driver is replaced. Ownership, scheduling, validation,
// retirement and actual NSURL custody use the production implementation.
@protocol MDFilePanelDriver <NSObject>
@property(nonatomic,readonly,strong) NSWindow *window;
- (void)begin:(NSWindow *)primary completion:(void (^)(NSModalResponse))completion;
- (NSArray<NSURL *> *)selected;
- (void)cancel;
@end
@interface MDNativeFilePanel (Testing)
- (BOOL)beginTestDriver:(id<MDFilePanelDriver>)driver purpose:(MDFilePurpose)purpose reply:(MDPanelReply)reply;
@end
#endif
NS_ASSUME_NONNULL_END
