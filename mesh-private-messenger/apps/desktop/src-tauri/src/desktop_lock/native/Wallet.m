#import "Wallet.h"
#import "ProtectionBridge.h"
#import "morse_wallet_core.h"
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <TargetConditionals.h>
#import <sys/file.h>
#import <sys/stat.h>
#import <fcntl.h>
#import <unistd.h>
#import <AppKit/AppKit.h>

@interface MorseDesktopWalletContext : NSObject
@property(nonatomic, copy) NSString *service;
@property(nonatomic, copy) NSString *directory;
@property(nonatomic) int descriptor;
@property(nonatomic) uint8_t purpose;
@property(nonatomic) MDPrivateScope scope;
@property(nonatomic) void *protection;
@end
@implementation MorseDesktopWalletContext
- (void)dealloc { if (_scope.release != NULL) _scope.release(_scope.context); }
@end
static BOOL MWCurrent(MorseDesktopWalletContext *host) {
  return host.scope.current != NULL && host.scope.current(host.scope.context);
}

static NSDictionary *MWQuery(MorseDesktopWalletContext *host, NSString *name) {
  return @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
           (__bridge id)kSecAttrService: host.service,
           (__bridge id)kSecAttrAccount: name,
           (__bridge id)kSecAttrSynchronizable: @NO};
}
static int MWRead(MorseDesktopWalletContext *host, NSString *name, NSMutableData **value) {
  if (!MWCurrent(host)) return 3;
  NSMutableDictionary *query = [MWQuery(host, name) mutableCopy];
  query[(__bridge id)kSecReturnData] = @YES;
  query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
  CFTypeRef result = NULL;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
  if (status == errSecItemNotFound) return 2;
  if (status != errSecSuccess || !result) { if (result) CFRelease(result); return 3; }
  if (CFGetTypeID(result)!=CFDataGetTypeID()) {CFRelease(result);return 3;}
  *value = [NSMutableData dataWithBytes:CFDataGetBytePtr(result) length:CFDataGetLength(result)];
  CFRelease(result);
  return 0;
}
static int MWAdd(MorseDesktopWalletContext *host, NSString *name, NSData *value) {
  if (!MWCurrent(host)) return 3;
  NSMutableDictionary *query = [MWQuery(host, name) mutableCopy];
  query[(__bridge id)kSecValueData] = value;
  query[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
  return SecItemAdd((__bridge CFDictionaryRef)query, NULL) == errSecSuccess ? 0 : 3;
}
static void MWClear(NSMutableData *value) {
  if (value.length) { volatile uint8_t *p = value.mutableBytes; for (NSUInteger i=0;i<value.length;i++) p[i]=0; }
}
static int MWAcquire(void *context) {
  MorseDesktopWalletContext *host = (__bridge MorseDesktopWalletContext *)context;
  if (host.descriptor != -1 || !MWCurrent(host)) return 3;
  struct stat folder;
  if (lstat(host.directory.fileSystemRepresentation, &folder) != 0 || !S_ISDIR(folder.st_mode) ||
      folder.st_uid != getuid() || (folder.st_mode & 0777) != 0700) return 3;
  NSString *path = [host.directory stringByAppendingPathComponent:@"custody.lock"];
  int fd = open(path.fileSystemRepresentation, O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW, 0600);
  if (fd < 0) return 3;
  struct stat st;
  if (fstat(fd,&st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_uid != getuid() ||
      (st.st_mode & 0777) != 0600 || flock(fd,LOCK_EX) != 0) { close(fd); return 3; }
  if (!MWCurrent(host)) { flock(fd,LOCK_UN);close(fd);return 3; }
  /* Anchor the lock inode in the credential store. Replacing/deleting an app
   * file cannot create an independent lock domain and rewind the counter. */
  uint64_t identity[4] = {(uint64_t)folder.st_dev,(uint64_t)folder.st_ino,(uint64_t)st.st_dev,(uint64_t)st.st_ino};
  NSData *expected = [NSData dataWithBytes:identity length:sizeof(identity)];
  NSMutableData *anchor = nil;
  int status = MWRead(host,@"lock-v1",&anchor);
  if (status == 2) {
    if (fsync(fd) != 0) status=3;
    else {
      int directory = open(host.directory.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
      status = directory >= 0 && fsync(directory) == 0 ? 0 : 3;
      if (directory >= 0) close(directory);
      if (!status && MWAdd(host,@"lock-v1",expected) != 0) status=MWRead(host,@"lock-v1",&anchor);
      else if (!status) anchor=[expected mutableCopy];
    }
  }
  BOOL matches = status == 0 && [anchor isEqualToData:expected];
  MWClear(anchor);
  if (!matches) { flock(fd,LOCK_UN);close(fd);return 3; }
  host.descriptor=fd;
  return 0;
}
static int MWRelease(void *context) {
  MorseDesktopWalletContext *host = (__bridge MorseDesktopWalletContext *)context;
  if (host.descriptor < 0) return 3;
  int fd=host.descriptor;host.descriptor=-1;
  int status=flock(fd,LOCK_UN);int closed=close(fd);
  return status == 0 && closed == 0 ? 0 : 3;
}
static int MWLoad(void *context,uint8_t *output,uint64_t capacity,uint64_t *written) {
  if (!written) return 3;*written=0;
  MorseDesktopWalletContext *host=(__bridge MorseDesktopWalletContext *)context;
  if (!MWCurrent(host) || host.descriptor < 0 || !output || capacity < 44) return 3;
  NSMutableData *marker=nil,*record=nil;
  int marked=MWRead(host,@"initialized-v1",&marker), loaded=MWRead(host,@"record-v1",&record);
  int result=3;
  if (marked==2 && loaded==2) result=2;
  else if (marked==0 && marker.length==1 && ((const uint8_t *)marker.bytes)[0]==1 && loaded==0 && record.length==44) {
    memcpy(output,record.bytes,44);*written=44;result=0;
  }
  MWClear(marker);MWClear(record);return result;
}
static int MWReplace(void *context,const uint8_t *input,uint64_t length) {
  MorseDesktopWalletContext *host=(__bridge MorseDesktopWalletContext *)context;
  if (!MWCurrent(host) || host.descriptor < 0 || !input || length!=44 || memcmp(input,"MWL1",4)) return 3;
  NSMutableData *marker=nil,*old=nil;
  int marked=MWRead(host,@"initialized-v1",&marker), loaded=MWRead(host,@"record-v1",&old);
  int result=3;
  NSData *value=[NSData dataWithBytesNoCopy:(void *)input length:44 freeWhenDone:NO];
  if (marked==2 && loaded==2) {
    uint8_t byte=1;
    /* A crash after this marker fails closed; Create cannot replace a wallet. */
    if (MWAdd(host,@"initialized-v1",[NSData dataWithBytes:&byte length:1])==0) result=MWAdd(host,@"record-v1",value);
  } else if (marked==0 && marker.length==1 && ((const uint8_t *)marker.bytes)[0]==1 && loaded==0 && old.length==44) {
    if (!MWCurrent(host)) { MWClear(marker);MWClear(old);return 3; }
    result=SecItemUpdate((__bridge CFDictionaryRef)MWQuery(host,@"record-v1"),
                        (__bridge CFDictionaryRef)@{(__bridge id)kSecValueData:value})==errSecSuccess ? 0:3;
  }
  MWClear(marker);MWClear(old);return result;
}

static NSString *MWConfirmation(uint32_t operation,const uint8_t *intent,uint64_t length,uint8_t purpose) {
  if(operation==3 && (length!=288 || intent[141]!=purpose))return nil;
  if(operation==5 && (length!=198 || intent[164]!=purpose))return nil;
  uint8_t output[2048];uint64_t written=0;
  int status=morse_wallet_authorization_text(operation,intent,length,output,sizeof(output),&written);
  if(status!=0 || written>sizeof(output))return nil;
  return [[NSString alloc] initWithBytes:output length:(NSUInteger)written encoding:NSUTF8StringEncoding];
}

// One exact private command owns a single-use native confirmation window.
// Cancellation marks finished synchronously, including before main insertion.
@interface MDWalletConfirmation : NSObject
- (instancetype)initWithHost:(MorseDesktopWalletContext *)host operation:(uint32_t)operation message:(NSString *)message;
- (void)present;
- (BOOL)wait;
- (void)cancel;
@end
@implementation MDWalletConfirmation {
  MorseDesktopWalletContext *_host;
  NSLock *_gate;
  dispatch_semaphore_t _done;
  uint32_t _operation;
  NSString *_message;
  NSAlert *_alert;
  BOOL _finished, _approved;
}
- (instancetype)initWithHost:(MorseDesktopWalletContext *)host operation:(uint32_t)operation message:(NSString *)message {
  if ((self=[super init])) { _host=host;_operation=operation;_message=[message copy];_gate=[NSLock new];_done=dispatch_semaphore_create(0); }
  return self;
}
- (BOOL)finished { [_gate lock];BOOL value=_finished;[_gate unlock];return value; }
- (void)closeOnMain {
  NSAssert([NSThread isMainThread],@"native confirmation retirement");
  NSAlert *alert=_alert;_alert=nil;_message=nil;
  if (alert == nil) return;
  NSWindow *window=alert.window;
  if (window.sheetParent != nil) [window.sheetParent endSheet:window returnCode:NSModalResponseCancel];
  [window orderOut:nil];
  MDNativeProtectionReleaseAuxiliary(_host.protection,_host.scope.window_id,_host.scope.page_id,(__bridge void *)window);
}
- (void)settle:(BOOL)approved {
  [_gate lock];
  if (_finished) { [_gate unlock];return; }
  _finished=YES;_approved=approved;[_gate unlock];
  dispatch_semaphore_signal(_done);
  if ([NSThread isMainThread]) [self closeOnMain];
  else dispatch_async(dispatch_get_main_queue(), ^{ [self closeOnMain]; });
}
- (void)cancel { [self settle:NO]; }
- (void)present {
  NSAssert([NSThread isMainThread],@"native confirmation presentation");
  if (self.finished || !MWCurrent(_host)) { [self cancel];return; }
  NSWindow *parent=(__bridge NSWindow *)MDNativeProtectionPrimary(_host.protection,_host.scope.window_id,_host.scope.page_id);
  if (parent == nil || parent.attachedSheet != nil) { [self cancel];return; }
  NSAlert *alert=[NSAlert new];
  alert.messageText=_operation==1?@"Create local wallet":_operation==5?@"Confirm bounty transfer":@"Confirm credit payment";
  alert.informativeText=_message;
  [alert addButtonWithTitle:_operation==1?@"Create wallet":_operation==5?@"Move bounty":@"Confirm payment"];
  [alert addButtonWithTitle:@"Cancel"];
  _alert=alert;
  __weak MDWalletConfirmation *weakSelf=self;
  if (!MDNativeProtectionBindAuxiliary(_host.protection,_host.scope.window_id,_host.scope.page_id,(__bridge void *)alert.window,^{ [weakSelf cancel]; }) ||
      self.finished || !MWCurrent(_host)) { [self cancel];return; }
  [alert beginSheetModalForWindow:parent completionHandler:^(NSModalResponse response) {
    MDWalletConfirmation *held=weakSelf;
    if (held == nil) return;
    BOOL current=MWCurrent(held->_host) && MDNativeProtectionPrimary(held->_host.protection,held->_host.scope.window_id,held->_host.scope.page_id) != NULL;
    [held settle:current && response==NSAlertFirstButtonReturn];
  }];
  // beginSheet can reenter covering/owner retirement before returning.
  if (self.finished || !MWCurrent(_host)) { [self cancel];[self closeOnMain]; }
}
- (BOOL)wait {
  if (dispatch_semaphore_wait(_done,dispatch_time(DISPATCH_TIME_NOW,60*NSEC_PER_SEC)) != 0) [self cancel];
  [_gate lock];BOOL value=_finished && _approved;[_gate unlock];return value;
}
@end
static int MWAuthorize(void *context,uint32_t operation,const uint8_t *intent,uint64_t length) {
  if ([NSThread isMainThread] || !intent) return 4;
  MorseDesktopWalletContext *host=(__bridge MorseDesktopWalletContext *)context;
  if (!MWCurrent(host)) return 4;
  NSString *message=MWConfirmation(operation,intent,length,host.purpose);if(!message)return 4;
  MDWalletConfirmation *job=[[MDWalletConfirmation alloc] initWithHost:host operation:operation message:message];
  dispatch_async(dispatch_get_main_queue(), ^{ [job present]; });
  BOOL approved=[job wait];
  return approved && MWCurrent(host) ? 0:4;
}

int32_t MorseDesktopWalletCall(void *protection, MDPrivateScope scope, const char *service,const char *directory,const uint8_t pins[34],uint32_t operation,const uint8_t *input,uint64_t input_length,uint8_t *output,uint64_t capacity,uint64_t *written) {
  @autoreleasepool {
    if(written)*written=0;
    if(!protection||!scope.context||!scope.retain||!scope.release||!scope.current||!scope.current(scope.context)||!service||!directory||!pins||pins[0]!=1||pins[1]>1||!written)return 1;
    uint8_t nonzero=0;for(int i=2;i<34;i++)nonzero|=pins[i];if(!nonzero)return 1;
    MorseDesktopWalletContext *host=[MorseDesktopWalletContext new];host.service=[NSString stringWithUTF8String:service];host.directory=[NSString stringWithUTF8String:directory];host.purpose=pins[1];host.descriptor=-1;host.protection=protection;scope.retain(scope.context);host.scope=scope;
    if(!host.service.length||!host.directory.isAbsolutePath)return 1;
    NSError *error=nil;
    if(![NSFileManager.defaultManager fileExistsAtPath:host.directory]) {
      if(![NSFileManager.defaultManager createDirectoryAtPath:host.directory withIntermediateDirectories:NO attributes:@{NSFilePosixPermissions:@0700} error:&error])return 3;
    }
    NSURL *url=[NSURL fileURLWithPath:host.directory isDirectory:YES];
    if(![url setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:&error])return 3;
    MorseWalletCallbacksV1 callbacks={0};callbacks.abi_version=1;callbacks.struct_size=sizeof(callbacks);callbacks.context=(__bridge void *)host;callbacks.acquire=MWAcquire;callbacks.load=MWLoad;callbacks.replace=MWReplace;callbacks.release=MWRelease;callbacks.authorize=MWAuthorize;memcpy(callbacks.usdc_mint,pins+2,32);callbacks.purpose=pins[1];
    if (!MWCurrent(host)) return 3;
    int32_t status=morse_wallet_call(&callbacks,operation,input,input_length,output,capacity,written);
    if(host.descriptor>=0)MWRelease((__bridge void *)host);
    return status;
  }
}
