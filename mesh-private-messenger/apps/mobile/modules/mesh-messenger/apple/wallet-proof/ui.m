#import "../MorseWalletApple.m"

@interface WalletProof : NSObject
@property NSString *service;
@property NSString *directory;
@property NSWindow *window;
@property NSTextField *status;
@property NSButton *next;
@property NSUInteger step;
@property NSData *address;
@property(atomic) BOOL backgroundObserved;
@property BOOL failed;
@end
@implementation WalletProof
- (void)cleanup {
  MorseWalletAppleContext *host=[MorseWalletAppleContext new];host.service=self.service;
  for(NSString *name in @[@"record-v1",@"initialized-v1",@"lock-v1"])SecItemDelete((__bridge CFDictionaryRef)MWQuery(host,name));
  [NSFileManager.defaultManager removeItemAtPath:self.directory error:nil];
}
- (void)advance:(id)sender {
  (void)sender;
  if(self.step==5){
    [self cleanup];if(!self.failed)puts("Apple native UI proof passed: cancel/create, persisted address, actual payment button, real background cancellation.");fflush(stdout);
    [NSApp terminate:nil];return;
  }
  if(!NSApp.isActive){self.status.stringValue=@"Bring this proof app to the foreground before starting a step.";return;}
  const NSUInteger step=self.step;self.next.enabled=NO;self.backgroundObserved=NO;
  __block id backgroundObserver=nil;
  if(step==4)backgroundObserver=[NSNotificationCenter.defaultCenter addObserverForName:NSApplicationDidResignActiveNotification object:nil queue:nil usingBlock:^(NSNotification *note){(void)note;self.backgroundObserved=YES;}];
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{@autoreleasepool{
    uint8_t pins[34]={1,1};memset(pins+2,7,32);
    uint8_t input[256]={1,'C','Q','T'};
    memset(input+4,7,32);memset(input+36,8,64);input[132]=1;
    memset(input+133,255,8);input[141]=1;input[143]=100;
    uint64_t now=(uint64_t)NSDate.date.timeIntervalSince1970;
    for(int i=7;i>=0;i--){input[144+i]=(now>>(8*(7-i)))&255;input[152+i]=((now+900)>>(8*(7-i)))&255;}
    memset(input+160,7,64);memset(input+224,9,32);
    uint8_t output[1232]={0};uint64_t written=0;
    uint32_t operation=step<2?1:step==2?2:3;
    int status=MorseWalletAppleCall(self.service.UTF8String,self.directory.fileSystemRepresentation,pins,operation,step>=3?input:NULL,step>=3?sizeof(input):0,output,sizeof(output),&written);
    if(backgroundObserver)[NSNotificationCenter.defaultCenter removeObserver:backgroundObserver];
    BOOL okay=step==4 ? status==4&&written==0&&self.backgroundObserved : step==0 ? status==4&&written==0 : step==1 ? status==0&&written==32 : step==2 ? status==0&&written==32&&[self.address isEqualToData:[NSData dataWithBytes:output length:32]] : status==0&&written>64;
    NSData *address=step==1&&okay?[NSData dataWithBytes:output length:32]:nil;
    dispatch_async(dispatch_get_main_queue(),^{
      if(!okay){self.status.stringValue=[NSString stringWithFormat:@"FAILED step %lu: status %d bytes %llu",(unsigned long)step,status,(unsigned long long)written];fprintf(stderr,"%s\n",self.status.stringValue.UTF8String);self.failed=YES;self.step=5;self.next.title=@"Clean failed proof";self.next.enabled=YES;return;}
      if(address)self.address=address;self.step=step+1;
      self.status.stringValue=[NSString stringWithFormat:@"Passed step %lu of 5. No RPC or payment is sent.",(unsigned long)self.step];
      self.next.title=@[@"Test canceled creation",@"Create disposable wallet",@"Check stored address",@"Sign local test packet",@"Test background cancellation",@"Finish proof"][self.step];self.next.enabled=YES;
    });
  }});
}
@end
int main(void){@autoreleasepool{
  NSApplication *app=NSApplication.sharedApplication;[app setActivationPolicy:NSApplicationActivationPolicyRegular];
  WalletProof *proof=[WalletProof new];proof.service=[@"app.morse.wallet.disposable-ui-proof." stringByAppendingString:NSUUID.UUID.UUIDString];
  proof.directory=[NSTemporaryDirectory() stringByAppendingPathComponent:[@"wallet-ui-proof-" stringByAppendingString:NSUUID.UUID.UUIDString]];
  if(![NSFileManager.defaultManager createDirectoryAtPath:proof.directory withIntermediateDirectories:NO attributes:@{NSFilePosixPermissions:@0700} error:nil])return 1;
  NSWindow *window=[[NSWindow alloc] initWithContentRect:NSMakeRect(300,300,520,180) styleMask:NSWindowStyleMaskTitled backing:NSBackingStoreBuffered defer:NO];window.title=@"Morse disposable wallet proof";proof.window=window;
  proof.status=[NSTextField wrappingLabelWithString:@"Disposable native custody proof. Local signing only; no RPC or payment is sent."];
  proof.status.frame=NSMakeRect(20,75,480,80);[window.contentView addSubview:proof.status];
  proof.next=[NSButton buttonWithTitle:@"Test canceled creation" target:proof action:@selector(advance:)];proof.next.frame=NSMakeRect(20,20,320,40);[window.contentView addSubview:proof.next];
  [window makeKeyAndOrderFront:nil];[app run];[proof cleanup];
}return 0;}
