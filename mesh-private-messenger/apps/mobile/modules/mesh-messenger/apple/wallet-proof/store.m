#import "../MorseWalletApple.m"

static void check(BOOL okay, NSString *message) {
  if(!okay) {fprintf(stderr,"FAIL: %s\n",message.UTF8String);exit(1);}
}
static MorseWalletAppleContext *context(NSString *service,NSString *directory) {
  MorseWalletAppleContext *host=[MorseWalletAppleContext new];host.service=service;host.directory=directory;host.descriptor=-1;host.purpose=1;return host;
}
static int reserve(NSString *service,NSString *directory) {
  uint8_t pins[34]={1,1};memset(pins+2,7,32);
  uint8_t output[1232]={0};uint64_t written=0;
  int status=MorseWalletAppleCall(service.UTF8String,directory.fileSystemRepresentation,pins,4,NULL,0,output,sizeof(output),&written);
  if(status || written!=40)return 1;
  uint64_t index=0;for(int i=7;i>=0;i--)index=(index<<8)|output[i];
  printf("%llu\n",(unsigned long long)index);return 0;
}
int main(int argc,const char **argv) {
  @autoreleasepool {
    if(argc==4 && !strcmp(argv[1],"reserve"))return reserve(@(argv[2]),@(argv[3]));
    NSString *service=[@"app.morse.wallet.disposable-proof." stringByAppendingString:NSUUID.UUID.UUIDString];
    NSString *directory=[NSTemporaryDirectory() stringByAppendingPathComponent:[@"wallet-proof-" stringByAppendingString:NSUUID.UUID.UUIDString]];
    check([NSFileManager.defaultManager createDirectoryAtPath:directory withIntermediateDirectories:NO attributes:@{NSFilePosixPermissions:@0700} error:nil],@"private directory");
    MorseWalletAppleContext *host=context(service,directory);
    @try {
      check(MWAcquire((__bridge void *)host)==0,@"acquire");
      uint8_t bytes[44]={0};uint64_t count=999;
      check(MWLoad((__bridge void *)host,bytes,44,&count)==2 && count==0,@"genuine absence");
      memcpy(bytes,"MWL1",4);memset(bytes+4,0x37,32);
      check(MWReplace((__bridge void *)host,bytes,44)==0,@"durable credential write");
      memset(bytes,0,44);
      check(MWLoad((__bridge void *)host,bytes,44,&count)==0 && count==44 && bytes[4]==0x37,@"credential roundtrip");
      check(MWRelease((__bridge void *)host)==0,@"release");
      NSMutableArray<NSTask *> *tasks=[NSMutableArray array];NSMutableArray<NSPipe *> *pipes=[NSMutableArray array];
      for(int i=0;i<16;i++) {
        NSTask *task=[NSTask new];task.executableURL=[NSURL fileURLWithPath:@(argv[0])];task.arguments=@[@"reserve",service,directory];
        NSPipe *pipe=NSPipe.pipe;task.standardOutput=pipe;
        check([task launchAndReturnError:nil],@"spawn peer process");[tasks addObject:task];[pipes addObject:pipe];
      }
      NSMutableSet *indices=[NSMutableSet set];
      for(NSUInteger i=0;i<tasks.count;i++) {
        [tasks[i] waitUntilExit];check(tasks[i].terminationStatus==0,@"peer reserve");
        NSString *value=[[NSString alloc] initWithData:[pipes[i].fileHandleForReading readDataToEndOfFile] encoding:NSUTF8StringEncoding];
        [indices addObject:@(value.longLongValue)];
      }
      check(indices.count==16,@"cross-process indexes unique");for(int i=0;i<16;i++)check([indices containsObject:@(i)],@"no skipped/reused successful index");
      check(MWAcquire((__bridge void *)host)==0,@"reopen");
      check(MWLoad((__bridge void *)host,bytes,44,&count)==0 && bytes[36]==16,@"fresh highwater from credential store");
      check(MWRelease((__bridge void *)host)==0,@"release after peers");
      NSString *lock=[directory stringByAppendingPathComponent:@"custody.lock"];
      check([NSFileManager.defaultManager moveItemAtPath:lock toPath:[lock stringByAppendingString:@".old"] error:nil],@"simulate filesystem replacement");
      check(MWAcquire((__bridge void *)host)==3,@"replaced lock fails closed");
      check([NSFileManager.defaultManager removeItemAtPath:lock error:nil],@"remove rejected new lock");
      check([NSFileManager.defaultManager moveItemAtPath:[lock stringByAppendingString:@".old"] toPath:lock error:nil],@"restore original lock");
      check(MWAcquire((__bridge void *)host)==0,@"original lock restored");
      check(SecItemDelete((__bridge CFDictionaryRef)MWQuery(host,@"record-v1"))==errSecSuccess,@"simulate missing committed credential");
      check(MWLoad((__bridge void *)host,bytes,44,&count)==3 && count==0,@"missing committed record cannot reset");
      check(MWReplace((__bridge void *)host,bytes,44)==3,@"cannot overwrite missing committed record");
      check(MWRelease((__bridge void *)host)==0,@"release after corrupt state");
      uint8_t intent[288]={1,'C','Q','T'};intent[132]=1;intent[141]=1;intent[142]=0;intent[143]=100;
      memset(intent+133,255,8);memset(intent+4,7,32);memset(intent+36,8,32);memset(intent+68,8,32);memset(intent+160,7,64);memset(intent+224,9,64);intent[158]=3;intent[159]=132;
      NSString *text=MWConfirmation(3,intent,288,1);
      check([text containsString:@"18446744073.709551615 SOL"],@"full u64 financial text");
      check(MWConfirmation(3,intent,288,0)==nil,@"wrong purpose cannot prompt");
      puts("Apple credential custody proof passed: 16 peer processes, lock replacement, lost record, exact U64.");
    } @finally {
      if(host.descriptor>=0)MWRelease((__bridge void *)host);
      for(NSString *name in @[@"record-v1",@"initialized-v1",@"lock-v1"])SecItemDelete((__bridge CFDictionaryRef)MWQuery(host,name));
      [NSFileManager.defaultManager removeItemAtPath:directory error:nil];
    }
  }
  return 0;
}
