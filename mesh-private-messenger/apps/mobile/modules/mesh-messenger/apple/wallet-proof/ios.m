#import "../MorseWalletApple.m"

@interface IOSWalletProof : UIViewController
@property NSString *service;
@property NSString *directory;
@property UILabel *status;
@property UIButton *next;
@property NSUInteger step;
@property NSData *address;
@property(atomic) BOOL backgroundObserved;
@end
@implementation IOSWalletProof
- (void)record:(NSString *)value {
  self.status.text=value;
  NSURL *documents=[NSFileManager.defaultManager URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask].firstObject;
  [value writeToURL:[documents URLByAppendingPathComponent:@"wallet-proof-result.txt"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
}
- (void)viewDidLoad {
  [super viewDidLoad];self.view.backgroundColor=UIColor.systemBackgroundColor;
  NSString *previous=[NSUserDefaults.standardUserDefaults stringForKey:@"disposable-proof-service"];
  if([previous hasPrefix:@"app.morse.wallet.disposable-ios-proof."]) {
    MorseWalletAppleContext *old=[MorseWalletAppleContext new];old.service=previous;
    for(NSString *name in @[@"record-v1",@"initialized-v1",@"lock-v1"])SecItemDelete((__bridge CFDictionaryRef)MWQuery(old,name));
  }
  self.service=[@"app.morse.wallet.disposable-ios-proof." stringByAppendingString:NSUUID.UUID.UUIDString];
  [NSUserDefaults.standardUserDefaults setObject:self.service forKey:@"disposable-proof-service"];
  NSString *support=[NSFileManager.defaultManager URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask].firstObject.path;
  [NSFileManager.defaultManager createDirectoryAtPath:support withIntermediateDirectories:YES attributes:nil error:nil];
  self.directory=[support stringByAppendingPathComponent:[@"wallet-proof-" stringByAppendingString:NSUUID.UUID.UUIDString]];
  [NSFileManager.defaultManager createDirectoryAtPath:self.directory withIntermediateDirectories:NO attributes:@{NSFilePosixPermissions:@0700} error:nil];
  self.status=[UILabel new];self.status.numberOfLines=0;
  self.next=[UIButton buttonWithType:UIButtonTypeSystem];[self.next setTitle:@"Test canceled creation" forState:UIControlStateNormal];[self.next addTarget:self action:@selector(advance:) forControlEvents:UIControlEventTouchUpInside];
  UIStackView *stack=[[UIStackView alloc] initWithArrangedSubviews:@[self.status,self.next]];stack.axis=UILayoutConstraintAxisVertical;stack.spacing=24;stack.translatesAutoresizingMaskIntoConstraints=NO;[self.view addSubview:stack];
  [NSLayoutConstraint activateConstraints:@[[stack.leadingAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.leadingAnchor constant:20],[stack.trailingAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.trailingAnchor constant:-20],[stack.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor constant:40]]];
  [self record:@"Disposable iOS native custody proof. Local signing only; no RPC or payment is sent."];
}
- (void)advance:(id)sender {
  (void)sender;
  if(self.step==5){
    MorseWalletAppleContext *host=[MorseWalletAppleContext new];host.service=self.service;
    for(NSString *name in @[@"record-v1",@"initialized-v1",@"lock-v1"])SecItemDelete((__bridge CFDictionaryRef)MWQuery(host,name));
    [NSFileManager.defaultManager removeItemAtPath:self.directory error:nil];
    [self record:@"iOS native UI proof passed: cancel/create, persisted address, offline SDK signing, real background cancellation."];
    self.next.enabled=NO;return;
  }
  NSUInteger step=self.step;self.next.enabled=NO;self.backgroundObserved=NO;
  __block id backgroundObserver=nil;
  if(step==4)backgroundObserver=[NSNotificationCenter.defaultCenter addObserverForName:UIApplicationWillResignActiveNotification object:nil queue:nil usingBlock:^(NSNotification *note){(void)note;self.backgroundObserved=YES;}];
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{@autoreleasepool{
    uint8_t pins[34]={1,1};memset(pins+2,7,32);
    uint8_t input[256]={1,'C','Q','T'};memset(input+4,7,32);memset(input+36,8,64);input[132]=1;memset(input+133,255,8);input[141]=1;input[143]=100;
    uint64_t now=(uint64_t)NSDate.date.timeIntervalSince1970;
    for(int i=7;i>=0;i--){input[144+i]=(now>>(8*(7-i)))&255;input[152+i]=((now+900)>>(8*(7-i)))&255;}
    memset(input+160,7,64);memset(input+224,9,32);
    uint8_t output[1232]={0};uint64_t written=0;uint32_t operation=step<2?1:step==2?2:3;
    int status=MorseWalletAppleCall(self.service.UTF8String,self.directory.fileSystemRepresentation,pins,operation,step>=3?input:NULL,step>=3?sizeof(input):0,output,sizeof(output),&written);
    if(backgroundObserver)[NSNotificationCenter.defaultCenter removeObserver:backgroundObserver];
    BOOL okay=step==4 ? status==4&&written==0&&self.backgroundObserved : step==0 ? status==4&&written==0 : step==1 ? status==0&&written==32 : step==2 ? status==0&&written==32&&[self.address isEqualToData:[NSData dataWithBytes:output length:32]] : status==0&&written>64;
    NSData *address=step==1&&okay?[NSData dataWithBytes:output length:32]:nil;
    dispatch_async(dispatch_get_main_queue(),^{
      if(!okay){[self record:[NSString stringWithFormat:@"FAILED step %lu: status %d bytes %llu",(unsigned long)step,status,(unsigned long long)written]];return;}
      if(address)self.address=address;self.step=step+1;
      [self record:[NSString stringWithFormat:@"Passed step %lu of 5. No RPC or payment is sent.",(unsigned long)self.step]];
      [self.next setTitle:@[@"Test canceled creation",@"Create disposable wallet",@"Check stored address",@"Sign local test packet",@"Test background cancellation",@"Finish proof"][self.step] forState:UIControlStateNormal];self.next.enabled=YES;
    });
  }});
}
@end
@interface ProofScene : UIResponder<UIWindowSceneDelegate>
@property(nonatomic,strong,nullable) UIWindow *window;
@end
@implementation ProofScene
- (void)scene:(UIScene *)scene willConnectToSession:(UISceneSession *)session options:(UISceneConnectionOptions *)options {
  (void)session;(void)options;self.window=[[UIWindow alloc] initWithWindowScene:(UIWindowScene *)scene];self.window.rootViewController=[IOSWalletProof new];[self.window makeKeyAndVisible];
}
@end
@interface ProofApp : UIResponder<UIApplicationDelegate>
@end
@implementation ProofApp
- (UISceneConfiguration *)application:(UIApplication *)application configurationForConnectingSceneSession:(UISceneSession *)session options:(UISceneConnectionOptions *)options {
  (void)application;(void)options;UISceneConfiguration *config=[[UISceneConfiguration alloc] initWithName:@"Proof" sessionRole:session.role];config.delegateClass=ProofScene.class;return config;
}
@end
int main(int argc,char **argv){@autoreleasepool{return UIApplicationMain(argc,argv,nil,NSStringFromClass(ProofApp.class));}}
