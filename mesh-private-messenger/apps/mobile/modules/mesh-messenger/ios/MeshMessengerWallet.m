#import "MeshMessengerWallet.h"
#import "MeshMessengerSecureStore.h"
#import "MorseWalletApple.h"
#import <Foundation/Foundation.h>

int32_t MeshMessengerWalletCall(uint32_t operation,const uint8_t *input,uint64_t length,uint8_t *output,uint64_t capacity,uint64_t *written) {
  @autoreleasepool {
    uint8_t pins[34];if(MeshMessengerWalletPins(pins)!=0)return 1;
    NSString *bundle=NSBundle.mainBundle.bundleIdentifier;
    NSURL *support=[NSFileManager.defaultManager URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask].firstObject;
    if(!bundle.length||!support)return 3;
    NSError *error=nil;
    if(![NSFileManager.defaultManager createDirectoryAtURL:support withIntermediateDirectories:YES attributes:nil error:&error])return 3;
    NSString *service=[NSString stringWithFormat:@"%@.wallet.v1.%u",bundle,pins[1]];
    NSString *directory=[[support URLByAppendingPathComponent:[NSString stringWithFormat:@"MorseWallet-v1-%u",pins[1]] isDirectory:YES] path];
    return MorseWalletAppleCall(service.UTF8String,directory.fileSystemRepresentation,pins,operation,input,length,output,capacity,written);
  }
}
