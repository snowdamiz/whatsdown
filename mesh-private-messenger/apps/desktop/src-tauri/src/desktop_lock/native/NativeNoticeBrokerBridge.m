#import "NativeNoticeBrokerBridge.h"
#import "NativeNoticeBroker.h"
#import "ProtectionBridge.h"
#include <string.h>
@interface MDNoticeWakeOwner:NSObject
@property(nonatomic) MDNativeNoticeWake callbacks;
- (void)notify;
@end
@implementation MDNoticeWakeOwner
- (void)notify { MDNativeNoticeWake c=_callbacks;c.wake(c.context); }
- (void)dealloc { MDNativeNoticeWake c=_callbacks;dispatch_async(dispatch_get_main_queue(),^{c.release(c.context);}); }
@end
@interface MDNoticeBridgeContext:NSObject
@property(nonatomic) void *protection;
@property(nonatomic,strong) MDNativeNoticeBroker *broker;
@end
@implementation MDNoticeBridgeContext
- (void)dealloc { if(_protection)CFRelease(_protection); }
@end
static void erase(void *bytes,size_t length) {volatile unsigned char*p=bytes;while(length--)*p++=0;}
static NSString *text(const uint8_t *bytes,uint64_t length,uint64_t maximum) {
    if(length>maximum || (length && bytes==NULL) || (length && memchr(bytes,0,(size_t)length)))return nil;
    return length?[[NSString alloc]initWithBytes:bytes length:(NSUInteger)length encoding:NSUTF8StringEncoding]:@"";
}
static BOOL validScope(const uint8_t *scope,uint64_t length) {
    if(scope==NULL)return NO;uint64_t start;
    if(length==37&&memcmp(scope,"chat/",5)==0)start=5;
    else if(length==70&&memcmp(scope,"group/",6)==0)start=6;
    else return NO;
    for(uint64_t i=start;i<length;i++)if(!(scope[i]>='0'&&scope[i]<='9')&&!(scope[i]>='a'&&scope[i]<='f'))return NO;
    return YES;
}
#if defined(MD_NATIVE_TEST_PORTS)
static MDNativeNoticeBroker *(^testFactory)(dispatch_block_t);
void MDNativeNoticeBrokerSetFactoryForTest(MDNativeNoticeBroker *(^factory)(dispatch_block_t)) {
    NSCAssert(NSThread.isMainThread,@"native broker test factory");testFactory=factory;
}
#endif
void *MDNativeNoticeBrokerCreate(void *protection,MDNativeNoticeWake callbacks) {
    if(!NSThread.isMainThread || protection==NULL || callbacks.context==NULL || callbacks.retain==NULL ||
       callbacks.release==NULL || callbacks.wake==NULL)return NULL;
    __attribute__((objc_precise_lifetime)) MDNoticeWakeOwner *wake=nil;
    __attribute__((objc_precise_lifetime)) MDNativeNoticeBroker *broker=nil;
    @try {
        wake=[MDNoticeWakeOwner new];if(wake==nil)return NULL;wake.callbacks=callbacks;callbacks.retain(callbacks.context);
#if defined(MD_NATIVE_TEST_PORTS)
        if(testFactory!=nil) {
            broker=testFactory(^{[wake notify];});
        } else {
            broker=[MDNativeNoticeBroker prepareWithWake:^{[wake notify];}];
        }
        if(broker==nil)return NULL;
#else
        broker=[MDNativeNoticeBroker prepareWithWake:^{[wake notify];}];if(broker==nil)return NULL;
#endif
        if(!MDNativeProtectionInstallNoticeBroker(protection,broker.hooks)){[broker close];return NULL;}
        if(![broker activate]){[broker close];return NULL;}
        MDNoticeBridgeContext *context=[MDNoticeBridgeContext new];if(context==nil){[broker close];return NULL;}
        context.protection=protection;CFRetain(protection);context.broker=broker;
        return(__bridge_retained void*)context;
    }@catch(__unused NSException *error){[broker close];return NULL;}
}
typedef struct {
    __unsafe_unretained MDNativeNoticeBroker *broker;
    __unsafe_unretained MDNativeNoticeAuthorization *authorization;
    __unsafe_unretained NSString *title,*body,*scope;
    bool failed;
} PublishFrame;
static bool publishFrame(void *raw,MDNativeNoticeReceipt receipt) {
    PublishFrame *frame=raw;
    @try {return [frame->broker publishTitle:frame->title body:frame->body scope:frame->scope authorization:frame->authorization receipt:receipt];}
    @catch(__unused NSException *error){frame->failed=true;return false;}
}
bool MDNativeNoticeBrokerPublish(void *protection,void *raw,MDPrivateScope action,uint64_t account,
    const uint8_t *titleBytes,uint64_t titleLength,const uint8_t *bodyBytes,uint64_t bodyLength,
    const uint8_t *scopeBytes,uint64_t scopeLength) {
    if(!NSThread.isMainThread || raw==NULL || protection==NULL || !validScope(scopeBytes,scopeLength))return false;
    __attribute__((objc_precise_lifetime)) MDNoticeBridgeContext *context=(__bridge MDNoticeBridgeContext*)raw;
    if(context.protection!=protection)return false;
    __attribute__((objc_precise_lifetime)) MDNativeNoticeAuthorization *authorization=nil;
    @try {
        __attribute__((objc_precise_lifetime)) NSString *title=text(titleBytes,titleLength,4096);
        __attribute__((objc_precise_lifetime)) NSString *body=text(bodyBytes,bodyLength,8192);
        __attribute__((objc_precise_lifetime)) NSString *scope=text(scopeBytes,scopeLength,70);
        if(title==nil || body==nil || scope==nil)return false;
        authorization=[[MDNativeNoticeAuthorization alloc]initWithScope:action];
        if(authorization==nil || !authorization.current)return false;
        PublishFrame frame={context.broker,authorization,title,body,scope,false};
        BOOL accepted=MDNativeProtectionPublishNotice(protection,action.window_id,action.page_id,account,&frame,publishFrame);
        if(frame.failed)[context.broker close];
        return accepted;
    }@catch(__unused NSException *error){[context.broker close];return false;}
}
typedef struct {__unsafe_unretained MDNativeNoticeBroker *broker;MDNoticeIntent *output;bool failed;} ConsumeFrame;
static bool consumeFrame(void *raw,MDNativeNoticeReceipt receipt) {ConsumeFrame *frame=raw;
    @try{return[frame->broker consumeReceipt:receipt output:frame->output];}
    @catch(__unused NSException *error){frame->failed=true;return false;}
}
bool MDNativeNoticeBrokerConsume(void *protection,void *raw,MDPrivateScope action,uint64_t account,MDNoticeIntent *output) {
    if(output==NULL)return false;erase(output,sizeof(*output));
    if(!NSThread.isMainThread || raw==NULL || protection==NULL)return false;
    __attribute__((objc_precise_lifetime)) MDNoticeBridgeContext *context=(__bridge MDNoticeBridgeContext*)raw;
    if(context.protection!=protection)return false;
    __attribute__((objc_precise_lifetime)) MDNativeNoticeAuthorization *authorization=nil;
    MDNoticeIntent result={0};BOOL accepted=NO;
    @try {
        authorization=[[MDNativeNoticeAuthorization alloc]initWithScope:action];
        if(authorization!=nil && authorization.current){
            ConsumeFrame frame={context.broker,&result,false};
            accepted=MDNativeProtectionConsumeNotice(protection,action.window_id,action.page_id,account,&frame,consumeFrame);
            if(frame.failed)[context.broker close];
            if(accepted)accepted=authorization.current;
        }
        if(accepted){
            accepted=(result.kind==MDNoticeIntentNone||result.kind==MDNoticeIntentInbox)?result.scope_length==0:
                result.kind==MDNoticeIntentScope&&validScope((const uint8_t*)result.scope,result.scope_length);
        }
        if(accepted)*output=result;
    }@catch(__unused NSException *error){[context.broker close];accepted=NO;}
    erase(&result,sizeof(result));if(!accepted)erase(output,sizeof(*output));return accepted;
}
void MDNativeNoticeBrokerRetireInvalid(void *raw){if(raw!=NULL&&NSThread.isMainThread)[((__bridge MDNoticeBridgeContext*)raw).broker retireInvalid];}
void MDNativeNoticeBrokerClose(void *raw){if(raw!=NULL)[((__bridge MDNoticeBridgeContext*)raw).broker close];}
void MDNativeNoticeBrokerRelease(void *raw){if(raw==NULL)return;MDNativeNoticeBrokerClose(raw);dispatch_async(dispatch_get_main_queue(),^{MDNoticeBridgeContext *context=(__bridge_transfer MDNoticeBridgeContext*)raw;[context.broker close];});}
