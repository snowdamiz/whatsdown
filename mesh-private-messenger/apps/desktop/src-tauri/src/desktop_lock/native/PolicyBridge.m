#import "PolicyBridge.h"
#import "Policy.h"
#import "ProcessOwner.h"
#include <string.h>

@interface MDNativePolicyContext : NSObject
@property(nonatomic, strong) MDProcessOwner *owner;
@property(nonatomic, strong) MDInstallationPolicy *policy;
@end
@implementation MDNativePolicyContext
@end

// Shared by the system constructor and the explicitly separate test-only port.
// There is one actual policy and owner implementation, not a fixture FSM.
static void *MDMakePolicy(NSURL *directory, id<MDPolicyStorage> anchor, id<MDPolicyStorage> storage, int32_t *failure) {
    MDProcessOwnerStatus status;
    MDProcessOwner *owner = [MDProcessOwner acquireInDirectory:directory anchorStorage:anchor status:&status];
    if (owner == nil) { *failure = status == MDProcessOwnerBusy ? 2 : 1; return NULL; }
    MDNativePolicyContext *context = [MDNativePolicyContext new]; context.owner = owner;
    context.policy = [[MDInstallationPolicy alloc] initWithStorage:storage makeInstall:^{ return [NSUUID UUID]; }];
    if (!owner.current || context.policy == nil) { [owner close]; *failure = 1; return NULL; }
    *failure = 0; return (__bridge_retained void *)context;
}
void *MDNativePolicyOpen(const char *bundleIdentifier, const char *appDataDirectory, int32_t *failure) {
    if (failure == NULL) return NULL;
    *failure = 1;
    if ([NSThread isMainThread] || bundleIdentifier == NULL || appDataDirectory == NULL) return NULL;
    @autoreleasepool {
        @try {
            NSString *bundle = [[NSString alloc] initWithUTF8String:bundleIdentifier];
            NSString *root = [[NSString alloc] initWithUTF8String:appDataDirectory];
            if (bundle.length == 0 || bundle.length > 200 || !root.isAbsolutePath) return NULL;
            NSURL *directory = [[NSURL fileURLWithPath:root isDirectory:YES] URLByAppendingPathComponent:@"morse-desktop-app-lock-v1" isDirectory:YES];
            MDKeychainPolicyStorage *anchor = [[MDKeychainPolicyStorage alloc] initWithService:[bundle stringByAppendingString:@".desktop-app-lock.owner.v1"] directory:directory];
            MDKeychainPolicyStorage *storage = [[MDKeychainPolicyStorage alloc] initWithService:[bundle stringByAppendingString:@".desktop-app-lock.v1"] directory:directory];
            if (anchor == nil || storage == nil) return NULL;
            return MDMakePolicy(directory,anchor,storage,failure);
        } @catch (NSException *error) { (void)error; return NULL; }
    }
}
bool MDNativePolicyCurrent(void *raw) {
    if (raw == NULL) return false;
    @autoreleasepool {
        @try { return ((__bridge MDNativePolicyContext *)raw).owner.current; }
        @catch (NSException *error) { (void)error; return false; }
    }
}
int MDNativePolicyDuplicateOwnedDirectory(void *raw) {
    if (raw==NULL) return -1;
    @autoreleasepool {
        @try { return [((__bridge MDNativePolicyContext *)raw).owner duplicateOwnedDirectory]; }
        @catch (NSException *error) { (void)error;return -1; }
    }
}
static int32_t MDCopyPolicy(MDNativePolicyContext *context, MDPolicyStatus status, MDPolicyValue value,
    uint8_t install[16], uint64_t *sequence, uint32_t *policy) {
    if (!context.owner.current) return MDPolicyUnreadable;
    if (status != MDPolicyOK) return status;
    memcpy(install,value.install,16); *sequence = value.sequence; *policy = value.policy; return MDPolicyOK;
}
int32_t MDNativePolicyRead(void *raw, uint8_t install[16], uint64_t *sequence, uint32_t *policy) {
    if (raw == NULL || install == NULL || sequence == NULL || policy == NULL) return MDPolicyUnreadable;
    @autoreleasepool {
        @try {
            MDNativePolicyContext *context = (__bridge MDNativePolicyContext *)raw;
            if (!context.owner.current) return MDPolicyUnreadable;
            MDPolicyValue value = {0}; MDPolicyStatus status = [context.policy load:&value];
            return MDCopyPolicy(context,status,value,install,sequence,policy);
        } @catch (NSException *error) { (void)error; return MDPolicyUnreadable; }
    }
}
int32_t MDNativePolicyTransition(void *raw, const uint8_t previousInstall[16], uint64_t previousSequence,
    uint32_t previousPolicy, uint32_t desired, uint8_t install[16], uint64_t *sequence, uint32_t *policy) {
    if (raw == NULL || previousInstall == NULL || install == NULL || sequence == NULL || policy == NULL ||
        previousPolicy > MDPolicyDisablePending || desired > MDPolicyDisablePending) return MDPolicyUnreadable;
    @autoreleasepool {
        @try {
            MDNativePolicyContext *context = (__bridge MDNativePolicyContext *)raw;
            if (!context.owner.current) return MDPolicyUnreadable;
            MDPolicyValue previous = {0}, next = {0}; memcpy(previous.install,previousInstall,16);
            previous.sequence = previousSequence; previous.policy = (MDPolicyState)previousPolicy;
            MDPolicyStatus status = [context.policy transition:previous desired:(MDPolicyState)desired result:&next];
            return MDCopyPolicy(context,status,next,install,sequence,policy);
        } @catch (NSException *error) { (void)error; return MDPolicyUnreadable; }
    }
}
void MDNativePolicyRetain(void *raw) { if (raw != NULL) CFRetain(raw); }
void MDNativePolicyRelease(void *raw) { if (raw != NULL) CFRelease(raw); }

#if defined(MD_NATIVE_TEST_PORTS)
// Implemented test factory supplies raw storage ports; there is no such entry
// in product builds and no configurable production caller-plan/approval input.
void *MDNativePolicyWithTestPorts(NSURL *directory, id<MDPolicyStorage> anchor, id<MDPolicyStorage> storage) {
    int32_t failure = 1; return MDMakePolicy(directory,anchor,storage,&failure);
}
#endif
