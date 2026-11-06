#import "Policy.h"
#import <CoreFoundation/CoreFoundation.h>
#include <string.h>

static const uint64_t MDMaximumSequence = 9007199254740990ULL;
static NSArray<NSString *> *MDPolicies(void) {
    return @[@"disabled", @"enable_pending", @"enabled", @"disable_pending"];
}
static BOOL MDSamePolicy(MDPolicyValue a, MDPolicyValue b) {
    return memcmp(a.install,b.install,16) == 0 && a.sequence == b.sequence && a.policy == b.policy;
}
static NSString *MDInstall(MDPolicyValue value) {
    return [[[NSUUID alloc] initWithUUIDBytes:value.install].UUIDString lowercaseString];
}
static NSData *MDMarker(MDPolicyValue value) {
    return [[NSString stringWithFormat:@"AL1:%@\n", MDInstall(value)] dataUsingEncoding:NSUTF8StringEncoding];
}
static NSData *MDEncode(MDPolicyValue value) {
    if (value.policy > MDPolicyDisablePending || value.sequence > MDMaximumSequence) return nil;
    return [[NSString stringWithFormat:@"{\"version\":1,\"install\":\"%@\",\"sequence\":%llu,\"policy\":\"%@\"}",
        MDInstall(value),(unsigned long long)value.sequence,MDPolicies()[value.policy]] dataUsingEncoding:NSUTF8StringEncoding];
}
static BOOL MDDecode(NSData *bytes, MDPolicyValue *record) {
    if (bytes.length < 1 || bytes.length > 4096) return NO;
    id object = [NSJSONSerialization JSONObjectWithData:bytes options:0 error:NULL];
    if (![object isKindOfClass:NSDictionary.class] || [object count] != 4 ||
        ![[NSSet setWithArray:[object allKeys]] isEqual:[NSSet setWithArray:@[@"version",@"install",@"sequence",@"policy"]]]) return NO;
    id version = object[@"version"], sequence = object[@"sequence"], install = object[@"install"], policy = object[@"policy"];
    if (![version isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)version) == CFBooleanGetTypeID() ||
        ![version isEqual:@1] || ![sequence isKindOfClass:NSNumber.class] ||
        CFGetTypeID((__bridge CFTypeRef)sequence) == CFBooleanGetTypeID() || ![install isKindOfClass:NSString.class] ||
        ![policy isKindOfClass:NSString.class]) return NO;
    NSUUID *uuid = [[NSUUID alloc] initWithUUIDString:install];
    if (uuid == nil || ![[uuid.UUIDString lowercaseString] isEqual:install]) return NO;
    NSUInteger state = [MDPolicies() indexOfObject:policy];
    if (state == NSNotFound) return NO;
    MDPolicyValue result; [uuid getUUIDBytes:result.install];
    result.sequence = [sequence unsignedLongLongValue]; result.policy = (MDPolicyState)state;
    // Re-encoding rejects duplicate/unknown fields, fractional/exponent/negative
    // numbers, alternate UUID encodings and every whitespace/trailing variant.
    if (![MDEncode(result) isEqual:bytes]) return NO;
    *record = result; return YES;
}
static BOOL MDPermits(MDPolicyState previous, MDPolicyState desired) {
    if (desired == MDPolicyEnablePending) return previous == MDPolicyDisabled || previous == MDPolicyEnablePending || previous == MDPolicyDisablePending;
    if (desired == MDPolicyDisablePending) return previous == MDPolicyEnabled || previous == MDPolicyEnablePending || previous == MDPolicyDisablePending;
    return (previous == MDPolicyEnablePending && desired == MDPolicyEnabled) ||
        (previous == MDPolicyDisablePending && desired == MDPolicyDisabled);
}
static NSLock *MDPolicyWriter(void) {
    static NSLock *writer; static dispatch_once_t once;
    dispatch_once(&once, ^{ writer = [NSLock new]; }); return writer;
}

@implementation MDInstallationPolicy {
    id<MDPolicyStorage> _storage;
    NSUUID *(^_makeInstall)(void);
}
- (instancetype)initWithStorage:(id<MDPolicyStorage>)storage makeInstall:(NSUUID *(^)(void))makeInstall {
    if ((self = [super init])) { _storage = storage; _makeInstall = [makeInstall copy]; }
    return self;
}
- (MDPolicyStatus)load:(MDPolicyValue *)record {
    if ([NSThread isMainThread]) return MDPolicyBackgroundRequired;
    [MDPolicyWriter() lock];
    @try { return [self loadLocked:record]; }
    @finally { [MDPolicyWriter() unlock]; }
}
- (MDPolicyStatus)transition:(MDPolicyValue)previous desired:(MDPolicyState)desired result:(MDPolicyValue *)record {
    if ([NSThread isMainThread]) return MDPolicyBackgroundRequired;
    [MDPolicyWriter() lock];
    @try {
        MDPolicyValue actual;
        MDPolicyStatus status = [self loadLocked:&actual]; if (status != MDPolicyOK) return status;
        if (!MDSamePolicy(previous,actual)) return MDPolicyChanged;
        if (previous.sequence >= MDMaximumSequence || !MDPermits(previous.policy,desired)) return MDPolicyUnreadable;
        MDPolicyValue next = previous; next.sequence++; next.policy = desired;
        if ([_storage updateRecord:MDEncode(next)] != MDPolicyOK) return MDPolicyUnreadable;
        return [self verify:next result:record];
    } @finally { [MDPolicyWriter() unlock]; }
}
- (MDPolicyStatus)loadLocked:(MDPolicyValue *)record {
    NSData *marker = nil, *bytes = nil;
    if ([_storage readMarker:&marker] != MDPolicyOK || [_storage readRecord:&bytes] != MDPolicyOK) return MDPolicyUnreadable;
    if (bytes != nil) {
        MDPolicyValue existing;
        if (!MDDecode(bytes,&existing)) return MDPolicyUnreadable;
        if (marker != nil) {
            if (![marker isEqual:MDMarker(existing)]) return MDPolicyUnreadable;
        } else {
            NSData *readback = nil;
            if ([_storage createMarker:MDMarker(existing)] != MDPolicyOK ||
                [_storage readMarker:&readback] != MDPolicyOK || ![readback isEqual:MDMarker(existing)]) return MDPolicyUnreadable;
        }
        *record = existing; return MDPolicyOK;
    }
    if (marker != nil) return MDPolicyUnreadable;
    NSUUID *uuid = _makeInstall(); if (uuid == nil) return MDPolicyUnreadable;
    MDPolicyValue initial = {.sequence = 0, .policy = MDPolicyDisabled}; [uuid getUUIDBytes:initial.install];
    NSData *readback = nil;
    if ([_storage createMarker:MDMarker(initial)] != MDPolicyOK ||
        [_storage readMarker:&readback] != MDPolicyOK || ![readback isEqual:MDMarker(initial)] ||
        [_storage createRecord:MDEncode(initial)] != MDPolicyOK) return MDPolicyUnreadable;
    return [self verify:initial result:record];
}
- (MDPolicyStatus)verify:(MDPolicyValue)expected result:(MDPolicyValue *)record {
    NSData *marker = nil, *bytes = nil; MDPolicyValue actual;
    if ([_storage readRecord:&bytes] != MDPolicyOK || !MDDecode(bytes,&actual) || !MDSamePolicy(expected,actual) ||
        [_storage readMarker:&marker] != MDPolicyOK || ![marker isEqual:MDMarker(expected)]) return MDPolicyUnreadable;
    *record = expected; return MDPolicyOK;
}
@end
