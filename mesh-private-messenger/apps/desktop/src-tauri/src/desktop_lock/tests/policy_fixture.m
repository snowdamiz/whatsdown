#import "Policy.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

extern void *MDNativePolicyWithTestPorts(NSURL *, id<MDPolicyStorage>, id<MDPolicyStorage>);
// Only raw IO is controlled. The owner lock, canonical policy, checked CAS,
// C ABI and Rust PolicyStore are the actual production implementations.
@interface MDBridgeStorage : NSObject <MDPolicyStorage>
@property(nonatomic, strong) NSData *marker;
@property(nonatomic, strong) NSData *record;
@property(nonatomic) uint32_t fault;
@end
@implementation MDBridgeStorage
- (MDPolicyStatus)readMarker:(NSData **)bytes { *bytes = _marker; return MDPolicyOK; }
- (MDPolicyStatus)readRecord:(NSData **)bytes {
    if (_fault == 3) { _fault = 0; return MDPolicyUnreadable; }
    *bytes = _record; return MDPolicyOK;
}
- (MDPolicyStatus)createMarker:(NSData *)bytes {
    if (_marker != nil) return MDPolicyUnreadable;
    _marker = [bytes copy]; return MDPolicyOK;
}
- (MDPolicyStatus)createRecord:(NSData *)bytes {
    if (_record != nil) return MDPolicyUnreadable;
    _record = [bytes copy]; return MDPolicyOK;
}
- (MDPolicyStatus)updateRecord:(NSData *)bytes {
    if (_record == nil) return MDPolicyUnreadable;
    uint32_t fault = _fault; _fault = 0;
    if (fault == 1) return MDPolicyUnreadable;
    _record = [bytes copy]; return fault == 2 ? MDPolicyUnreadable : MDPolicyOK;
}
@end
@interface MDBridgeFixture : NSObject
@property(nonatomic, strong) NSURL *directory;
@property(nonatomic, strong) MDBridgeStorage *anchor;
@property(nonatomic, strong) MDBridgeStorage *storage;
@end
@implementation MDBridgeFixture
@end
void *MDTestPolicyFixture(const char *path) {
    @autoreleasepool {
        NSString *value = path == NULL ? nil : [[NSString alloc] initWithUTF8String:path];
        struct stat info;
        if ([NSThread isMainThread] || !value.isAbsolutePath || lstat(path,&info) != 0 ||
            !S_ISDIR(info.st_mode) || info.st_uid != geteuid() || (info.st_mode & 0777) != 0700) return NULL;
        MDBridgeFixture *fixture = [MDBridgeFixture new];
        fixture.directory = [NSURL fileURLWithPath:value isDirectory:YES];
        fixture.anchor = [MDBridgeStorage new]; fixture.storage = [MDBridgeStorage new];
        return (__bridge_retained void *)fixture;
    }
}
void *MDTestPolicyOpen(void *raw) {
    @autoreleasepool {
        MDBridgeFixture *fixture = (__bridge MDBridgeFixture *)raw;
        return MDNativePolicyWithTestPorts(fixture.directory,fixture.anchor,fixture.storage);
    }
}
void MDTestPolicyFault(void *raw, uint32_t fault) {
    ((__bridge MDBridgeFixture *)raw).storage.fault = fault;
}
bool MDTestPolicyReplaceLock(void *raw) {
    @autoreleasepool {
        MDBridgeFixture *fixture = (__bridge MDBridgeFixture *)raw;
        NSURL *path = [fixture.directory URLByAppendingPathComponent:@"process-owner.v1"];
        if (unlink(path.fileSystemRepresentation) != 0) return false;
        int fd = open(path.fileSystemRepresentation,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if (fd < 0) return false;
        bool valid = fchmod(fd,0600) == 0; close(fd); return valid;
    }
}
void MDTestPolicyFixtureRelease(void *raw) { if (raw != NULL) CFRelease(raw); }
