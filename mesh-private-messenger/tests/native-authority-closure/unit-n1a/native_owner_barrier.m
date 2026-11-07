#import "ProcessOwner.h"
#include "libauthority.h"
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#ifndef N1A_BASELINE
#import "ProcessOwnerRetirementLink.h"
#endif

// Only the anchor is synthetic. Acquisition, stat, duplication, close and flock
// all use production ProcessOwner and real unique filesystem objects.
@interface N1Anchor : NSObject <MDPolicyStorage>
@property(nonatomic, strong) NSData *record;
@end
@implementation N1Anchor
- (MDPolicyStatus)readRecord:(NSData **)bytes { *bytes = self.record; return MDPolicyOK; }
- (MDPolicyStatus)createRecord:(NSData *)bytes {
    if (self.record) return MDPolicyChanged;
    self.record = bytes; return MDPolicyOK;
}
- (MDPolicyStatus)updateRecord:(NSData *)bytes { return MDPolicyUnreadable; }
- (MDPolicyStatus)readMarker:(NSData **)bytes { return MDPolicyUnreadable; }
- (MDPolicyStatus)createMarker:(NSData *)bytes { return MDPolicyUnreadable; }
@end

@interface N1Fixture : NSObject
@property(nonatomic, strong) MDProcessOwner *owner;
@property(nonatomic, strong) N1Anchor *anchor;
@property(nonatomic, strong) NSURL *url;
@property(nonatomic) const MeshNativeGeneration *node;
#ifndef N1A_BASELINE
@property(nonatomic, strong) MDProcessOwnerRetirementLink *link;
#endif
@end
@implementation N1Fixture
- (void)dealloc {
    [_owner close];
#ifdef N1A_BASELINE
    mesh_authority_generation_release_v2(_node);
#endif
}
@end

// Transfers the generation's owning C reference even on acquisition failure.
static void *N1Create(const char *path, const MeshNativeGeneration *node, N1Anchor *anchor) {
    @autoreleasepool {
        N1Fixture *fixture = [N1Fixture new];
        fixture.node = node;
#ifndef N1A_BASELINE
        fixture.link = [[MDProcessOwnerRetirementLink alloc] initTakingGeneration:&node];
        if (!fixture.link) {
            if (node) mesh_authority_generation_release_v2(node);
            return NULL;
        }
        NSCAssert(node == NULL, @"owning generation reference was not transferred");
#endif
        fixture.url = [NSURL fileURLWithPath:@(path)];
        fixture.anchor = anchor ?: [N1Anchor new];
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            @autoreleasepool {
            MDProcessOwnerStatus status;
            fixture.owner = [MDProcessOwner acquireInDirectory:fixture.url
                anchorStorage:fixture.anchor
#ifndef N1A_BASELINE
                retirementLink:fixture.link
#endif
                status:&status];
            }
            dispatch_semaphore_signal(done);
        });
        dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
        if (!fixture.owner) return NULL;
        return (__bridge_retained void *)fixture;
    }
}
void *n1a_create(const char *path, const MeshNativeGeneration *node) { return N1Create(path, node, nil); }
int n1a_current(void *handle) { @autoreleasepool { return [(__bridge N1Fixture *)handle owner].current; } }
int n1a_duplicate(void *handle) {
    @autoreleasepool {
    MDProcessOwner *owner = [(__bridge N1Fixture *)handle owner];
    if (!owner) return 0;
    int fd = [owner duplicateOwnedDirectory];
    if (fd >= 0) close(fd);
    return fd >= 0;
    }
}
int n1a_owned_duplicate(void *handle) { @autoreleasepool {
    MDProcessOwner *owner = [(__bridge N1Fixture *)handle owner];
    return owner ? [owner duplicateOwnedDirectory] : -1;
} }
void n1a_close(void *handle) { @autoreleasepool { [[(__bridge N1Fixture *)handle owner] close]; } }
void n1a_drop_owner(void *handle) { @autoreleasepool { [(__bridge N1Fixture *)handle setOwner:nil]; } }
void n1a_release(void *handle) { @autoreleasepool { (void)CFBridgingRelease(handle); } }
#ifndef N1A_BASELINE
void n1a_drop_link(void *handle) { @autoreleasepool { [(__bridge N1Fixture *)handle setLink:nil]; } }
void *n1a_successor(void *handle, const MeshNativeGeneration *node) {
    @autoreleasepool {
        N1Fixture *fixture = (__bridge N1Fixture *)handle;
        return N1Create(fixture.url.fileSystemRepresentation, node, fixture.anchor);
    }
}
int n1a_rebind_refuses(void *handle, const char *path) {
    N1Fixture *fixture = (__bridge N1Fixture *)handle;
    __block BOOL refused = NO;
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        MDProcessOwnerStatus status;
        MDProcessOwner *other = [MDProcessOwner acquireInDirectory:[NSURL fileURLWithPath:@(path)]
            anchorStorage:[N1Anchor new] retirementLink:fixture.link status:&status];
        refused = other == nil && status == MDProcessOwnerUnreadable;
        [other close];
        dispatch_semaphore_signal(done);
    });
    dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
    return refused;
}
int n1a_missing_refuses(const char *path) {
    MDProcessOwnerStatus status;
    MDProcessOwnerRetirementLink *missing = nil;
    MDProcessOwner *owner = [MDProcessOwner acquireInDirectory:[NSURL fileURLWithPath:@(path)]
        anchorStorage:[N1Anchor new] retirementLink:missing status:&status];
    return owner == nil && status == MDProcessOwnerUnreadable;
}
#endif
int n1a_anchor_refuses(void *handle) {
    N1Fixture *fixture = (__bridge N1Fixture *)handle;
    __block BOOL refused = NO;
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        MDProcessOwnerStatus status;
        MDProcessOwner *other = [MDProcessOwner acquireInDirectory:fixture.url
            anchorStorage:fixture.anchor status:&status];
        refused = other == nil && status == MDProcessOwnerUnreadable;
        [other close];
        dispatch_semaphore_signal(done);
    });
    dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
    return refused;
}
