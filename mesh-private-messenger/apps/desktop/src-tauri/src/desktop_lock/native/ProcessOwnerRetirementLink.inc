// Included once by ProcessOwner.m so the existing native build owns this code.
// Exact frozen ABI linkage; missing runtime symbols leave legacy owners usable
// but refuse construction of a protected link. No configurable callback table.
#import "ProcessOwnerRetirementLink.h"
#include <dlfcn.h>
#include <stdatomic.h>
NS_ASSUME_NONNULL_BEGIN

typedef int32_t (*MDRetireGeneration)(const struct MeshNativeGeneration *);
typedef uint64_t (*MDLocalInflight)(const struct MeshNativeGeneration *);
typedef void (*MDReleaseGeneration)(const struct MeshNativeGeneration *);

@interface MDProcessOwnerRetirementLink ()
- (BOOL)claimRegistration;
- (void)retireOriginal;
- (uint64_t)localInflightAfterRetirement;
@end


@implementation MDProcessOwnerRetirementLink {
    const struct MeshNativeGeneration *_generation;
    MDRetireGeneration _retire;
    MDLocalInflight _localInflight;
    MDReleaseGeneration _release;
    atomic_bool _claimed;
}
- (nullable instancetype)initTakingGeneration:(const struct MeshNativeGeneration *_Nullable *_Nonnull)generation {
    if (!(self = [super init])) return nil;
    if (!generation || !*generation) return nil;
    _retire = (MDRetireGeneration)dlsym(RTLD_DEFAULT, "mesh_authority_retire_v2");
    _localInflight = (MDLocalInflight)dlsym(RTLD_DEFAULT, "mesh_authority_local_inflight_v2");
    _release = (MDReleaseGeneration)dlsym(RTLD_DEFAULT, "mesh_authority_generation_release_v2");
    if (!_retire || !_localInflight || !_release) return nil;
    _generation = *generation;
    *generation = NULL;
    atomic_init(&_claimed, false);
    return self;
}
- (const struct MeshNativeGeneration *)generation { return _generation; }
- (BOOL)claimRegistration {
    bool expected = false;
    return atomic_compare_exchange_strong(&_claimed, &expected, true);
}
- (void)retireOriginal { _retire(_generation); }
- (uint64_t)localInflightAfterRetirement { return _localInflight(_generation); }
- (void)dealloc {
    if (_generation) {
        _retire(_generation);
        _release(_generation);
    }
}
@end

@interface MDProcessOwnerState : NSObject {
@public
    NSLock *gate;
    int directory;
    int lock;
    MDProcessOwnerRetirementLink *link;
    atomic_bool lost;
    atomic_bool closed;
    atomic_bool cleanupScheduled;
}
- (nullable instancetype)initWithLink:(nullable MDProcessOwnerRetirementLink *)original;
- (void)observeLoss;
- (void)closeOriginal;
@end

static dispatch_queue_t MDProcessOwnerCleanupQueue(void) {
    static dispatch_queue_t queue;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ queue = dispatch_queue_create("morse.process-owner-cleanup", DISPATCH_QUEUE_SERIAL); });
    return queue;
}

@implementation MDProcessOwnerState
- (nullable instancetype)initWithLink:(nullable MDProcessOwnerRetirementLink *)original {
    if (!(self = [super init])) return nil;
    directory = -1;
    lock = -1;
    if (original && ![original claimRegistration]) return nil;
    gate = [NSLock new];
    link = original;
    atomic_init(&lost, false);
    atomic_init(&closed, false);
    atomic_init(&cleanupScheduled, false);
    return self;
}
- (void)observeLoss {
    if (link) {
        [link retireOriginal];
        atomic_store(&lost, true);
    }
}
- (void)disposeLocked {
    // The scheduling bit is already set. Detach both numbers before any close;
    // later close/dealloc cannot touch a descriptor reused by another owner.
    int originalLock = lock, originalDirectory = directory;
    lock = -1;
    directory = -1;
    if (originalLock >= 0) close(originalLock);
    if (originalDirectory >= 0) close(originalDirectory);
}
- (void)reapClosedOriginal {
    if ([gate tryLock]) {
        BOOL settled = [link localInflightAfterRetirement] == 0;
        if (settled) [self disposeLocked];
        [gate unlock];
        if (settled) return;
    }
    // r1 has no settlement notification. Recheck without holding a lock or
    // joining an invocation. A delay never stands in for a zero observation.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_MSEC),
                   MDProcessOwnerCleanupQueue(), ^{ [self reapClosedOriginal]; });
}
- (void)closeOriginal {
    [link retireOriginal];
    atomic_store(&closed, true);
    if (!link) {
        [gate lock];
        atomic_store(&cleanupScheduled, true);
        [self disposeLocked];
        [gate unlock];
        return;
    }
    if (atomic_exchange(&cleanupScheduled, true)) return;
    if ([gate tryLock]) {
        BOOL settled = [link localInflightAfterRetirement] == 0;
        if (settled) [self disposeLocked];
        [gate unlock];
        if (settled) return;
    }
    // The executor retains the original state, never the dying facade.
    dispatch_async(MDProcessOwnerCleanupQueue(), ^{ [self reapClosedOriginal]; });
}
@end

NS_ASSUME_NONNULL_END
