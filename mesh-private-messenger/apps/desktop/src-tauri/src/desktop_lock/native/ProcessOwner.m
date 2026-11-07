#import "ProcessOwner.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#import "ProcessOwnerRetirementLink.inc"

static const char *MDProcessLockName = "process-owner.v1";
static BOOL MDOwnedDirectory(struct stat value) {
    return S_ISDIR(value.st_mode) && value.st_uid == geteuid() && (value.st_mode & 0777) == 0700;
}
static BOOL MDOwnedLock(struct stat value) {
    return S_ISREG(value.st_mode) && value.st_uid == geteuid() && value.st_nlink == 1 &&
        (value.st_mode & 0777) == 0600 && value.st_size == 0;
}
static NSData *MDOwnerIdentity(struct stat directory, struct stat lock) {
    // Device-local native anchor. A newly-created lock is never accepted against
    // any surviving anchor, so inode reuse cannot authorize a replacement lock.
    const uint64_t value[] = {1,(uint64_t)directory.st_dev,(uint64_t)directory.st_ino,
        (uint64_t)lock.st_dev,(uint64_t)lock.st_ino};
    return [NSData dataWithBytes:value length:sizeof(value)];
}

static MDProcessOwner *MDFailedOwner(MDProcessOwner *owner) { [owner close]; return nil; }

@implementation MDProcessOwner {
    MDProcessOwnerState *_state;
    NSURL *_url;
    dev_t _directoryDevice;
    ino_t _directoryInode;
    dev_t _lockDevice;
    ino_t _lockInode;
}
- (instancetype)init {
    if ((self = [super init])) { _state = [[MDProcessOwnerState alloc] initWithLink:nil]; }
    return self;
}
+ (instancetype)acquireInDirectory:(NSURL *)directory anchorStorage:(id<MDPolicyStorage>)storage status:(MDProcessOwnerStatus *)status {
    return [self acquireOriginal:directory anchorStorage:storage retirementLink:nil status:status];
}
+ (instancetype)acquireInDirectory:(NSURL *)directory anchorStorage:(id<MDPolicyStorage>)storage retirementLink:(MDProcessOwnerRetirementLink *)link status:(MDProcessOwnerStatus *)status {
    if (!link) { *status = MDProcessOwnerUnreadable; return nil; }
    return [self acquireOriginal:directory anchorStorage:storage retirementLink:link status:status];
}
+ (instancetype)acquireOriginal:(NSURL *)directory anchorStorage:(id<MDPolicyStorage>)storage retirementLink:(MDProcessOwnerRetirementLink *)link status:(MDProcessOwnerStatus *)status {
    *status = MDProcessOwnerUnreadable;
    MDProcessOwner *owner = [MDProcessOwner new];
    if (link) {
        owner->_state = [[MDProcessOwnerState alloc] initWithLink:link];
        if (!owner->_state) return nil;
    }
    if ([NSThread isMainThread] || !directory.isFileURL) return MDFailedOwner(owner);
    owner->_url = [directory copy];
    owner->_state->directory = open(directory.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (owner->_state->directory < 0) return MDFailedOwner(owner);
    struct stat folder;
    if (fstat(owner->_state->directory,&folder) != 0 || !MDOwnedDirectory(folder)) return MDFailedOwner(owner);
    BOOL created = NO;
    owner->_state->lock = openat(owner->_state->directory,MDProcessLockName,O_RDWR|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
    if (owner->_state->lock < 0) {
        if (errno != ENOENT) return MDFailedOwner(owner);
        // Do not leave initialization evidence after an unreadable Keychain.
        // Both absence and a successful read are required before first creation.
        NSData *prior = nil;
        if ([storage readRecord:&prior] != MDPolicyOK || prior != nil) return MDFailedOwner(owner);
        owner->_state->lock = openat(owner->_state->directory,MDProcessLockName,O_RDWR|O_CREAT|O_EXCL|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,0600);
        if (owner->_state->lock >= 0) created = YES;
        else if (errno == EEXIST)
            owner->_state->lock = openat(owner->_state->directory,MDProcessLockName,O_RDWR|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
        if (owner->_state->lock < 0) return MDFailedOwner(owner);
    }
    struct stat held;
    if (fstat(owner->_state->lock,&held) != 0 || !MDOwnedLock(held)) return MDFailedOwner(owner);
    if (flock(owner->_state->lock,LOCK_EX|LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) *status = MDProcessOwnerBusy;
        return MDFailedOwner(owner);
    }
    owner->_directoryDevice = folder.st_dev; owner->_directoryInode = folder.st_ino;
    owner->_lockDevice = held.st_dev; owner->_lockInode = held.st_ino;
    if (!owner.current) return MDFailedOwner(owner);
    NSData *expected = MDOwnerIdentity(folder,held), *actual = nil;
    if ([storage readRecord:&actual] != MDPolicyOK) return MDFailedOwner(owner);
    if (created) {
        if (actual != nil || [storage createRecord:expected] != MDPolicyOK) return MDFailedOwner(owner);
        actual = nil;
        if ([storage readRecord:&actual] != MDPolicyOK || ![actual isEqual:expected]) return MDFailedOwner(owner);
    } else if (![actual isEqual:expected]) return MDFailedOwner(owner);
    if (fsync(owner->_state->lock) != 0 || fsync(owner->_state->directory) != 0 || !owner.current) return MDFailedOwner(owner);
    *status = MDProcessOwnerOK; return owner;
}
- (BOOL)currentLocked {
    struct stat directory, pathDirectory, held, pathLock;
    BOOL valid = _state->directory >= 0 && _state->lock >= 0 &&
        fstat(_state->directory,&directory) == 0 && MDOwnedDirectory(directory) &&
        directory.st_dev == _directoryDevice && directory.st_ino == _directoryInode &&
        lstat(_url.fileSystemRepresentation,&pathDirectory) == 0 && MDOwnedDirectory(pathDirectory) &&
        pathDirectory.st_dev == _directoryDevice && pathDirectory.st_ino == _directoryInode &&
        fstat(_state->lock,&held) == 0 && MDOwnedLock(held) && held.st_dev == _lockDevice && held.st_ino == _lockInode &&
        fstatat(_state->directory,MDProcessLockName,&pathLock,AT_SYMLINK_NOFOLLOW) == 0 && MDOwnedLock(pathLock) &&
        pathLock.st_dev == _lockDevice && pathLock.st_ino == _lockInode &&
        (!_state->link || (!atomic_load(&_state->lost) && !atomic_load(&_state->closed)));
    if (!valid) [_state observeLoss];
    return valid;
}
- (BOOL)current {
    [_state->gate lock];BOOL valid=[self currentLocked];[_state->gate unlock];return valid;
}
- (int)duplicateOwnedDirectory {
    [_state->gate lock];int copy=-1;
    if ([self currentLocked]) {
        copy=fcntl(_state->directory,F_DUPFD_CLOEXEC,0);
        if (copy>=0 && ![self currentLocked]) { close(copy);copy=-1; }
    }
    [_state->gate unlock];return copy;
}
#if defined(MD_OWNER_TEST_PORTS)
- (BOOL)testDescriptorsCloseOnExec {
    [_state->gate lock];
    int directoryFlags = _state->directory >= 0 ? fcntl(_state->directory,F_GETFD) : -1;
    int lockFlags = _state->lock >= 0 ? fcntl(_state->lock,F_GETFD) : -1;
    BOOL flags = directoryFlags >= 0 && lockFlags >= 0 &&
        (directoryFlags & FD_CLOEXEC) != 0 && (lockFlags & FD_CLOEXEC) != 0;
    [_state->gate unlock]; return flags;
}
#endif
- (void)close { [_state closeOriginal]; }
- (void)dealloc { [self close]; }
@end
