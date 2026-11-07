#import "../native/ProcessOwner.h"
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

// Only the anchor record is in memory. MDProcessOwner, paths, descriptors,
// metadata, rename and flock are production code and real macOS operations.
@interface ClosureAnchor : NSObject <MDPolicyStorage>
@property(nonatomic, strong) NSData *record;
@end
@implementation ClosureAnchor
- (MDPolicyStatus)readRecord:(NSData **)bytes { *bytes = self.record; return MDPolicyOK; }
- (MDPolicyStatus)createRecord:(NSData *)bytes {
    if (self.record) return MDPolicyChanged;
    self.record = bytes; return MDPolicyOK;
}
- (MDPolicyStatus)updateRecord:(NSData *)bytes { return MDPolicyUnreadable; }
- (MDPolicyStatus)readMarker:(NSData **)bytes { return MDPolicyUnreadable; }
- (MDPolicyStatus)createMarker:(NSData *)bytes { return MDPolicyUnreadable; }
@end

static void Require(BOOL condition, NSString *message) {
    if (!condition) @throw [NSException exceptionWithName:@"ClosureProofFailure" reason:message userInfo:nil];
}

static void Prove(BOOL replaceDirectory) {
    NSString *base = [NSTemporaryDirectory() stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
    NSString *path = [base stringByAppendingPathComponent:@"owner"];
    Require(mkdir(base.fileSystemRepresentation,0700) == 0, @"create isolated fixture");
    Require(mkdir(path.fileSystemRepresentation,0700) == 0, @"create exact owner directory");
    MDProcessOwner *owner = nil;
    int heldDirectory = -1, replacementLock = -1, oldLock = -1;
    @try {
        ClosureAnchor *anchor = [ClosureAnchor new];
        MDProcessOwnerStatus status;
        owner = [MDProcessOwner acquireInDirectory:[NSURL fileURLWithPath:path] anchorStorage:anchor status:&status];
        Require(owner != nil && status == MDProcessOwnerOK && owner.current, @"production owner acquired and current");
        heldDirectory = [owner duplicateOwnedDirectory];
        Require(heldDirectory >= 0, @"retain exact descriptor before external change");
        [owner close];
        Require(!owner.current && [owner duplicateOwnedDirectory] == -1, @"live owner close refuses before returning");
        owner = [MDProcessOwner acquireInDirectory:[NSURL fileURLWithPath:path] anchorStorage:anchor status:&status];
        Require(owner != nil && status == MDProcessOwnerOK && owner.current, @"unchanged namespace reacquires against original anchor");
        dispatch_semaphore_t ready = dispatch_semaphore_create(0), replace = dispatch_semaphore_create(0), changed = dispatch_semaphore_create(0);
        __block BOOL mutationOK = NO;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT,0), ^{
            dispatch_semaphore_signal(ready);
            if (dispatch_semaphore_wait(replace, dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC)) == 0) {
                if (replaceDirectory) {
                    NSString *old = [base stringByAppendingPathComponent:@"retired-owner"];
                    mutationOK = rename(path.fileSystemRepresentation,old.fileSystemRepresentation) == 0 &&
                        mkdir(path.fileSystemRepresentation,0700) == 0;
                } else {
                    mutationOK = renameat(heldDirectory,"process-owner.v1",heldDirectory,"retired-lock") == 0;
                }
            }
            dispatch_semaphore_signal(changed);
        });
        Require(dispatch_semaphore_wait(ready,dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC)) == 0, @"external mutation ready barrier");
        Require(owner.current, @"last production currentness observation before replacement");
        dispatch_semaphore_signal(replace);
        Require(dispatch_semaphore_wait(changed,dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC)) == 0 && mutationOK,
            @"external namespace replacement succeeds while original flock remains held");
        Require(!owner.current && [owner duplicateOwnedDirectory] == -1, @"production policy refuses path loss");
        struct stat retained;
        Require(fstat(heldDirectory,&retained) == 0 && S_ISDIR(retained.st_mode), @"descriptor capability survives named-path loss");
        NSString *newLockPath = [path stringByAppendingPathComponent:@"process-owner.v1"];
        replacementLock = open(newLockPath.fileSystemRepresentation,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
        Require(replacementLock >= 0 && flock(replacementLock,LOCK_EX|LOCK_NB) == 0, @"replacement inode has independent exclusive flock");
        oldLock = openat(heldDirectory,replaceDirectory ? "process-owner.v1" : "retired-lock",O_RDWR|O_NOFOLLOW);
        Require(oldLock >= 0 && flock(oldLock,LOCK_EX|LOCK_NB) != 0, @"original inode remains exclusively held");
        Require(flock(replacementLock,LOCK_UN) == 0, @"release replacement flock before testing anchor refusal");
        MDProcessOwnerStatus successorStatus;
        MDProcessOwner *successor = [MDProcessOwner acquireInDirectory:[NSURL fileURLWithPath:path] anchorStorage:anchor status:&successorStatus];
        Require(successor == nil && successorStatus == MDProcessOwnerUnreadable,
            @"original anchor rejects unlocked replacement without a BUSY shortcut");
        [owner close];
        Require(!owner.current, @"explicit close refuses synchronously");
        printf("PASS %s replacement: live policy refuses; descriptor and flock do not pin namespace\n",
            replaceDirectory ? "directory" : "lock");
    } @finally {
        if (oldLock >= 0) close(oldLock);
        if (replacementLock >= 0) close(replacementLock);
        if (heldDirectory >= 0) close(heldDirectory);
        [owner close];
        [[NSFileManager defaultManager] removeItemAtPath:base error:nil];
    }
}

int main(void) {
    @autoreleasepool {
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        __block int result = 0;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT,0), ^{
            @autoreleasepool {
                @try { Prove(NO); Prove(YES); }
                @catch (NSException *error) { fprintf(stderr,"FAIL %s\n",error.reason.UTF8String); result = 1; }
            }
            dispatch_semaphore_signal(done);
        });
        if (dispatch_semaphore_wait(done,dispatch_time(DISPATCH_TIME_NOW,10*NSEC_PER_SEC)) != 0) return 2;
        if (!result) puts("RESULT 2/2 process-owner capability limits demonstrated");
        return result;
    }
}
