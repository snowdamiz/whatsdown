#import "PolicyPorts.h"
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

@implementation MDPolicyMarker {
    int _directory;
}
- (instancetype)initWithDirectory:(NSURL *)directory {
    if ((self = [super init])) {
        _directory = -1;
        if ([NSThread isMainThread] || !directory.isFileURL) return nil;
        int made = mkdir(directory.fileSystemRepresentation,0700);
        if (made != 0 && errno != EEXIST) return nil;
        int fd = open(directory.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if (fd < 0) return nil;
        struct stat info;
        if (fstat(fd,&info) != 0 || !S_ISDIR(info.st_mode) || info.st_uid != geteuid() || fchmod(fd,0700) != 0) {
            close(fd); return nil;
        }
        NSNumber *excluded = nil;
        if (![directory setResourceValue:@YES forKey:NSURLIsExcludedFromBackupKey error:NULL] ||
            ![directory getResourceValue:&excluded forKey:NSURLIsExcludedFromBackupKey error:NULL] ||
            ![excluded isEqual:@YES] || fsync(fd) != 0) { close(fd); return nil; }
        if (made == 0) {
            int parent = open(directory.URLByDeletingLastPathComponent.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            if (parent < 0) { close(fd); return nil; }
            int status = fsync(parent); close(parent);
            if (status != 0) { close(fd); return nil; }
        }
        _directory = fd;
    }
    return self;
}
- (MDPolicyStatus)read:(NSData **)bytes {
    *bytes = nil;
    if ([NSThread isMainThread]) return MDPolicyBackgroundRequired;
    int fd = openat(_directory,"policy-initialized.v1",O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? MDPolicyOK : MDPolicyUnreadable;
    struct stat info;
    if (fstat(fd,&info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != geteuid() || info.st_nlink != 1 ||
        (info.st_mode & 0777) != 0600 || info.st_size < 1 || info.st_size > 128) { close(fd); return MDPolicyUnreadable; }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)info.st_size];
    NSUInteger offset = 0;
    while (offset < data.length) {
        ssize_t count = read(fd,(uint8_t *)data.mutableBytes+offset,data.length-offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { close(fd); return MDPolicyUnreadable; }
        offset += (NSUInteger)count;
    }
    uint8_t extra;
    ssize_t remaining;
    do { remaining = read(fd,&extra,1); } while (remaining < 0 && errno == EINTR);
    close(fd);
    if (remaining != 0) return MDPolicyUnreadable;
    *bytes = data; return MDPolicyOK;
}
- (MDPolicyStatus)create:(NSData *)bytes {
    if ([NSThread isMainThread]) return MDPolicyBackgroundRequired;
    if (bytes.length < 1 || bytes.length > 128) return MDPolicyUnreadable;
    int fd = openat(_directory,"policy-initialized.v1",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if (fd < 0) return MDPolicyUnreadable;
    if (fchmod(fd,0600) != 0) { close(fd); return MDPolicyUnreadable; }
    NSUInteger offset = 0;
    while (offset < bytes.length) {
        ssize_t count = write(fd,(const uint8_t *)bytes.bytes+offset,bytes.length-offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { close(fd); return MDPolicyUnreadable; }
        offset += (NSUInteger)count;
    }
    int saved = fsync(fd); close(fd);
    NSData *readback = nil;
    // A partial/failed marker is never removed: missing record is interrupted
    // initialization, not positive evidence of a new disabled installation.
    if (saved != 0 || fsync(_directory) != 0 || [self read:&readback] != MDPolicyOK || ![readback isEqual:bytes]) return MDPolicyUnreadable;
    return MDPolicyOK;
}
- (void)dealloc { if (_directory >= 0) close(_directory); }
@end

@interface MDSystemKeychainAccess : NSObject <MDKeychainAccess>
@end
@implementation MDSystemKeychainAccess
- (int32_t)copyMatching:(NSDictionary *)query result:(id *)object {
    CFTypeRef output = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query,&output);
    *object = output == NULL ? nil : CFBridgingRelease(output); return status;
}
- (int32_t)add:(NSDictionary *)query { return SecItemAdd((__bridge CFDictionaryRef)query,NULL); }
- (int32_t)update:(NSDictionary *)query attributes:(NSDictionary *)attributes {
    return SecItemUpdate((__bridge CFDictionaryRef)query,(__bridge CFDictionaryRef)attributes);
}
@end

@implementation MDKeychainPolicyStorage {
    NSString *_service;
    MDPolicyMarker *_marker;
    id<MDKeychainAccess> _calls;
}
- (instancetype)initWithService:(NSString *)service directory:(NSURL *)directory {
    return [self initWithService:service directory:directory nativeCalls:[MDSystemKeychainAccess new]];
}
- (instancetype)initWithService:(NSString *)service directory:(NSURL *)directory nativeCalls:(id<MDKeychainAccess>)calls {
    if ((self = [super init])) {
        if ([NSThread isMainThread] || service.length == 0) return nil;
        _service = [service copy]; _calls = calls;
        _marker = [[MDPolicyMarker alloc] initWithDirectory:directory];
        if (_marker == nil) return nil;
    }
    return self;
}
- (NSMutableDictionary *)query {
    LAContext *context = [LAContext new]; context.interactionNotAllowed = YES;
    return [@{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecUseDataProtectionKeychain:@YES,
        (__bridge id)kSecAttrService:_service, (__bridge id)kSecAttrAccount:@"policy",
        (__bridge id)kSecAttrSynchronizable:@NO, (__bridge id)kSecUseAuthenticationContext:context} mutableCopy];
}
- (MDPolicyStatus)readMarker:(NSData **)bytes { return [_marker read:bytes]; }
- (MDPolicyStatus)createMarker:(NSData *)bytes { return [_marker create:bytes]; }
- (MDPolicyStatus)readRecord:(NSData **)bytes {
    *bytes = nil;
    if ([NSThread isMainThread]) return MDPolicyBackgroundRequired;
    NSMutableDictionary *query = [self query];
    query[(__bridge id)kSecAttrSynchronizable] = (__bridge id)kSecAttrSynchronizableAny;
    query[(__bridge id)kSecReturnData] = @YES; query[(__bridge id)kSecReturnAttributes] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
    id object = nil;
    OSStatus status = [_calls copyMatching:query result:&object];
    [(LAContext *)query[(__bridge id)kSecUseAuthenticationContext] invalidate];
    if (status == errSecItemNotFound) return MDPolicyOK;
    if (status != errSecSuccess || ![object isKindOfClass:NSArray.class] || [object count] != 1) return MDPolicyUnreadable;
    id row = object[0];
    if (![row isKindOfClass:NSDictionary.class]) return MDPolicyUnreadable;
    NSData *data = row[(__bridge id)kSecValueData];
    if (![data isKindOfClass:NSData.class] || data.length < 1 || data.length > 4096 ||
        ![row[(__bridge id)kSecAttrSynchronizable] isEqual:@NO] ||
        ![row[(__bridge id)kSecAttrAccessible] isEqual:(__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]) return MDPolicyUnreadable;
    *bytes = data; return MDPolicyOK;
}
- (MDPolicyStatus)createRecord:(NSData *)bytes {
    if ([NSThread isMainThread]) return MDPolicyBackgroundRequired;
    NSMutableDictionary *query = [self query];
    query[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
    query[(__bridge id)kSecValueData] = bytes;
    OSStatus status = [_calls add:query];
    [(LAContext *)query[(__bridge id)kSecUseAuthenticationContext] invalidate];
    return status == errSecSuccess ? MDPolicyOK : MDPolicyUnreadable;
}
- (MDPolicyStatus)updateRecord:(NSData *)bytes {
    if ([NSThread isMainThread]) return MDPolicyBackgroundRequired;
    NSMutableDictionary *query = [self query];
    NSDictionary *attributes = @{(__bridge id)kSecValueData:bytes,
        (__bridge id)kSecAttrAccessible:(__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly};
    OSStatus status = [_calls update:query attributes:attributes];
    [(LAContext *)query[(__bridge id)kSecUseAuthenticationContext] invalidate];
    // Missing remains missing; never recreate or upsert an installation policy.
    return status == errSecSuccess ? MDPolicyOK : MDPolicyUnreadable;
}
@end
