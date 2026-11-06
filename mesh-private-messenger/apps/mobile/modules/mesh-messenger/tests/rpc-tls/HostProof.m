#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import "MeshMessengerSecureStore.h"
#import "libmessenger_mobile.h"

static MeshLibraryHostCallbacksV1 callbacks;
static IMP originalRead;

int32_t mesh_library_register_host_callbacks(const MeshLibraryHostCallbacksV1 *value) {
  callbacks = *value;
  return 0;
}

static id FailingRead(id bundle, SEL selector, NSString *key) {
  if ([key isEqualToString:@"MeshMessengerRpcTLSRoots"]) {
    @throw [NSException exceptionWithName:@"OwnedReadFailure" reason:@"resource unavailable" userInfo:nil];
  }
  return ((id (*)(id, SEL, NSString *))originalRead)(bundle, selector, key);
}

int main(int argc, const char **argv) {
  @autoreleasepool {
    if (argc != 4 || MeshMessengerRegisterAppleHostCallbacks() != 0) return 1;
    if (strcmp(argv[3], "read-error") == 0) {
      Method method = class_getInstanceMethod(NSBundle.mainBundle.class, @selector(objectForInfoDictionaryKey:));
      originalRead = method_setImplementation(method, (IMP)FailingRead);
    }
    const uint8_t selector[] = "messenger/rpc-tls-roots/v1";
    uint8_t output[82004];
    memset(output, 0xa5, sizeof(output));
    uint64_t capacity = strtoull(argv[2], NULL, 10), length = 999;
    if (capacity > sizeof(output) - 2) return 2;
    int32_t code = callbacks.push_get_token(NULL, selector, sizeof(selector) - 1, output + 1, capacity, &length);
    if (code != atoi(argv[1])) {
      fprintf(stderr, "RPC Apple callback: expected status=%s, actual=%d length=%llu\n", argv[1], code, (unsigned long long)length);
      return 3;
    }
    if (code == 0) {
      id value = [NSBundle.mainBundle objectForInfoDictionaryKey:@"MeshMessengerRpcTLSRoots"];
      NSData *expected = value == nil ? [NSData dataWithBytes:(uint8_t[]){1, 0} length:2]
          : [[NSData alloc] initWithBase64EncodedString:value options:0];
      if (length > capacity || expected.length != length || memcmp(output + 1, expected.bytes, length) != 0) return 4;
    } else if (length != 0) return 5;
    if (output[0] != 0xa5) return 6;
    for (NSUInteger index = (NSUInteger)length + 1; index < sizeof(output); ++index) {
      if (output[index] != 0xa5) return 7;
    }
  }
  return 0;
}
