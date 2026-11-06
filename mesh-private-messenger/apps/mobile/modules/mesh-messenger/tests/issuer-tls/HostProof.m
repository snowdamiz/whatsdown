#import <Foundation/Foundation.h>
#import "MeshMessengerSecureStore.h"
#import "libmessenger_mobile.h"
static MeshLibraryHostCallbacksV1 callbacks;
int32_t mesh_library_register_host_callbacks(const MeshLibraryHostCallbacksV1 *value) {
  callbacks = *value;
  return 0;
}
int main(int argc, const char **argv) {
  @autoreleasepool {
    if (argc != 3 || MeshMessengerRegisterAppleHostCallbacks() != 0) return 1;
    const uint8_t selector[] = "messenger/issuer-tls-root/v1";
    uint8_t output[67592]; uint64_t length = 999;
    int32_t code = callbacks.push_get_token(NULL, selector, sizeof(selector)-1, output, strtoull(argv[2],NULL,10), &length);
    if (code != atoi(argv[1])) return 2;
    if (code == 0) {
      id value = [NSBundle.mainBundle objectForInfoDictionaryKey:@"MeshMessengerIssuerTLSRoot"];
      NSData *expected = value == nil ? [NSData dataWithBytes:(uint8_t[]){1,0,0,0,0,0,0} length:7] : [[NSData alloc] initWithBase64EncodedString:value options:0];
      if (expected.length != length || memcmp(output, expected.bytes, length) != 0) return 3;
    } else if (length != 0) return 4;
    printf("issuer TLS Apple callback: status=%d length=%llu\n", code, (unsigned long long)length);
  }
  return 0;
}
