#import "MeshMessengerSecureStore.h"

#import <Foundation/Foundation.h>
#import <Security/Security.h>

#import "libmessenger_mobile.h"

static NSString *const MeshMessengerKeychainService = @"app.whatsdown.mesh";

enum MeshMessengerSecureStoreStatus {
  MeshMessengerSecureStoreInvalidInput = 1,
  MeshMessengerSecureStoreNotFound = 2,
  MeshMessengerSecureStorePlatformFailure = 3,
  MeshMessengerSecureStoreOutputTooLarge = 4,
};

static NSString *MeshMessengerAccount(const uint8_t *bytes, uint64_t length) {
  if (bytes == NULL || length == 0 || length > 4096) {
    return nil;
  }
  NSData *key = [NSData dataWithBytes:bytes length:(NSUInteger)length];
  return [key base64EncodedStringWithOptions:0];
}

static NSDictionary *MeshMessengerQuery(NSString *account) {
  return @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService : MeshMessengerKeychainService,
    (__bridge id)kSecAttrAccount : account,
  };
}

static int32_t MeshMessengerSecureStorePut(void *context, const uint8_t *input,
                                           uint64_t inputLength, uint8_t *output,
                                           uint64_t outputCapacity,
                                           uint64_t *outputLength) {
  (void)context;
  (void)output;
  (void)outputCapacity;
  if (outputLength == NULL) {
    return MeshMessengerSecureStoreInvalidInput;
  }
  *outputLength = 0;
  if (input == NULL || inputLength < 5) {
    return MeshMessengerSecureStoreInvalidInput;
  }

  uint32_t keyLength = ((uint32_t)input[0] << 24) |
                       ((uint32_t)input[1] << 16) |
                       ((uint32_t)input[2] << 8) | (uint32_t)input[3];
  if (keyLength == 0 || keyLength > 4096 || keyLength > inputLength - 4 ||
      inputLength == (uint64_t)keyLength + 4) {
    return MeshMessengerSecureStoreInvalidInput;
  }
  NSString *account = MeshMessengerAccount(input + 4, keyLength);
  NSData *value = [NSData dataWithBytes:input + 4 + keyLength
                                 length:(NSUInteger)(inputLength - 4 - keyLength)];
  if (account == nil) {
    return MeshMessengerSecureStoreInvalidInput;
  }

  NSDictionary *query = MeshMessengerQuery(account);
  OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query,
                                  (__bridge CFDictionaryRef)@{
                                    (__bridge id)kSecValueData : value,
                                  });
  if (status == errSecItemNotFound) {
    NSMutableDictionary *item = [query mutableCopy];
    item[(__bridge id)kSecValueData] = value;
    item[(__bridge id)kSecAttrAccessible] =
        (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
    status = SecItemAdd((__bridge CFDictionaryRef)item, NULL);
  }
  return status == errSecSuccess ? MESH_LIBRARY_OK
                                 : MeshMessengerSecureStorePlatformFailure;
}

static int32_t MeshMessengerSecureStoreGet(void *context, const uint8_t *input,
                                           uint64_t inputLength, uint8_t *output,
                                           uint64_t outputCapacity,
                                           uint64_t *outputLength) {
  (void)context;
  if (output == NULL || outputLength == NULL) {
    return MeshMessengerSecureStoreInvalidInput;
  }
  *outputLength = 0;
  NSString *account = MeshMessengerAccount(input, inputLength);
  if (account == nil) {
    return MeshMessengerSecureStoreInvalidInput;
  }

  NSMutableDictionary *query = [MeshMessengerQuery(account) mutableCopy];
  query[(__bridge id)kSecReturnData] = @YES;
  query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
  CFTypeRef result = NULL;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
  if (status == errSecItemNotFound) {
    return MeshMessengerSecureStoreNotFound;
  }
  if (status != errSecSuccess || result == NULL) {
    if (result != NULL) {
      CFRelease(result);
    }
    return MeshMessengerSecureStorePlatformFailure;
  }

  NSData *value = CFBridgingRelease(result);
  if (value.length > outputCapacity) {
    return MeshMessengerSecureStoreOutputTooLarge;
  }
  [value getBytes:output length:value.length];
  *outputLength = value.length;
  return MESH_LIBRARY_OK;
}

static int32_t MeshMessengerSecureStoreDelete(void *context,
                                              const uint8_t *input,
                                              uint64_t inputLength,
                                              uint8_t *output,
                                              uint64_t outputCapacity,
                                              uint64_t *outputLength) {
  (void)context;
  (void)output;
  (void)outputCapacity;
  if (outputLength == NULL) {
    return MeshMessengerSecureStoreInvalidInput;
  }
  *outputLength = 0;
  NSString *account = MeshMessengerAccount(input, inputLength);
  if (account == nil) {
    return MeshMessengerSecureStoreInvalidInput;
  }
  OSStatus status = SecItemDelete(
      (__bridge CFDictionaryRef)MeshMessengerQuery(account));
  return status == errSecSuccess || status == errSecItemNotFound
             ? MESH_LIBRARY_OK
             : MeshMessengerSecureStorePlatformFailure;
}

int32_t MeshMessengerRegisterAppleSecureStore(void) {
  MeshLibraryHostCallbacksV1 callbacks = {0};
  callbacks.abi_version = MESH_LIBRARY_ABI_VERSION;
  callbacks.struct_size = sizeof(callbacks);
  callbacks.secure_store_put = MeshMessengerSecureStorePut;
  callbacks.secure_store_get = MeshMessengerSecureStoreGet;
  callbacks.secure_store_delete = MeshMessengerSecureStoreDelete;
  return mesh_library_register_host_callbacks(&callbacks);
}
