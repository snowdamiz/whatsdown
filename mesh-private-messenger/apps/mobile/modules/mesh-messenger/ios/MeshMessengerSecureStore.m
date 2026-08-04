#import "MeshMessengerSecureStore.h"

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <os/lock.h>
#import <string.h>

#import "libmessenger_mobile.h"

static NSString *const MeshMessengerKeychainService = @"app.whatsdown.mesh";
static NSString *const MeshMessengerExpoProjectIDKey =
    @"MeshMessengerExpoProjectID";
static NSString *const MeshMessengerPushBrokerPublicKeyHexKey =
    @"MeshMessengerPushBrokerPublicKeyHex";
static const uint8_t MeshMessengerRawPushSelector[] = "expo/raw/v1";
static const uint8_t MeshMessengerConfigPushSelector[] = "expo/config/v1";
static const uint64_t MeshMessengerMaximumApplicationIDLength = 255;
static const uint64_t MeshMessengerMaximumPushTokenLength = 4096;
static const uint64_t MeshMessengerMaximumPushFrameLength = 4362;

static os_unfair_lock MeshMessengerPushLock = OS_UNFAIR_LOCK_INIT;
static uint8_t MeshMessengerPushFrame[4362];
static uint64_t MeshMessengerPushFrameLength = 0;

enum MeshMessengerSecureStoreStatus {
  MeshMessengerSecureStoreInvalidInput = 1,
  MeshMessengerSecureStoreNotFound = 2,
  MeshMessengerSecureStorePlatformFailure = 3,
  MeshMessengerSecureStoreOutputTooLarge = 4,
};

static void MeshMessengerZero(void *bytes, uint64_t length) {
  volatile uint8_t *cursor = bytes;
  while (length-- > 0) {
    *cursor++ = 0;
  }
}

static void MeshMessengerWriteU32(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)(value >> 24);
  output[1] = (uint8_t)(value >> 16);
  output[2] = (uint8_t)(value >> 8);
  output[3] = (uint8_t)value;
}

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

static int32_t MeshMessengerPushGetToken(void *context, const uint8_t *input,
                                         uint64_t inputLength, uint8_t *output,
                                         uint64_t outputCapacity,
                                         uint64_t *outputLength) {
  (void)context;
  if (input == NULL || output == NULL || outputLength == NULL) {
    return MeshMessengerSecureStoreInvalidInput;
  }
  *outputLength = 0;

  bool rawSelector = inputLength == sizeof(MeshMessengerRawPushSelector) - 1 &&
                     memcmp(input, MeshMessengerRawPushSelector, inputLength) ==
                         0;
  bool configSelector =
      inputLength == sizeof(MeshMessengerConfigPushSelector) - 1 &&
      memcmp(input, MeshMessengerConfigPushSelector, inputLength) == 0;
  if (!rawSelector && !configSelector) {
    return MeshMessengerSecureStoreInvalidInput;
  }
  if (configSelector) {
    id projectValue =
        [NSBundle.mainBundle objectForInfoDictionaryKey:MeshMessengerExpoProjectIDKey];
    id brokerValue = [NSBundle.mainBundle
        objectForInfoDictionaryKey:MeshMessengerPushBrokerPublicKeyHexKey];
    if (projectValue == nil && brokerValue == nil) {
      return MeshMessengerSecureStoreNotFound;
    }
    if ((projectValue != nil && ![projectValue isKindOfClass:NSString.class]) ||
        (brokerValue != nil && ![brokerValue isKindOfClass:NSString.class])) {
      return MeshMessengerSecureStorePlatformFailure;
    }
    NSString *frame = [NSString
        stringWithFormat:@"1\n%@\n%@", projectValue ?: @"", brokerValue ?: @""];
    NSData *data = [frame dataUsingEncoding:NSUTF8StringEncoding];
    if (data == nil) {
      return MeshMessengerSecureStorePlatformFailure;
    }
    if (data.length > outputCapacity) {
      return MeshMessengerSecureStoreOutputTooLarge;
    }
    [data getBytes:output length:data.length];
    *outputLength = data.length;
    return MESH_LIBRARY_OK;
  }

  os_unfair_lock_lock(&MeshMessengerPushLock);
  if (MeshMessengerPushFrameLength == 0) {
    os_unfair_lock_unlock(&MeshMessengerPushLock);
    return MeshMessengerSecureStoreNotFound;
  }
  if (MeshMessengerPushFrameLength > outputCapacity) {
    os_unfair_lock_unlock(&MeshMessengerPushLock);
    return MeshMessengerSecureStoreOutputTooLarge;
  }
  memcpy(output, MeshMessengerPushFrame, (size_t)MeshMessengerPushFrameLength);
  *outputLength = MeshMessengerPushFrameLength;
  MeshMessengerZero(MeshMessengerPushFrame, MeshMessengerPushFrameLength);
  MeshMessengerPushFrameLength = 0;
  os_unfair_lock_unlock(&MeshMessengerPushLock);
  return MESH_LIBRARY_OK;
}

int32_t MeshMessengerCacheApplePushToken(const uint8_t *applicationID,
                                         uint64_t applicationIDLength,
                                         const uint8_t *token,
                                         uint64_t tokenLength,
                                         bool development) {
  if (applicationID == NULL || token == NULL || applicationIDLength == 0 ||
      applicationIDLength > MeshMessengerMaximumApplicationIDLength ||
      tokenLength == 0 || tokenLength > MeshMessengerMaximumPushTokenLength) {
    return MeshMessengerSecureStoreInvalidInput;
  }
  uint64_t frameLength = 11 + applicationIDLength + tokenLength;
  if (frameLength > MeshMessengerMaximumPushFrameLength) {
    return MeshMessengerSecureStoreOutputTooLarge;
  }

  uint8_t frame[4362] = {0};
  uint64_t cursor = 0;
  frame[cursor++] = 1;
  frame[cursor++] = 1;
  frame[cursor++] = development ? 1 : 0;
  MeshMessengerWriteU32(frame + cursor, (uint32_t)applicationIDLength);
  cursor += 4;
  memcpy(frame + cursor, applicationID, (size_t)applicationIDLength);
  cursor += applicationIDLength;
  MeshMessengerWriteU32(frame + cursor, (uint32_t)tokenLength);
  cursor += 4;
  memcpy(frame + cursor, token, (size_t)tokenLength);

  os_unfair_lock_lock(&MeshMessengerPushLock);
  MeshMessengerZero(MeshMessengerPushFrame, MeshMessengerPushFrameLength);
  memcpy(MeshMessengerPushFrame, frame, (size_t)frameLength);
  MeshMessengerPushFrameLength = frameLength;
  os_unfair_lock_unlock(&MeshMessengerPushLock);
  MeshMessengerZero(frame, frameLength);
  return MESH_LIBRARY_OK;
}

void MeshMessengerClearApplePushToken(void) {
  os_unfair_lock_lock(&MeshMessengerPushLock);
  MeshMessengerZero(MeshMessengerPushFrame, MeshMessengerPushFrameLength);
  MeshMessengerPushFrameLength = 0;
  os_unfair_lock_unlock(&MeshMessengerPushLock);
}

int32_t MeshMessengerRegisterAppleHostCallbacks(void) {
  MeshLibraryHostCallbacksV1 callbacks = {0};
  callbacks.abi_version = MESH_LIBRARY_ABI_VERSION;
  callbacks.struct_size = sizeof(callbacks);
  callbacks.secure_store_put = MeshMessengerSecureStorePut;
  callbacks.secure_store_get = MeshMessengerSecureStoreGet;
  callbacks.secure_store_delete = MeshMessengerSecureStoreDelete;
  callbacks.push_get_token = MeshMessengerPushGetToken;
  return mesh_library_register_host_callbacks(&callbacks);
}
