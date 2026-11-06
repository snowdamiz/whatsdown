#import "MeshMessengerSecureStore.h"

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <os/lock.h>
#import <string.h>

#import "libmessenger_mobile.h"

static NSString *const MeshMessengerKeychainService = @"app.morse.mesh";
static NSString *const MeshMessengerExpoProjectIDKey =
    @"MeshMessengerExpoProjectID";
static NSString *const MeshMessengerPushBrokerPublicKeyHexKey =
    @"MeshMessengerPushBrokerPublicKeyHex";
static NSString *const MeshMessengerSecurityConfigKey =
    @"MeshMessengerSecurityConfig";
static NSString *const MeshMessengerNetworkConfigKey = @"MeshMessengerNetworkConfig";
static NSString *const MeshMessengerCreditPurposeKey = @"MeshMessengerCreditPurpose";
static const uint8_t MeshMessengerRawPushSelector[] = "expo/raw/v1";
static const uint8_t MeshMessengerConfigPushSelector[] = "expo/config/v1";
static const uint8_t MeshMessengerCounterConfigSelector[] = "messenger/network-counter/v1";
static const uint8_t MeshMessengerSecurityConfigSelector[] =
    "messenger/config/v1";
static const uint8_t MeshMessengerCreditPurposeSelector[] = "messenger/credits/v1";
static const uint8_t MeshMessengerNetworkConfigSelector[] = "messenger/network/v1";
static const uint8_t MeshMessengerOhttpConfigSelector[] = "messenger/ohttp/v1";
static const uint8_t MeshMessengerLightningSelector[] = "messenger/lightning/v1";
static const uint8_t MeshMessengerIssuerTLSSelector[] = "messenger/issuer-tls-root/v1";
static const uint8_t MeshMessengerRpcTLSSelector[] = "messenger/rpc-tls-roots/v1";
static const uint8_t MeshMessengerWalletSelector[] = "messenger/wallet/v1";
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

int32_t MeshMessengerWalletPins(uint8_t output[34]) {
  id purpose = [NSBundle.mainBundle objectForInfoDictionaryKey:MeshMessengerCreditPurposeKey];
  id mint = [NSBundle.mainBundle objectForInfoDictionaryKey:@"MeshMessengerCreditUSDCMintHex"];
  if (![purpose isKindOfClass:NSString.class] || ![mint isKindOfClass:NSString.class] || [(NSString *)mint length] != 64 ||
      (![(NSString *)purpose isEqualToString:@"live"] && ![(NSString *)purpose isEqualToString:@"test"])) return 3;
  const char *hex = [(NSString *)mint UTF8String];
  const char *alphabet = "0123456789abcdef";
  uint8_t nonzero = 0;
  for (NSUInteger index = 0; index < 32; ++index) {
    const char *left = strchr(alphabet, hex[index * 2]);
    const char *right = strchr(alphabet, hex[index * 2 + 1]);
    if (left == NULL || right == NULL || hex[index * 2] == 0 || hex[index * 2 + 1] == 0) return 3;
    output[index + 2] = (uint8_t)(((left - alphabet) << 4) | (right - alphabet));
    nonzero |= output[index + 2];
  }
  if (nonzero == 0) return 3;
  output[0] = 1;
  output[1] = [(NSString *)purpose isEqualToString:@"live"] ? 0 : 1;
  return 0;
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
  bool counterConfigSelector = inputLength == sizeof(MeshMessengerCounterConfigSelector) - 1 &&
      memcmp(input, MeshMessengerCounterConfigSelector, inputLength) == 0;
  bool securityConfigSelector =
      inputLength == sizeof(MeshMessengerSecurityConfigSelector) - 1 &&
      memcmp(input, MeshMessengerSecurityConfigSelector, inputLength) == 0;
  bool creditPurposeSelector = inputLength == sizeof(MeshMessengerCreditPurposeSelector) - 1 &&
      memcmp(input, MeshMessengerCreditPurposeSelector, inputLength) == 0;
  bool lightningSelector = inputLength == sizeof(MeshMessengerLightningSelector) - 1 &&
      memcmp(input, MeshMessengerLightningSelector, inputLength) == 0;
  bool walletSelector = inputLength == sizeof(MeshMessengerWalletSelector) - 1 &&
      memcmp(input, MeshMessengerWalletSelector, inputLength) == 0;
  bool networkConfigSelector = inputLength == sizeof(MeshMessengerNetworkConfigSelector) - 1 &&
      memcmp(input, MeshMessengerNetworkConfigSelector, inputLength) == 0;
  bool ohttpConfigSelector = inputLength == sizeof(MeshMessengerOhttpConfigSelector) - 1 &&
      memcmp(input, MeshMessengerOhttpConfigSelector, inputLength) == 0;
  bool issuerTLSSelector = inputLength == sizeof(MeshMessengerIssuerTLSSelector) - 1 &&
      memcmp(input, MeshMessengerIssuerTLSSelector, inputLength) == 0;
  bool rpcTLSSelector = inputLength == sizeof(MeshMessengerRpcTLSSelector) - 1 &&
      memcmp(input, MeshMessengerRpcTLSSelector, inputLength) == 0;
  if (!ohttpConfigSelector && !counterConfigSelector && !issuerTLSSelector && !rpcTLSSelector && !rawSelector && !configSelector && !securityConfigSelector && !creditPurposeSelector && !walletSelector && !networkConfigSelector && !lightningSelector) {
    return MeshMessengerSecureStoreInvalidInput;
  }
  if (rpcTLSSelector) {
    @try {
      id value = [NSBundle.mainBundle objectForInfoDictionaryKey:@"MeshMessengerRpcTLSRoots"];
      NSData *data;
      if (value == nil) {
        const uint8_t absent[] = {1, 0};
        data = [NSData dataWithBytes:absent length:sizeof(absent)];
      } else {
        if (![value isKindOfClass:NSString.class] || [(NSString *)value length] > 109336) return MeshMessengerSecureStorePlatformFailure;
        data = [[NSData alloc] initWithBase64EncodedString:value options:0];
        if (data == nil || data.length < 2 || data.length > 82002 ||
            ![[data base64EncodedStringWithOptions:0] isEqualToString:value]) return MeshMessengerSecureStorePlatformFailure;
      }
      if (data.length > outputCapacity) return MeshMessengerSecureStoreOutputTooLarge;
      [data getBytes:output length:data.length];
      *outputLength = data.length;
      return MESH_LIBRARY_OK;
    } @catch (NSException *exception) {
      (void)exception;
      return MeshMessengerSecureStorePlatformFailure;
    }
  }
  if (issuerTLSSelector) {
    id value = [NSBundle.mainBundle objectForInfoDictionaryKey:@"MeshMessengerIssuerTLSRoot"];
    NSData *data;
    if (value == nil) {
      const uint8_t absent[] = {1, 0, 0, 0, 0, 0, 0};
      data = [NSData dataWithBytes:absent length:sizeof(absent)];
    } else {
      if (![value isKindOfClass:NSString.class] || [(NSString *)value length] > 90124) return MeshMessengerSecureStorePlatformFailure;
      data = [[NSData alloc] initWithBase64EncodedString:value options:0];
      if (data == nil || data.length < 7 || data.length > 67591 ||
          ![[data base64EncodedStringWithOptions:0] isEqualToString:value]) return MeshMessengerSecureStorePlatformFailure;
    }
    if (data.length > outputCapacity) return MeshMessengerSecureStoreOutputTooLarge;
    [data getBytes:output length:data.length];
    *outputLength = data.length;
    return MESH_LIBRARY_OK;
  }
  if (lightningSelector) {
    id value = [NSBundle.mainBundle objectForInfoDictionaryKey:@"MeshMessengerLightningNetwork"];
    if (value == nil) return MeshMessengerSecureStoreNotFound;
    if (![value isKindOfClass:NSString.class]) return MeshMessengerSecureStorePlatformFailure;
    NSUInteger index = [@[@"mainnet", @"testnet", @"regtest", @"signet", @"simnet"] indexOfObject:value];
    if (index == NSNotFound) return MeshMessengerSecureStorePlatformFailure;
    if (outputCapacity < 2) return MeshMessengerSecureStoreOutputTooLarge;
    output[0] = 1;
    output[1] = (uint8_t)index;
    *outputLength = 2;
    return MESH_LIBRARY_OK;
  }
  if (walletSelector) {
    if (outputCapacity < 34) return MeshMessengerSecureStoreOutputTooLarge;
    int32_t status = MeshMessengerWalletPins(output);
    if (status == 0) *outputLength = 34;
    return status;
  }
  if (creditPurposeSelector) {
    id value = [NSBundle.mainBundle objectForInfoDictionaryKey:MeshMessengerCreditPurposeKey];
    if (value == nil) return MeshMessengerSecureStoreNotFound;
    if (![value isKindOfClass:NSString.class] ||
        (![(NSString *)value isEqualToString:@"live"] && ![(NSString *)value isEqualToString:@"test"])) {
      return MeshMessengerSecureStorePlatformFailure;
    }
    if (outputCapacity < 2) return MeshMessengerSecureStoreOutputTooLarge;
    output[0] = 1;
    output[1] = [(NSString *)value isEqualToString:@"live"] ? 0 : 1;
    *outputLength = 2;
    return MESH_LIBRARY_OK;
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
  if (ohttpConfigSelector || counterConfigSelector || securityConfigSelector || networkConfigSelector) {
    id value = [NSBundle.mainBundle
        objectForInfoDictionaryKey:ohttpConfigSelector ? @"MeshMessengerOhttpConfig" : counterConfigSelector ? @"MeshMessengerNetworkCounterConfig" : networkConfigSelector ? MeshMessengerNetworkConfigKey : MeshMessengerSecurityConfigKey];
    if (value == nil) {
      return MeshMessengerSecureStoreNotFound;
    }
    if (![value isKindOfClass:NSString.class]) {
      return MeshMessengerSecureStorePlatformFailure;
    }
    if (ohttpConfigSelector && [(NSString *)value length] > 600) return MeshMessengerSecureStorePlatformFailure;
    NSData *data = [(NSString *)value dataUsingEncoding:NSUTF8StringEncoding];
    if (data == nil) {
      return MeshMessengerSecureStorePlatformFailure;
    }
    if (ohttpConfigSelector && (data.length == 0 || data.length > 600)) return MeshMessengerSecureStorePlatformFailure;
    if (counterConfigSelector && data.length > 24576) return MeshMessengerSecureStorePlatformFailure;
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
