#include "libmessenger_mobile.h"

/* ABI and lifecycle smoke only. Protocol and state assertions belong in Mesh. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint8_t key[64];
  size_t key_len;
  uint8_t value[64];
  size_t value_len;
} SecureRecord;

static SecureRecord secure_records[2] = {0};

static int32_t secure_store_get(void *context, const uint8_t *input,
                                uint64_t input_len, uint8_t *output,
                                uint64_t output_capacity,
                                uint64_t *output_len) {
  (void)context;
  if (input == NULL || output == NULL || output_len == NULL) return 1;
  *output_len = 0;
  for (size_t index = 0; index < 2; index += 1) {
    SecureRecord *record = &secure_records[index];
    if (record->key_len == input_len &&
        memcmp(record->key, input, record->key_len) == 0) {
      if (record->value_len > output_capacity) return 1;
      memcpy(output, record->value, record->value_len);
      *output_len = record->value_len;
      return 0;
    }
  }
  return 2;
}

static int32_t secure_store_put(void *context, const uint8_t *input,
                                uint64_t input_len, uint8_t *output,
                                uint64_t output_capacity,
                                uint64_t *output_len) {
  (void)context;
  (void)output;
  (void)output_capacity;
  if (input == NULL || output_len == NULL || input_len < 5) return 1;
  *output_len = 0;
  uint32_t key_len = ((uint32_t)input[0] << 24) |
                     ((uint32_t)input[1] << 16) |
                     ((uint32_t)input[2] << 8) | (uint32_t)input[3];
  if (key_len == 0 || key_len > sizeof(secure_records[0].key) ||
      (uint64_t)key_len + 4 >= input_len) {
    return 1;
  }
  uint64_t value_len = input_len - 4 - key_len;
  if (value_len > sizeof(secure_records[0].value)) return 1;

  SecureRecord *record = NULL;
  for (size_t index = 0; index < 2; index += 1) {
    if (secure_records[index].key_len == 0 ||
        (secure_records[index].key_len == key_len &&
         memcmp(secure_records[index].key, input + 4, key_len) == 0)) {
      record = &secure_records[index];
      break;
    }
  }
  if (record == NULL) return 1;
  memcpy(record->key, input + 4, key_len);
  memcpy(record->value, input + 4 + key_len, (size_t)value_len);
  record->key_len = key_len;
  record->value_len = (size_t)value_len;
  return 0;
}

static int register_secure_store(void) {
  MeshLibraryHostCallbacksV1 callbacks = {0};
  callbacks.abi_version = MESH_LIBRARY_ABI_VERSION;
  callbacks.struct_size = sizeof(callbacks);
  callbacks.secure_store_get = secure_store_get;
  callbacks.secure_store_put = secure_store_put;
  return mesh_library_register_host_callbacks(&callbacks);
}

static void write_u32(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)(value >> 24);
  output[1] = (uint8_t)(value >> 16);
  output[2] = (uint8_t)(value >> 8);
  output[3] = (uint8_t)value;
}

static uint8_t *account_request(const char *database_path,
                                size_t *request_len) {
  static const char username[] = "abi-smoke";
  size_t path_len = strlen(database_path);
  size_t username_len = sizeof(username) - 1;
  if (path_len > UINT32_MAX) return NULL;
  *request_len = 8 + path_len + username_len;
  uint8_t *request = malloc(*request_len);
  if (request == NULL) return NULL;

  write_u32(request, (uint32_t)path_len);
  memcpy(request + 4, database_path, path_len);
  write_u32(request + 4 + path_len, (uint32_t)username_len);
  memcpy(request + 8 + path_len, username, username_len);
  return request;
}

int main(int argc, char **argv) {
  if (argc != 2) return 10;
  if (mesh_library_init() != MESH_LIBRARY_OK) return 11;

  int result = 0;
  MeshLibraryBytes response = {0};
  if (register_secure_store() != MESH_LIBRARY_OK) {
    result = 12;
    goto shutdown;
  }

  int32_t status = mesh_messenger_initialize(
      (const uint8_t *)argv[1], strlen(argv[1]), &response);
  mesh_library_free_returned_bytes(&response);
  if (status != MESH_LIBRARY_OK) {
    result = 13;
    goto shutdown;
  }

  size_t request_len = 0;
  uint8_t *request = account_request(argv[1], &request_len);
  if (request == NULL) {
    result = 14;
    goto shutdown;
  }
  status = mesh_messenger_create_account(request, request_len, &response);
  mesh_library_free_returned_bytes(&response);
  free(request);
  if (status != MESH_LIBRARY_OK) result = 15;

shutdown:
  if (mesh_library_shutdown() != MESH_LIBRARY_OK && result == 0) result = 16;
  return result;
}
