#include "libmessenger_mobile.h"

#include <stdint.h>
#include <stdio.h>
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
  for (size_t index = 0; index < 2; index += 1) {
    SecureRecord *record = &secure_records[index];
    if (record->key_len == input_len &&
        memcmp(record->key, input, (size_t)input_len) == 0) {
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
  if (input_len < 4 || output_len == NULL) return 1;
  size_t key_len = ((size_t)input[0] << 24) | ((size_t)input[1] << 16) |
                   ((size_t)input[2] << 8) | (size_t)input[3];
  if (key_len == 0 || key_len > sizeof(secure_records[0].key) ||
      key_len > input_len - 4) {
    return 1;
  }
  size_t value_len = (size_t)input_len - 4 - key_len;
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
  memcpy(record->value, input + 4 + key_len, value_len);
  record->key_len = key_len;
  record->value_len = value_len;
  *output_len = 0;
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

static uint8_t hex_nibble(char value) {
  if (value >= '0' && value <= '9') return (uint8_t)(value - '0');
  if (value >= 'a' && value <= 'f') return (uint8_t)(value - 'a' + 10);
  if (value >= 'A' && value <= 'F') return (uint8_t)(value - 'A' + 10);
  return 255;
}

static uint8_t *read_hex(const char *path, size_t *output_len) {
  FILE *file = fopen(path, "rb");
  if (file == NULL || fseek(file, 0, SEEK_END) != 0) return NULL;
  long file_len = ftell(file);
  if (file_len <= 0 || fseek(file, 0, SEEK_SET) != 0) return NULL;
  char *text = malloc((size_t)file_len);
  if (text == NULL || fread(text, 1, (size_t)file_len, file) != (size_t)file_len) return NULL;
  fclose(file);

  uint8_t *bytes = malloc((size_t)file_len / 2 + 1);
  if (bytes == NULL) return NULL;
  size_t digits = 0;
  for (long index = 0; index < file_len; index += 1) {
    uint8_t nibble = hex_nibble(text[index]);
    if (nibble == 255) continue;
    if ((digits & 1) == 0) {
      bytes[digits / 2] = (uint8_t)(nibble << 4);
    } else {
      bytes[digits / 2] |= nibble;
    }
    digits += 1;
  }
  free(text);
  if ((digits & 1) != 0) {
    free(bytes);
    return NULL;
  }
  *output_len = digits / 2;
  return bytes;
}

static void write_u32(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)(value >> 24);
  output[1] = (uint8_t)(value >> 16);
  output[2] = (uint8_t)(value >> 8);
  output[3] = (uint8_t)value;
}

static uint8_t *store_request(const char *database_path, const uint8_t *envelope,
                              size_t envelope_len, size_t *request_len) {
  static const uint8_t record_key[] = "whatsdown-mobile-record-key";
  size_t path_len = strlen(database_path);
  *request_len = 12 + path_len + sizeof(record_key) - 1 + envelope_len;
  uint8_t *request = malloc(*request_len);
  if (request == NULL) return NULL;
  size_t offset = 0;
  write_u32(request + offset, (uint32_t)path_len);
  offset += 4;
  memcpy(request + offset, database_path, path_len);
  offset += path_len;
  write_u32(request + offset, (uint32_t)(sizeof(record_key) - 1));
  offset += 4;
  memcpy(request + offset, record_key, sizeof(record_key) - 1);
  offset += sizeof(record_key) - 1;
  write_u32(request + offset, (uint32_t)envelope_len);
  offset += 4;
  memcpy(request + offset, envelope, envelope_len);
  return request;
}

static uint8_t *account_request(const char *database_path, const char *username,
                                size_t *request_len) {
  size_t path_len = strlen(database_path);
  size_t username_len = strlen(username);
  *request_len = 8 + path_len + username_len;
  uint8_t *request = malloc(*request_len);
  if (request == NULL) return NULL;
  size_t offset = 0;
  const char *values[] = {database_path, username};
  const size_t lengths[] = {path_len, username_len};
  for (size_t index = 0; index < 2; index += 1) {
    write_u32(request + offset, (uint32_t)lengths[index]);
    offset += 4;
    memcpy(request + offset, values[index], lengths[index]);
    offset += lengths[index];
  }
  return request;
}

static uint8_t *vector_request(const uint8_t **values, const size_t *lengths,
                               size_t count, size_t *request_len) {
  *request_len = count * 4;
  for (size_t index = 0; index < count; index += 1) {
    *request_len += lengths[index];
  }
  uint8_t *request = malloc(*request_len);
  if (request == NULL) return NULL;
  size_t offset = 0;
  for (size_t index = 0; index < count; index += 1) {
    write_u32(request + offset, (uint32_t)lengths[index]);
    offset += 4;
    memcpy(request + offset, values[index], lengths[index]);
    offset += lengths[index];
  }
  return request;
}

int main(int argc, char **argv) {
  if (argc != 3) return 10;
  size_t envelope_len = 0;
  uint8_t *envelope = read_hex(argv[1], &envelope_len);
  if (envelope == NULL) return 11;
  if (mesh_library_init() != MESH_LIBRARY_OK) return 12;
  if (register_secure_store() != MESH_LIBRARY_OK) return 20;

  MeshLibraryBytes response = {0};
  if (mesh_messenger_initialize((const uint8_t *)argv[2], strlen(argv[2]), &response) !=
          MESH_LIBRARY_OK ||
      response.len == 0) {
    return 13;
  }
  mesh_library_free_returned_bytes(&response);

  if (mesh_messenger_validate_outer(envelope, envelope_len, &response) != MESH_LIBRARY_OK ||
      response.len != envelope_len || memcmp(response.data, envelope, envelope_len) != 0) {
    return 14;
  }
  mesh_library_free_returned_bytes(&response);

  if (envelope_len < 70) return 18;
  size_t stored_envelope_len = 86;
  uint8_t *stored_envelope = malloc(stored_envelope_len);
  if (stored_envelope == NULL) return 19;
  memcpy(stored_envelope, envelope, 70);
  write_u32(stored_envelope + 66, 16);
  for (size_t index = 70; index < stored_envelope_len; index += 1) {
    stored_envelope[index] = (uint8_t)index;
  }

  size_t request_len = 0;
  uint8_t *request =
      store_request(argv[2], stored_envelope, stored_envelope_len, &request_len);
  int32_t store_status = request == NULL
                             ? MESH_LIBRARY_ERR_INVALID_ARGUMENT
                             : mesh_messenger_store_envelope(request, request_len, &response);
  if (store_status != MESH_LIBRARY_OK || response.len != 64) {
    fprintf(stderr, "store failed: status=%d payload=%.*s\n", store_status,
            (int)response.len, response.data == NULL ? (uint8_t *)"" : response.data);
    return 15;
  }
  mesh_library_free_returned_bytes(&response);
  free(request);
  free(stored_envelope);

  size_t account_request_len = 0;
  uint8_t *create_request =
      account_request(argv[2], "alice", &account_request_len);
  int32_t create_status = create_request == NULL
                              ? MESH_LIBRARY_ERR_INVALID_ARGUMENT
                              : mesh_messenger_create_account(
                                    create_request, account_request_len, &response);
  if (create_status != MESH_LIBRARY_OK || response.len == 0) {
    fprintf(stderr, "create account failed: status=%d payload=%.*s\n",
            create_status, (int)response.len,
            response.data == NULL ? (uint8_t *)"" : response.data);
    return 21;
  }
  uint8_t *profile = malloc((size_t)response.len);
  size_t profile_len = (size_t)response.len;
  if (profile == NULL) return 22;
  memcpy(profile, response.data, profile_len);
  mesh_library_free_returned_bytes(&response);
  if (mesh_messenger_create_account(create_request, account_request_len,
                                    &response) != MESH_LIBRARY_ERR_APPLICATION) {
    return 24;
  }
  mesh_library_free_returned_bytes(&response);
  free(create_request);
  if (mesh_messenger_load_profile((const uint8_t *)argv[2], strlen(argv[2]),
                                  &response) != MESH_LIBRARY_OK ||
      response.len != profile_len ||
      memcmp(response.data, profile, profile_len) != 0) {
    return 23;
  }
  mesh_library_free_returned_bytes(&response);

  size_t bob_path_len = strlen(argv[2]) + 5;
  char *bob_path = malloc(bob_path_len);
  if (bob_path == NULL) return 25;
  snprintf(bob_path, bob_path_len, "%s.bob", argv[2]);
  size_t bob_request_len = 0;
  uint8_t *bob_request = account_request(bob_path, "bob", &bob_request_len);
  if (bob_request == NULL ||
      mesh_messenger_create_account(bob_request, bob_request_len, &response) !=
          MESH_LIBRARY_OK ||
      response.len == 0) {
    return 26;
  }
  size_t bob_profile_len = (size_t)response.len;
  uint8_t *bob_profile = malloc(bob_profile_len);
  if (bob_profile == NULL) return 27;
  memcpy(bob_profile, response.data, bob_profile_len);
  mesh_library_free_returned_bytes(&response);
  free(bob_request);

  static const uint8_t greeting[] = "hello bob";
  const uint8_t *start_values[] = {(const uint8_t *)argv[2], bob_profile,
                                   greeting};
  const size_t start_lengths[] = {strlen(argv[2]), bob_profile_len,
                                  sizeof(greeting) - 1};
  size_t start_request_len = 0;
  uint8_t *start_request =
      vector_request(start_values, start_lengths, 3, &start_request_len);
  if (start_request == NULL ||
      mesh_messenger_start_conversation(start_request, start_request_len,
                                        &response) != MESH_LIBRARY_OK ||
      response.len == 0) {
    return 28;
  }
  size_t initial_outer_len = (size_t)response.len;
  uint8_t *initial_outer = malloc(initial_outer_len);
  if (initial_outer == NULL) return 29;
  memcpy(initial_outer, response.data, initial_outer_len);
  mesh_library_free_returned_bytes(&response);
  free(start_request);

  const uint8_t *receive_values[] = {(const uint8_t *)bob_path, initial_outer};
  const size_t receive_lengths[] = {strlen(bob_path), initial_outer_len};
  size_t receive_request_len = 0;
  uint8_t *receive_request =
      vector_request(receive_values, receive_lengths, 2, &receive_request_len);
  if (receive_request == NULL ||
      mesh_messenger_receive_initial(receive_request, receive_request_len,
                                     &response) != MESH_LIBRARY_OK ||
      response.len != sizeof(greeting) - 1 ||
      memcmp(response.data, greeting, sizeof(greeting) - 1) != 0) {
    return 30;
  }
  mesh_library_free_returned_bytes(&response);
  free(receive_request);
  free(initial_outer);
  free(bob_profile);
  free(bob_path);
  free(profile);

  const uint8_t invalid[] = {0, 1, 2};
  if (mesh_messenger_validate_outer(invalid, sizeof(invalid), &response) !=
      MESH_LIBRARY_ERR_APPLICATION) {
    return 16;
  }
  mesh_library_free_returned_bytes(&response);
  free(envelope);
  if (mesh_library_shutdown() != MESH_LIBRARY_OK) return 17;
  puts("mobile core host proof passed");
  return 0;
}
