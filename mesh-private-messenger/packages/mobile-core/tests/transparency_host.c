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
  size_t value_len = (size_t)input_len - 4 - key_len;
  if (key_len == 0 || key_len > sizeof(secure_records[0].key) ||
      key_len > input_len - 4 || value_len > sizeof(secure_records[0].value)) {
    return 1;
  }
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

static uint32_t read_u32(const uint8_t *input) {
  return ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16) |
         ((uint32_t)input[2] << 8) | (uint32_t)input[3];
}

static void write_u32(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)(value >> 24);
  output[1] = (uint8_t)(value >> 16);
  output[2] = (uint8_t)(value >> 8);
  output[3] = (uint8_t)value;
}

static uint8_t hex_nibble(char value) {
  if (value >= '0' && value <= '9') return (uint8_t)(value - '0');
  if (value >= 'a' && value <= 'f') return (uint8_t)(value - 'a' + 10);
  return 255;
}

static int parse_key(const char *input, uint8_t output[32]) {
  if (strlen(input) != 64) return 0;
  for (size_t index = 0; index < 32; index += 1) {
    uint8_t high = hex_nibble(input[index * 2]);
    uint8_t low = hex_nibble(input[index * 2 + 1]);
    if (high == 255 || low == 255) return 0;
    output[index] = (uint8_t)((high << 4) | low);
  }
  return 1;
}

static uint8_t *read_file(const char *path, size_t *output_len) {
  FILE *file = fopen(path, "rb");
  if (file == NULL || fseek(file, 0, SEEK_END) != 0) return NULL;
  long length = ftell(file);
  if (length <= 0 || fseek(file, 0, SEEK_SET) != 0) {
    fclose(file);
    return NULL;
  }
  uint8_t *output = malloc((size_t)length);
  if (output == NULL || fread(output, 1, (size_t)length, file) != (size_t)length) {
    free(output);
    fclose(file);
    return NULL;
  }
  fclose(file);
  *output_len = (size_t)length;
  return output;
}

static uint8_t *vectors(const uint8_t **values, const size_t *lengths,
                        size_t count, size_t *output_len) {
  *output_len = count * 4;
  for (size_t index = 0; index < count; index += 1) *output_len += lengths[index];
  uint8_t *output = malloc(*output_len);
  if (output == NULL) return NULL;
  size_t offset = 0;
  for (size_t index = 0; index < count; index += 1) {
    write_u32(output + offset, (uint32_t)lengths[index]);
    offset += 4;
    memcpy(output + offset, values[index], lengths[index]);
    offset += lengths[index];
  }
  return output;
}

int main(int argc, char **argv) {
  static const uint8_t username[] = "alice";
  if (argc != 6) return 10;
  size_t evidence_len = 0;
  uint8_t *evidence = read_file(argv[1], &evidence_len);
  uint8_t service_key[32];
  uint8_t witness_a[32];
  uint8_t witness_b[32];
  if (evidence == NULL || !parse_key(argv[3], service_key) ||
      !parse_key(argv[4], witness_a) || !parse_key(argv[5], witness_b)) {
    return 11;
  }
  if (mesh_library_init() != MESH_LIBRARY_OK ||
      register_secure_store() != MESH_LIBRARY_OK) {
    return 12;
  }

  MeshLibraryBytes response = {0};
  if (mesh_messenger_initialize((const uint8_t *)argv[2], strlen(argv[2]),
                                &response) != MESH_LIBRARY_OK) {
    return 13;
  }
  mesh_library_free_returned_bytes(&response);

  const uint8_t *verify_values[] = {(const uint8_t *)argv[2], username,
                                    evidence, service_key, witness_a, witness_b};
  const size_t verify_lengths[] = {strlen(argv[2]), sizeof(username) - 1,
                                   evidence_len, 32, 32, 32};
  size_t verify_len = 0;
  uint8_t *verify_request = vectors(verify_values, verify_lengths, 6, &verify_len);
  if (verify_request == NULL ||
      mesh_messenger_verify_transparency(verify_request, verify_len, &response) !=
          MESH_LIBRARY_OK ||
      response.len < 4 || response.data[0] != 1 ||
      memcmp(response.data + 1, "DVS", 3) != 0) {
    return 14;
  }
  mesh_library_free_returned_bytes(&response);

  if (mesh_messenger_verify_transparency(verify_request, verify_len, &response) !=
      MESH_LIBRARY_ERR_APPLICATION) {
    return 15;
  }
  mesh_library_free_returned_bytes(&response);
  free(verify_request);
  free(evidence);

  const uint8_t *lookup_values[] = {(const uint8_t *)argv[2], username};
  const size_t lookup_lengths[] = {strlen(argv[2]), sizeof(username) - 1};
  size_t lookup_len = 0;
  uint8_t *lookup_request = vectors(lookup_values, lookup_lengths, 2, &lookup_len);
  int32_t lookup_status = lookup_request == NULL
                              ? MESH_LIBRARY_ERR_INVALID_ARGUMENT
                              : mesh_messenger_transparency_lookup(
                                    lookup_request, lookup_len, &response);
  if (lookup_status != MESH_LIBRARY_OK ||
      response.len != 17 || memcmp(response.data + 1, "KTQ", 3) != 0 ||
      read_u32(response.data + 13) == 0) {
    fprintf(stderr, "lookup failed: status=%d length=%llu payload=%.*s\n",
            lookup_status, (unsigned long long)response.len,
            (int)response.len, response.data == NULL ? (uint8_t *)"" : response.data);
    return 16;
  }
  mesh_library_free_returned_bytes(&response);
  free(lookup_request);
  mesh_library_shutdown();
  puts("mobile transparency proof passed");
  return 0;
}
