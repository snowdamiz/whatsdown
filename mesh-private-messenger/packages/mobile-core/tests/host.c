#include "libmessenger_mobile.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int main(int argc, char **argv) {
  if (argc != 3) return 10;
  size_t envelope_len = 0;
  uint8_t *envelope = read_hex(argv[1], &envelope_len);
  if (envelope == NULL) return 11;
  if (mesh_library_init() != MESH_LIBRARY_OK) return 12;

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
