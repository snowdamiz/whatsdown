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
    if ((digits & 1) == 0) bytes[digits / 2] = (uint8_t)(nibble << 4);
    else bytes[digits / 2] |= nibble;
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

static void write_u32(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)(value >> 24);
  output[1] = (uint8_t)(value >> 16);
  output[2] = (uint8_t)(value >> 8);
  output[3] = (uint8_t)value;
}

int main(int argc, char **argv) {
  if (argc != 4) return 10;
  size_t outer_len = 0;
  uint8_t *outer = read_hex(argv[1], &outer_len);
  uint8_t public_key[32];
  if (outer == NULL || !parse_key(argv[2], public_key)) return 11;
  size_t request_len = 4 + outer_len + 4 + sizeof(public_key) + 4 + 1;
  uint8_t *request = malloc(request_len);
  if (request == NULL) return 12;
  size_t offset = 0;
  write_u32(request + offset, (uint32_t)outer_len);
  offset += 4;
  memcpy(request + offset, outer, outer_len);
  offset += outer_len;
  write_u32(request + offset, sizeof(public_key));
  offset += 4;
  memcpy(request + offset, public_key, sizeof(public_key));
  offset += sizeof(public_key);
  write_u32(request + offset, 1);
  offset += 4;
  request[offset] = 8;

  MeshLibraryBytes response = {0};
  if (mesh_library_init() != MESH_LIBRARY_OK ||
      mesh_messenger_privacy_submission(request, request_len, &response) != MESH_LIBRARY_OK ||
      response.len < 24 || response.data[0] != 1 ||
      memcmp(response.data + 1, "PRV", 3) != 0 || response.data[20] != 1 ||
      memcmp(response.data + 21, "SED", 3) != 0) {
    return 13;
  }
  FILE *output = fopen(argv[3], "wb");
  if (output == NULL || fwrite(response.data, 1, response.len, output) != response.len ||
      fclose(output) != 0) {
    return 14;
  }
  mesh_library_free_returned_bytes(&response);
  mesh_library_shutdown();
  free(request);
  free(outer);
  puts("mobile privacy submission proof passed");
  return 0;
}
