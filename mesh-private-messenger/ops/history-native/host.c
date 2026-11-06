#include "libhistory_native.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
  uint8_t *key, *value;
  size_t key_len, value_len;
} Record;
static Record records[256];
static size_t total_bytes;
static uint32_t be32(const uint8_t *p) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
         p[3];
}
static void put32(uint8_t *p, size_t n) {
  p[0] = n >> 24;
  p[1] = n >> 16;
  p[2] = n >> 8;
  p[3] = n;
}
static int32_t get(void *ctx, const uint8_t *input, uint64_t n, uint8_t *out,
                   uint64_t cap, uint64_t *len) {
  (void)ctx;
  *len = 0;
  if (!input || n == 0 || n > 4096)
    return 1;
  for (size_t i = 0; i < 256; i++)
    if (records[i].key_len == n && !memcmp(records[i].key, input, n)) {
      if (records[i].value_len > cap)
        return 4;
      memcpy(out, records[i].value, records[i].value_len);
      *len = records[i].value_len;
      return 0;
    }
  return 2;
}
static int32_t put(void *ctx, const uint8_t *input, uint64_t n, uint8_t *out,
                   uint64_t cap, uint64_t *len) {
  (void)ctx;
  (void)out;
  (void)cap;
  *len = 0;
  if (!input || n < 6 || n > 1048576)
    return 1;
  size_t k = be32(input);
  if (!k || k > 4096 || k >= n - 4)
    return 1;
  size_t v = n - 4 - k;
  Record *slot = NULL;
  for (size_t i = 0; i < 256; i++)
    if (records[i].key_len == k && !memcmp(records[i].key, input + 4, k)) {
      slot = &records[i];
      break;
    }
  if (!slot)
    for (size_t i = 0; i < 256; i++)
      if (!records[i].key_len) {
        slot = &records[i];
        break;
      }
  if (!slot)
    return 4;
  size_t next = total_bytes - slot->key_len - slot->value_len + k + v;
  if (next > 1048576)
    return 4;
  uint8_t *key = malloc(k), *value = malloc(v);
  if (!key || !value) {
    free(key);
    free(value);
    return 3;
  }
  memcpy(key, input + 4, k);
  memcpy(value, input + 4 + k, v);
  if (slot->value) {
    memset(slot->value, 0, slot->value_len);
    free(slot->value);
  }
  free(slot->key);
  *slot = (Record){key, value, k, v};
  total_bytes = next;
  return 0;
}
static int32_t drop(void *ctx, const uint8_t *input, uint64_t n, uint8_t *out,
                    uint64_t cap, uint64_t *len) {
  (void)ctx;
  (void)out;
  (void)cap;
  *len = 0;
  for (size_t i = 0; i < 256; i++)
    if (records[i].key_len == n && !memcmp(records[i].key, input, n)) {
      total_bytes -= records[i].key_len + records[i].value_len;
      memset(records[i].value, 0, records[i].value_len);
      free(records[i].value);
      free(records[i].key);
      records[i] = (Record){0};
      return 0;
    }
  return 2;
}
static int field(const uint8_t *data, size_t total, size_t *at, size_t expected,
                 const uint8_t **value) {
  if (*at > total || total - *at < 4)
    return 0;
  size_t n = be32(data + *at);
  *at += 4;
  if (n != expected || n > total - *at)
    return 0;
  *value = data + *at;
  *at += n;
  return 1;
}
static int check(const MeshLibraryBytes *response) {
  if (response->len != 8404488 || !response->data)
    return 0;
  const uint8_t *data = response->data, *p;
  size_t at = 0;
  if (!field(data, response->len, &at, 4, &p) || be32(p) != 256)
    return 0;
  for (size_t row = 0; row < 256; row++) {
    const uint8_t *entry;
    if (!field(data, response->len, &at, 32826, &entry))
      return 0;
    size_t pos = 0;
    if (!field(entry, 32826, &pos, 1, &p) || *p != 1)
      return 0;
    if (!field(entry, 32826, &pos, 16, &p))
      return 0;
    for (size_t j = 0; j < 16; j++)
      if (p[j] != (uint8_t)row)
        return 0;
    if (!field(entry, 32826, &pos, 8, &p))
      return 0;
    for (size_t j = 0; j < 7; j++)
      if (p[j] != 0)
        return 0;
    if (p[7] != 1)
      return 0;
    if (!field(entry, 32826, &pos, 32768, &p))
      return 0;
    for (size_t j = 0; j < 32768; j++)
      if (p[j] != 120)
        return 0;
    if (!field(entry, 32826, &pos, 4, &p) || be32(p) != 0)
      return 0;
    if (!field(entry, 32826, &pos, 0, &p))
      return 0;
    if (!field(entry, 32826, &pos, 1, &p) || p[0] != 0 || pos != 32826)
      return 0;
  }
  return at == response->len;
}
int main(int argc, char **argv) {
  if (argc != 2)
    return 1;
  if (mesh_library_init() != 0)
    return 2;
  MeshLibraryHostCallbacksV1 callbacks = {0};
  callbacks.abi_version = MESH_LIBRARY_ABI_VERSION;
  callbacks.struct_size = sizeof(callbacks);
  callbacks.secure_store_get = get;
  callbacks.secure_store_put = put;
  callbacks.secure_store_delete = drop;
  if (mesh_library_register_host_callbacks(&callbacks) != 0)
    return 3;
  MeshLibraryBytes peer = {0};
  int status = mesh_history_fixture_seed((const uint8_t *)argv[1],
                                         strlen(argv[1]), &peer);
  if (status) {
    fprintf(stderr, "seed failed status=%d: %.*s\n", status, (int)peer.len,
            peer.data);
    return 4;
  }
  size_t path_len = strlen(argv[1]), request_len = 8 + path_len + peer.len;
  uint8_t *request = malloc(request_len);
  if (!request)
    return 5;
  put32(request, path_len);
  memcpy(request + 4, argv[1], path_len);
  put32(request + 4 + path_len, peer.len);
  memcpy(request + 8 + path_len, peer.data, peer.len);
  mesh_library_free_returned_bytes(&peer);
  MeshLibraryBytes response = {0};
  status = mesh_history_fixture_default_load(request, request_len, &response);
  if (status != MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE || response.len ||
      response.data) {
    fprintf(stderr, "default bound failed status=%d len=%llu\n", status,
            (unsigned long long)response.len);
    return 6;
  }
  puts("default1MiB response correctly refused");
  status = mesh_history_fixture_load(request, request_len, &response);
  if (status || !check(&response)) {
    fprintf(stderr, "large history failed status=%d len=%llu\n", status,
            (unsigned long long)response.len);
    return 7;
  }
  printf("production256-row history verified bytes=%llu request_bytes=%zu "
         "secure_store_bytes=%zu\n",
         (unsigned long long)response.len, request_len, total_bytes);
  MeshLibraryBytes replay = {0};
  status = mesh_history_fixture_load(request, request_len, &replay);
  if (status || replay.len != response.len ||
      memcmp(replay.data, response.data, response.len))
    return 8;
  puts("repeat native production read exact; all256 IDs, timestamps,32768-byte "
       "bodies and states verified");
  mesh_library_free_returned_bytes(&replay);
  mesh_library_free_returned_bytes(&response);
  free(request);
  if (mesh_library_shutdown() != 0)
    return 9;
  for (size_t i = 0; i < 256; i++)
    if (records[i].key_len) {
      memset(records[i].value, 0, records[i].value_len);
      free(records[i].value);
      free(records[i].key);
    }
  return 0;
}
