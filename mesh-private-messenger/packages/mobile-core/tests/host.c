#include "libmessenger_mobile.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

static void write_u64(uint8_t *output, uint64_t value) {
  for (size_t index = 0; index < 8; index += 1) {
    output[index] = (uint8_t)(value >> (56 - index * 8));
  }
}

static uint32_t read_u32(const uint8_t *input) {
  return ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16) |
         ((uint32_t)input[2] << 8) | (uint32_t)input[3];
}

static int profile_ids(const uint8_t *profile, size_t profile_len,
                       const uint8_t **account_id, const uint8_t **device_id) {
  if (profile_len < 4) return 0;
  uint32_t username_len = read_u32(profile);
  size_t offset = 4 + username_len;
  if (offset + 4 + 32 + 4 + 16 > profile_len ||
      read_u32(profile + offset) != 32) {
    return 0;
  }
  *account_id = profile + offset + 4;
  offset += 4 + 32;
  if (read_u32(profile + offset) != 16) return 0;
  *device_id = profile + offset + 4;
  return 1;
}

static int profile_entry(const uint8_t *profile, size_t profile_len,
                         const uint8_t **username, size_t *username_len,
                         const uint8_t **entry, size_t *entry_len) {
  if (profile_len < 4) return 0;
  *username_len = read_u32(profile);
  size_t offset = 4;
  if (*username_len == 0 || offset + *username_len + 4 + 32 + 4 + 16 + 4 >
                                profile_len) {
    return 0;
  }
  *username = profile + offset;
  offset += *username_len;
  if (read_u32(profile + offset) != 32) return 0;
  offset += 4 + 32;
  if (read_u32(profile + offset) != 16) return 0;
  offset += 4 + 16;
  *entry_len = read_u32(profile + offset);
  offset += 4;
  if (*entry_len == 0 || offset + *entry_len != profile_len) return 0;
  *entry = profile + offset;
  return 1;
}

static uint8_t *device_set(const uint8_t **profiles,
                           const size_t *profile_lengths, size_t count,
                           uint64_t sequence, size_t *output_len) {
  if (count == 0 || count > 8) return NULL;
  const uint8_t *username = NULL;
  const uint8_t *first_entry = NULL;
  size_t username_len = 0;
  size_t first_entry_len = 0;
  if (!profile_entry(profiles[0], profile_lengths[0], &username, &username_len,
                     &first_entry, &first_entry_len) ||
      first_entry_len < 12 || first_entry[0] != 1 ||
      memcmp(first_entry + 1, "DRE", 3) != 0) {
    return NULL;
  }
  size_t entry_username_len = read_u32(first_entry + 4);
  size_t account_offset = 8 + entry_username_len;
  if (account_offset + 4 > first_entry_len) return NULL;
  size_t account_len = read_u32(first_entry + account_offset);
  account_offset += 4;
  if (account_len == 0 || account_offset + account_len > first_entry_len) {
    return NULL;
  }
  const uint8_t *entries[8] = {0};
  size_t entry_lengths[8] = {0};
  *output_len = 1 + 3 + 4 + username_len + 4 + account_len + 8 + 1 + 1;
  for (size_t index = 0; index < count; index += 1) {
    const uint8_t *next_username = NULL;
    size_t next_username_len = 0;
    if (!profile_entry(profiles[index], profile_lengths[index],
                       &next_username, &next_username_len, &entries[index],
                       &entry_lengths[index]) ||
        next_username_len != username_len ||
        memcmp(next_username, username, username_len) != 0) {
      return NULL;
    }
    *output_len += 4 + entry_lengths[index];
  }
  uint8_t *output = malloc(*output_len);
  if (output == NULL) return NULL;
  size_t offset = 0;
  output[offset++] = 1;
  memcpy(output + offset, "DVS", 3);
  offset += 3;
  write_u32(output + offset, (uint32_t)username_len);
  offset += 4;
  memcpy(output + offset, username, username_len);
  offset += username_len;
  write_u32(output + offset, (uint32_t)account_len);
  offset += 4;
  memcpy(output + offset, first_entry + account_offset, account_len);
  offset += account_len;
  write_u64(output + offset, sequence);
  offset += 8;
  output[offset++] = (uint8_t)count;
  for (size_t index = 0; index < count; index += 1) {
    write_u32(output + offset, (uint32_t)entry_lengths[index]);
    offset += 4;
    memcpy(output + offset, entries[index], entry_lengths[index]);
    offset += entry_lengths[index];
  }
  output[offset++] = 0;
  if (offset != *output_len) {
    free(output);
    return NULL;
  }
  return output;
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

static int bytes_contains(const uint8_t *value, size_t value_len,
                          const uint8_t *needle, size_t needle_len) {
  if (needle_len == 0 || needle_len > value_len) return 0;
  for (size_t index = 0; index <= value_len - needle_len; index += 1) {
    if (memcmp(value + index, needle, needle_len) == 0) return 1;
  }
  return 0;
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

  size_t linked_path_len = strlen(argv[2]) + 8;
  char *linked_path = malloc(linked_path_len);
  if (linked_path == NULL) return 55;
  snprintf(linked_path, linked_path_len, "%s.linked", argv[2]);
  if (mesh_messenger_create_link_request((const uint8_t *)linked_path,
                                         strlen(linked_path), &response) !=
          MESH_LIBRARY_OK ||
      response.len == 0) {
    fprintf(stderr, "create link request failed: %.*s\n", (int)response.len,
            response.data == NULL ? (uint8_t *)"" : response.data);
    return 56;
  }
  size_t link_request_len = (size_t)response.len;
  uint8_t *link_request = malloc(link_request_len);
  if (link_request == NULL) return 57;
  memcpy(link_request, response.data, link_request_len);
  mesh_library_free_returned_bytes(&response);
  if (mesh_messenger_device_link_sas(link_request, link_request_len,
                                     &response) != MESH_LIBRARY_OK ||
      response.len != 12) {
    return 58;
  }
  mesh_library_free_returned_bytes(&response);

  const uint8_t *root_profiles[] = {profile};
  const size_t root_profile_lengths[] = {profile_len};
  size_t root_set_len = 0;
  uint8_t *root_set = device_set(root_profiles, root_profile_lengths, 1, 1,
                                 &root_set_len);
  if (root_set == NULL) return 65;
  const uint8_t *authorize_values[] = {(const uint8_t *)argv[2], root_set,
                                       link_request};
  const size_t authorize_lengths[] = {strlen(argv[2]), root_set_len,
                                      link_request_len};
  size_t authorize_request_len = 0;
  uint8_t *authorize_request = vector_request(
      authorize_values, authorize_lengths, 3, &authorize_request_len);
  if (authorize_request == NULL ||
      mesh_messenger_authorize_device_link_for_set(
          authorize_request, authorize_request_len, &response) !=
          MESH_LIBRARY_OK ||
      response.len == 0) {
    return 59;
  }
  size_t authorization_len = (size_t)response.len;
  uint8_t *authorization = malloc(authorization_len);
  if (authorization == NULL) return 60;
  memcpy(authorization, response.data, authorization_len);
  mesh_library_free_returned_bytes(&response);
  free(authorize_request);
  free(root_set);

  const uint8_t *complete_values[] = {(const uint8_t *)linked_path,
                                      authorization};
  const size_t complete_lengths[] = {strlen(linked_path), authorization_len};
  size_t complete_request_len = 0;
  uint8_t *complete_request = vector_request(
      complete_values, complete_lengths, 2, &complete_request_len);
  if (complete_request == NULL ||
      mesh_messenger_complete_device_link(complete_request,
                                          complete_request_len,
                                          &response) != MESH_LIBRARY_OK ||
      response.len == 0) {
    fprintf(stderr, "complete link failed: %.*s\n", (int)response.len,
            response.data == NULL ? (uint8_t *)"" : response.data);
    return 61;
  }
  size_t linked_profile_len = (size_t)response.len;
  uint8_t *linked_profile = malloc(linked_profile_len);
  if (linked_profile == NULL) return 62;
  memcpy(linked_profile, response.data, linked_profile_len);
  mesh_library_free_returned_bytes(&response);
  if (mesh_messenger_load_profile((const uint8_t *)linked_path,
                                  strlen(linked_path), &response) !=
          MESH_LIBRARY_OK ||
      response.len != linked_profile_len ||
      memcmp(response.data, linked_profile, linked_profile_len) != 0) {
    return 63;
  }
  mesh_library_free_returned_bytes(&response);
  const uint8_t *root_account_id = NULL;
  const uint8_t *root_device_id = NULL;
  const uint8_t *linked_account_id = NULL;
  const uint8_t *linked_device_id = NULL;
  if (!profile_ids(profile, profile_len, &root_account_id, &root_device_id) ||
      !profile_ids(linked_profile, linked_profile_len, &linked_account_id,
                   &linked_device_id) ||
      memcmp(root_account_id, linked_account_id, 32) != 0 ||
      memcmp(root_device_id, linked_device_id, 16) == 0) {
    return 64;
  }
  const uint8_t *linked_profiles[] = {profile, linked_profile};
  const size_t linked_profile_lengths[] = {profile_len, linked_profile_len};
  size_t linked_set_len = 0;
  uint8_t *linked_set = device_set(linked_profiles, linked_profile_lengths, 2,
                                   2, &linked_set_len);
  if (linked_set == NULL) return 66;
  const uint8_t *inspect_values[] = {(const uint8_t *)argv[2], linked_set};
  const size_t inspect_lengths[] = {strlen(argv[2]), linked_set_len};
  size_t inspect_request_len = 0;
  uint8_t *inspect_request = vector_request(
      inspect_values, inspect_lengths, 2, &inspect_request_len);
  if (inspect_request == NULL ||
      mesh_messenger_inspect_device_set(inspect_request, inspect_request_len,
                                        &response) != MESH_LIBRARY_OK ||
      !bytes_contains(response.data, (size_t)response.len, root_device_id, 16) ||
      !bytes_contains(response.data, (size_t)response.len, linked_device_id,
                      16)) {
    return 67;
  }
  mesh_library_free_returned_bytes(&response);
  free(inspect_request);

  const uint8_t *revoke_values[] = {(const uint8_t *)argv[2], linked_set,
                                     linked_device_id};
  const size_t revoke_lengths[] = {strlen(argv[2]), linked_set_len, 16};
  size_t revoke_request_len = 0;
  uint8_t *revoke_request = vector_request(revoke_values, revoke_lengths, 3,
                                           &revoke_request_len);
  if (revoke_request == NULL ||
      mesh_messenger_create_device_revocation(revoke_request,
                                               revoke_request_len,
                                               &response) != MESH_LIBRARY_OK ||
      response.len == 0) {
    return 68;
  }
  mesh_library_free_returned_bytes(&response);
  free(revoke_request);
  free(linked_set);
  free(complete_request);
  free(authorization);
  free(link_request);

  if (mesh_messenger_directory_entry((const uint8_t *)bob_path,
                                     strlen(bob_path), &response) !=
          MESH_LIBRARY_OK ||
      response.len == 0) {
    return 50;
  }
  size_t bob_entry_len = (size_t)response.len;
  uint8_t *bob_entry = malloc(bob_entry_len);
  if (bob_entry == NULL) return 51;
  memcpy(bob_entry, response.data, bob_entry_len);
  mesh_library_free_returned_bytes(&response);
  if (mesh_messenger_import_contact(bob_entry, bob_entry_len, &response) !=
          MESH_LIBRARY_OK ||
      response.len != bob_profile_len ||
      memcmp(response.data, bob_profile, bob_profile_len) != 0) {
    return 52;
  }
  mesh_library_free_returned_bytes(&response);
  free(bob_entry);
  if (mesh_messenger_directory_lookup((const uint8_t *)"bob", 3, &response) !=
          MESH_LIBRARY_OK ||
      response.len == 0) {
    return 53;
  }
  mesh_library_free_returned_bytes(&response);
  if (mesh_messenger_mailbox_fetch((const uint8_t *)bob_path, strlen(bob_path),
                                   &response) != MESH_LIBRARY_OK ||
      response.len == 0) {
    return 54;
  }
  mesh_library_free_returned_bytes(&response);

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

  const uint8_t *alice_peer_values[] = {(const uint8_t *)argv[2], bob_profile};
  const size_t alice_peer_lengths[] = {strlen(argv[2]), bob_profile_len};
  size_t alice_peer_len = 0;
  uint8_t *alice_peer = vector_request(alice_peer_values, alice_peer_lengths, 2,
                                       &alice_peer_len);
  if (alice_peer == NULL ||
      mesh_messenger_safety_number(alice_peer, alice_peer_len, &response) !=
          MESH_LIBRARY_OK ||
      response.len != 64) {
    return 41;
  }
  uint8_t safety_number[64];
  memcpy(safety_number, response.data, sizeof(safety_number));
  mesh_library_free_returned_bytes(&response);

  const uint8_t *bob_peer_values[] = {(const uint8_t *)bob_path, profile};
  const size_t bob_peer_lengths[] = {strlen(bob_path), profile_len};
  size_t bob_peer_len = 0;
  uint8_t *bob_peer =
      vector_request(bob_peer_values, bob_peer_lengths, 2, &bob_peer_len);
  if (bob_peer == NULL ||
      mesh_messenger_safety_number(bob_peer, bob_peer_len, &response) !=
          MESH_LIBRARY_OK ||
      response.len != sizeof(safety_number) ||
      memcmp(response.data, safety_number, sizeof(safety_number)) != 0) {
    return 42;
  }
  mesh_library_free_returned_bytes(&response);
  if (mesh_messenger_list_conversations((const uint8_t *)bob_path,
                                        strlen(bob_path), &response) !=
          MESH_LIBRARY_OK ||
      !bytes_contains(response.data, (size_t)response.len,
                      (const uint8_t *)"alice", 5)) {
    return 43;
  }
  mesh_library_free_returned_bytes(&response);
  free(alice_peer);

  static const uint8_t reply[] = "hello alice";
  const uint8_t *send_values[] = {(const uint8_t *)bob_path, profile, reply};
  const size_t send_lengths[] = {strlen(bob_path), profile_len,
                                 sizeof(reply) - 1};
  size_t send_request_len = 0;
  uint8_t *send_request =
      vector_request(send_values, send_lengths, 3, &send_request_len);
  if (send_request == NULL ||
      mesh_messenger_send_message(send_request, send_request_len, &response) !=
          MESH_LIBRARY_ERR_APPLICATION) {
    return 35;
  }
  mesh_library_free_returned_bytes(&response);

  static const uint8_t accept_action[] = {1};
  static const uint8_t zero_value[] = {0, 0, 0, 0};
  const uint8_t *policy_values[] = {(const uint8_t *)bob_path, profile,
                                    accept_action, zero_value};
  const size_t policy_lengths[] = {strlen(bob_path), profile_len, 1, 4};
  size_t policy_request_len = 0;
  uint8_t *policy_request =
      vector_request(policy_values, policy_lengths, 4, &policy_request_len);
  if (policy_request == NULL ||
      mesh_messenger_update_conversation(policy_request, policy_request_len,
                                         &response) != MESH_LIBRARY_OK) {
    return 36;
  }
  mesh_library_free_returned_bytes(&response);
  free(policy_request);

  if (
      mesh_messenger_send_message(send_request, send_request_len, &response) !=
          MESH_LIBRARY_OK ||
      response.len == 0) {
    return 31;
  }
  size_t reply_outer_len = (size_t)response.len;
  uint8_t *reply_outer = malloc(reply_outer_len);
  if (reply_outer == NULL) return 32;
  memcpy(reply_outer, response.data, reply_outer_len);
  mesh_library_free_returned_bytes(&response);
  free(send_request);

  const uint8_t *reply_receive_values[] = {(const uint8_t *)argv[2],
                                           reply_outer};
  const size_t reply_receive_lengths[] = {strlen(argv[2]), reply_outer_len};
  size_t reply_receive_request_len = 0;
  uint8_t *reply_receive_request =
      vector_request(reply_receive_values, reply_receive_lengths, 2,
                     &reply_receive_request_len);
  if (reply_receive_request == NULL ||
      mesh_messenger_receive_message(reply_receive_request,
                                     reply_receive_request_len,
                                     &response) != MESH_LIBRARY_OK ||
      response.len != sizeof(reply) - 1 ||
      memcmp(response.data, reply, sizeof(reply) - 1) != 0) {
    return 33;
  }
  mesh_library_free_returned_bytes(&response);
  if (mesh_messenger_receive_message(reply_receive_request,
                                     reply_receive_request_len,
                                     &response) != MESH_LIBRARY_ERR_APPLICATION) {
    return 34;
  }
  mesh_library_free_returned_bytes(&response);

  static const uint8_t block_action[] = {2};
  const uint8_t *block_policy_values[] = {(const uint8_t *)bob_path, profile,
                                          block_action, zero_value};
  const size_t block_policy_lengths[] = {strlen(bob_path), profile_len, 1, 4};
  size_t block_policy_len = 0;
  uint8_t *block_policy = vector_request(block_policy_values,
                                         block_policy_lengths, 4,
                                         &block_policy_len);
  if (block_policy == NULL ||
      mesh_messenger_update_conversation(block_policy, block_policy_len,
                                         &response) != MESH_LIBRARY_OK) {
    return 37;
  }
  mesh_library_free_returned_bytes(&response);
  free(block_policy);

  static const uint8_t blocked_body[] = "blocked message";
  const uint8_t *blocked_send_values[] = {(const uint8_t *)argv[2], bob_profile,
                                          blocked_body};
  const size_t blocked_send_lengths[] = {strlen(argv[2]), bob_profile_len,
                                         sizeof(blocked_body) - 1};
  size_t blocked_send_len = 0;
  uint8_t *blocked_send = vector_request(blocked_send_values,
                                         blocked_send_lengths, 3,
                                         &blocked_send_len);
  if (blocked_send == NULL ||
      mesh_messenger_send_message(blocked_send, blocked_send_len, &response) !=
          MESH_LIBRARY_OK ||
      response.len == 0) {
    return 38;
  }
  size_t blocked_outer_len = (size_t)response.len;
  uint8_t *blocked_outer = malloc(blocked_outer_len);
  if (blocked_outer == NULL) return 39;
  memcpy(blocked_outer, response.data, blocked_outer_len);
  mesh_library_free_returned_bytes(&response);
  free(blocked_send);

  const uint8_t *blocked_receive_values[] = {(const uint8_t *)bob_path,
                                             blocked_outer};
  const size_t blocked_receive_lengths[] = {strlen(bob_path), blocked_outer_len};
  size_t blocked_receive_len = 0;
  uint8_t *blocked_receive = vector_request(blocked_receive_values,
                                            blocked_receive_lengths, 2,
                                            &blocked_receive_len);
  if (blocked_receive == NULL ||
      mesh_messenger_receive_message(blocked_receive, blocked_receive_len,
                                     &response) !=
          MESH_LIBRARY_ERR_APPLICATION) {
    return 40;
  }
  mesh_library_free_returned_bytes(&response);
  free(blocked_receive);
  free(blocked_outer);

  static const uint8_t unblock_action[] = {3};
  const uint8_t *unblock_values[] = {(const uint8_t *)bob_path, profile,
                                     unblock_action, zero_value};
  const size_t unblock_lengths[] = {strlen(bob_path), profile_len, 1, 4};
  size_t unblock_len = 0;
  uint8_t *unblock_request =
      vector_request(unblock_values, unblock_lengths, 4, &unblock_len);
  if (unblock_request == NULL ||
      mesh_messenger_update_conversation(unblock_request, unblock_len,
                                         &response) != MESH_LIBRARY_OK) {
    return 44;
  }
  mesh_library_free_returned_bytes(&response);
  free(unblock_request);

  static const uint8_t disappear_action[] = {5};
  static const uint8_t one_second[] = {0, 0, 0, 1};
  const uint8_t *disappear_values[] = {(const uint8_t *)argv[2], bob_profile,
                                       disappear_action, one_second};
  const size_t disappear_lengths[] = {strlen(argv[2]), bob_profile_len, 1, 4};
  size_t disappear_len = 0;
  uint8_t *disappear_request = vector_request(
      disappear_values, disappear_lengths, 4, &disappear_len);
  if (disappear_request == NULL ||
      mesh_messenger_update_conversation(disappear_request, disappear_len,
                                         &response) != MESH_LIBRARY_OK) {
    return 45;
  }
  mesh_library_free_returned_bytes(&response);
  free(disappear_request);

  static const uint8_t ephemeral_body[] = "gone soon";
  const uint8_t *ephemeral_values[] = {(const uint8_t *)argv[2], bob_profile,
                                       ephemeral_body};
  const size_t ephemeral_lengths[] = {strlen(argv[2]), bob_profile_len,
                                      sizeof(ephemeral_body) - 1};
  size_t ephemeral_len = 0;
  uint8_t *ephemeral_request =
      vector_request(ephemeral_values, ephemeral_lengths, 3, &ephemeral_len);
  if (ephemeral_request == NULL ||
      mesh_messenger_send_message(ephemeral_request, ephemeral_len, &response) !=
          MESH_LIBRARY_OK ||
      response.len == 0) {
    return 46;
  }
  size_t ephemeral_outer_len = (size_t)response.len;
  uint8_t *ephemeral_outer = malloc(ephemeral_outer_len);
  if (ephemeral_outer == NULL) return 47;
  memcpy(ephemeral_outer, response.data, ephemeral_outer_len);
  mesh_library_free_returned_bytes(&response);
  free(ephemeral_request);

  const uint8_t *ephemeral_receive_values[] = {(const uint8_t *)bob_path,
                                               ephemeral_outer};
  const size_t ephemeral_receive_lengths[] = {strlen(bob_path),
                                              ephemeral_outer_len};
  size_t ephemeral_receive_len = 0;
  uint8_t *ephemeral_receive =
      vector_request(ephemeral_receive_values, ephemeral_receive_lengths, 2,
                     &ephemeral_receive_len);
  if (ephemeral_receive == NULL ||
      mesh_messenger_receive_message(ephemeral_receive, ephemeral_receive_len,
                                     &response) != MESH_LIBRARY_OK ||
      response.len != sizeof(ephemeral_body) - 1) {
    return 48;
  }
  mesh_library_free_returned_bytes(&response);
  free(ephemeral_receive);
  free(ephemeral_outer);

  sleep(2);
  if (mesh_messenger_load_history(bob_peer, bob_peer_len, &response) !=
          MESH_LIBRARY_OK ||
      bytes_contains(response.data, (size_t)response.len, ephemeral_body,
                     sizeof(ephemeral_body) - 1)) {
    return 49;
  }
  mesh_library_free_returned_bytes(&response);
  free(bob_peer);
  free(reply_receive_request);
  free(reply_outer);
  free(initial_outer);
  free(bob_profile);
  free(bob_path);
  free(linked_profile);
  free(linked_path);
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
