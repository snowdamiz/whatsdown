#include "libmessenger_mobile.h"

#include <stdint.h>
#include <sqlite3.h>
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

static uint8_t *prekey_response(const uint8_t account_id[32],
                                const uint8_t device_id[16],
                                const uint64_t *active_ids,
                                size_t active_count, size_t *output_len) {
  if (active_count > 64 || output_len == NULL) return NULL;
  *output_len = 53 + active_count * 8;
  uint8_t *output = malloc(*output_len);
  if (output == NULL) return NULL;
  output[0] = 1;
  memcpy(output + 1, "OTA", 3);
  memcpy(output + 4, account_id, 32);
  memcpy(output + 36, device_id, 16);
  output[52] = (uint8_t)active_count;
  for (size_t index = 0; index < active_count; index += 1) {
    write_u64(output + 53 + index * 8, active_ids[index]);
  }
  return output;
}

static uint32_t read_u32(const uint8_t *input) {
  return ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16) |
         ((uint32_t)input[2] << 8) | (uint32_t)input[3];
}

static uint64_t read_u64(const uint8_t *input) {
  uint64_t value = 0;
  for (size_t index = 0; index < 8; index += 1) {
    value = (value << 8) | input[index];
  }
  return value;
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

static uint8_t *device_set_with_revoked(const uint8_t *profile,
                                        size_t profile_len,
                                        const uint8_t *revoked_device_id,
                                        uint64_t sequence,
                                        size_t *output_len) {
  const uint8_t *profiles[] = {profile};
  const size_t lengths[] = {profile_len};
  size_t active_len = 0;
  uint8_t *active = device_set(profiles, lengths, 1, sequence, &active_len);
  if (active == NULL || active_len == 0 || active[active_len - 1] != 0) {
    free(active);
    return NULL;
  }
  uint8_t *output = realloc(active, active_len + 16);
  if (output == NULL) {
    free(active);
    return NULL;
  }
  output[active_len - 1] = 1;
  memcpy(output + active_len, revoked_device_id, 16);
  *output_len = active_len + 16;
  return output;
}

static int profile_mailbox(const uint8_t *profile, size_t profile_len,
                           const uint8_t **mailbox) {
  const uint8_t *username = NULL;
  const uint8_t *entry = NULL;
  size_t username_len = 0;
  size_t entry_len = 0;
  if (!profile_entry(profile, profile_len, &username, &username_len, &entry,
                     &entry_len) ||
      entry_len < 32) {
    return 0;
  }
  *mailbox = entry + entry_len - 32;
  return 1;
}

static uint8_t *profile_with_prekey(const uint8_t *profile,
                                    size_t profile_len, uint64_t prekey_id,
                                    const uint8_t prekey_public[32]) {
  uint8_t *updated = malloc(profile_len);
  if (updated == NULL) return NULL;
  memcpy(updated, profile, profile_len);

  size_t bundle = 0;
  for (size_t index = 0; index + 4 <= profile_len; index += 1) {
    if (updated[index] == 1 && memcmp(updated + index + 1, "PKB", 3) == 0) {
      bundle = index;
      break;
    }
  }
  if (bundle == 0 || bundle + 10 > profile_len) goto invalid;

  size_t offset = bundle + 4 + 2;
  uint32_t credential_len = read_u32(updated + offset);
  offset += 4;
  if (credential_len > profile_len - offset) goto invalid;
  offset += credential_len;
  const size_t before_one_time = 32 + 32 + 8 + 32 + 64;
  if (offset > profile_len - before_one_time - 8 - 4 - 32) goto invalid;
  offset += before_one_time;
  write_u64(updated + offset, prekey_id);
  offset += 8;
  if (read_u32(updated + offset) != 32) goto invalid;
  memcpy(updated + offset + 4, prekey_public, 32);
  return updated;

invalid:
  free(updated);
  return NULL;
}

static uint8_t *output_list_item(const uint8_t *input, size_t input_len,
                                 size_t requested, size_t *count,
                                 size_t *item_len) {
  if (input_len < 8 || read_u32(input) != 4) return NULL;
  *count = read_u32(input + 4);
  size_t offset = 8;
  for (size_t index = 0; index < *count; index += 1) {
    if (offset + 4 > input_len) return NULL;
    size_t length = read_u32(input + offset);
    offset += 4;
    if (length == 0 || offset + length > input_len) return NULL;
    if (index == requested) {
      uint8_t *item = malloc(length);
      if (item == NULL) return NULL;
      memcpy(item, input + offset, length);
      *item_len = length;
      return item;
    }
    offset += length;
  }
  return NULL;
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

static int output_list_contains(const uint8_t *encoded, size_t encoded_len,
                                const uint8_t *expected,
                                size_t expected_len) {
  if (encoded_len < 8 || read_u32(encoded) != 4) return 0;
  uint32_t count = read_u32(encoded + 4);
  size_t offset = 8;
  for (uint32_t index = 0; index < count; index += 1) {
    if (offset > encoded_len - 4) return 0;
    uint32_t item_len = read_u32(encoded + offset);
    offset += 4;
    if (item_len > encoded_len - offset) return 0;
    if (item_len == expected_len &&
        memcmp(encoded + offset, expected, expected_len) == 0) {
      return 1;
    }
    offset += item_len;
  }
  return 0;
}

static int acknowledge_outbox(const char *database_path,
                              const uint8_t *envelope,
                              size_t envelope_len) {
  MeshLibraryBytes pending = {0};
  int32_t list_status = mesh_messenger_outbox_list(
      (const uint8_t *)database_path, strlen(database_path), &pending);
  int queued = list_status == MESH_LIBRARY_OK &&
               output_list_contains(pending.data, (size_t)pending.len,
                                    envelope, envelope_len);
  mesh_library_free_returned_bytes(&pending);
  if (!queued) return 0;
  const uint8_t *values[] = {(const uint8_t *)database_path, envelope};
  const size_t lengths[] = {strlen(database_path), envelope_len};
  size_t request_len = 0;
  uint8_t *request = vector_request(values, lengths, 2, &request_len);
  MeshLibraryBytes response = {0};
  int32_t status = request == NULL
                       ? MESH_LIBRARY_ERR_INVALID_ARGUMENT
                       : mesh_messenger_outbox_ack(request, request_len,
                                                   &response);
  free(request);
  mesh_library_free_returned_bytes(&response);
  return status == MESH_LIBRARY_OK;
}

static char *encrypted_database_state(const char *database_path) {
  sqlite3 *database = NULL;
  sqlite3_stmt *statement = NULL;
  char *copy = NULL;
  static const char query[] =
      "SELECT COALESCE(group_concat(record_hash || ':' || ciphertext, '|'), "
      "'') FROM (SELECT record_hash, ciphertext FROM encrypted_blobs ORDER BY "
      "record_hash)";
  if (sqlite3_open_v2(database_path, &database, SQLITE_OPEN_READONLY, NULL) !=
          SQLITE_OK ||
      sqlite3_prepare_v2(database, query, -1, &statement, NULL) != SQLITE_OK ||
      sqlite3_step(statement) != SQLITE_ROW) {
    goto done;
  }
  const unsigned char *value = sqlite3_column_text(statement, 0);
  int value_len = sqlite3_column_bytes(statement, 0);
  copy = malloc((size_t)value_len + 1);
  if (copy != NULL) {
    memcpy(copy, value, (size_t)value_len);
    copy[value_len] = '\0';
  }

done:
  sqlite3_finalize(statement);
  sqlite3_close(database);
  return copy;
}

static int set_outbox_write_failure(const char *database_path, int enabled) {
  sqlite3 *database = NULL;
  static const char create_trigger[] =
      "CREATE TRIGGER host_fail_outbox BEFORE INSERT ON encrypted_blobs "
      "WHEN NEW.record_hash = "
      "'2e18a8aa47e3428a0c87b2dd84049e85da6950238b82128496e6c35bd760b220' "
      "BEGIN SELECT RAISE(ABORT, 'forced outbox write failure'); END";
  static const char drop_trigger[] = "DROP TRIGGER host_fail_outbox";
  int ok = sqlite3_open(database_path, &database) == SQLITE_OK &&
           sqlite3_exec(database, enabled ? create_trigger : drop_trigger,
                        NULL, NULL, NULL) == SQLITE_OK;
  sqlite3_close(database);
  return ok;
}

static int set_receive_write_failure(const char *database_path, int enabled) {
  sqlite3 *database = NULL;
  static const char create_trigger[] =
      "CREATE TRIGGER host_fail_receive BEFORE UPDATE ON encrypted_blobs "
      "WHEN NEW.record_hash = "
      "'1157310c10370fde0a5d9bd24a1963b3d14362f1d666addd33e692f9bc246a63' "
      "BEGIN SELECT RAISE(ABORT, 'forced late receive write failure'); END";
  static const char drop_trigger[] = "DROP TRIGGER host_fail_receive";
  int ok = sqlite3_open(database_path, &database) == SQLITE_OK &&
           sqlite3_exec(database, enabled ? create_trigger : drop_trigger,
                        NULL, NULL, NULL) == SQLITE_OK;
  sqlite3_close(database);
  return ok;
}

int main(int argc, char **argv) {
  if (argc != 2) return 10;
  const char *database_path = argv[1];
  if (mesh_library_init() != MESH_LIBRARY_OK) return 12;
  if (register_secure_store() != MESH_LIBRARY_OK) return 20;

  MeshLibraryBytes response = {0};
  if (mesh_messenger_initialize((const uint8_t *)database_path, strlen(database_path), &response) !=
          MESH_LIBRARY_OK ||
      response.len == 0) {
    return 13;
  }
  mesh_library_free_returned_bytes(&response);

  size_t account_request_len = 0;
  uint8_t *create_request =
      account_request(database_path, "alice", &account_request_len);
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
  if (mesh_messenger_load_profile((const uint8_t *)database_path, strlen(database_path),
                                  &response) != MESH_LIBRARY_OK ||
      response.len != profile_len ||
      memcmp(response.data, profile, profile_len) != 0) {
    return 23;
  }
  mesh_library_free_returned_bytes(&response);

  size_t bob_path_len = strlen(database_path) + 5;
  char *bob_path = malloc(bob_path_len);
  if (bob_path == NULL) return 25;
  snprintf(bob_path, bob_path_len, "%s.bob", database_path);
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

  const uint8_t *bob_account_id = NULL;
  const uint8_t *bob_device_id = NULL;
  if (!profile_ids(bob_profile, bob_profile_len, &bob_account_id,
                   &bob_device_id)) {
    return 138;
  }
  static const uint8_t one_prekey[] = {0, 0, 0, 1};
  const uint8_t *replenish_values[] = {(const uint8_t *)bob_path, one_prekey};
  const size_t replenish_lengths[] = {strlen(bob_path), sizeof(one_prekey)};
  size_t replenish_request_len = 0;
  uint8_t *replenish_request = vector_request(
      replenish_values, replenish_lengths, 2, &replenish_request_len);
  if (replenish_request == NULL ||
      mesh_messenger_replenish_prekeys(replenish_request,
                                       replenish_request_len,
                                       &response) != MESH_LIBRARY_OK ||
      response.len != 157 || response.data[0] != 1 ||
      memcmp(response.data + 1, "OTB", 3) != 0 ||
      memcmp(response.data + 4, bob_account_id, 32) != 0 ||
      memcmp(response.data + 36, bob_device_id, 16) != 0 ||
      response.data[52] != 1 || read_u64(response.data + 53) != 3) {
    return 138;
  }
  mesh_library_free_returned_bytes(&response);
  free(replenish_request);

  size_t linked_path_len = strlen(database_path) + 8;
  char *linked_path = malloc(linked_path_len);
  if (linked_path == NULL) return 55;
  snprintf(linked_path, linked_path_len, "%s.linked", database_path);
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
  const uint8_t *authorize_values[] = {(const uint8_t *)database_path, root_set,
                                       link_request};
  const size_t authorize_lengths[] = {strlen(database_path), root_set_len,
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

  const uint8_t *linked_replenish_values[] = {
      (const uint8_t *)linked_path, one_prekey};
  const size_t linked_replenish_lengths[] = {strlen(linked_path),
                                             sizeof(one_prekey)};
  size_t linked_replenish_len = 0;
  uint8_t *linked_replenish = vector_request(
      linked_replenish_values, linked_replenish_lengths, 2,
      &linked_replenish_len);
  if (linked_replenish == NULL ||
      mesh_messenger_replenish_prekeys(linked_replenish,
                                       linked_replenish_len,
                                       &response) != MESH_LIBRARY_OK ||
      response.len != 157 || response.data[52] != 1 ||
      read_u64(response.data + 53) != 3) {
    return 146;
  }
  uint8_t linked_prekey_public[32];
  memcpy(linked_prekey_public, response.data + 61,
         sizeof(linked_prekey_public));
  mesh_library_free_returned_bytes(&response);
  free(linked_replenish);
  uint8_t *claimed_linked_profile = profile_with_prekey(
      linked_profile, linked_profile_len, 3, linked_prekey_public);
  if (claimed_linked_profile == NULL) return 147;

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
  const uint8_t *claimed_linked_profiles[] = {profile,
                                              claimed_linked_profile};
  size_t claimed_linked_set_len = 0;
  uint8_t *claimed_linked_set =
      device_set(claimed_linked_profiles, linked_profile_lengths, 2, 2,
                 &claimed_linked_set_len);
  if (claimed_linked_set == NULL) return 148;
  const uint8_t *inspect_values[] = {(const uint8_t *)database_path, linked_set};
  const size_t inspect_lengths[] = {strlen(database_path), linked_set_len};
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

  const uint8_t *revoke_values[] = {(const uint8_t *)database_path, linked_set,
                                     linked_device_id};
  const size_t revoke_lengths[] = {strlen(database_path), linked_set_len, 16};
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

  const uint8_t *bob_profiles[] = {bob_profile};
  const size_t bob_profile_lengths[] = {bob_profile_len};
  size_t bob_set_len = 0;
  uint8_t *bob_set =
      device_set(bob_profiles, bob_profile_lengths, 1, 1, &bob_set_len);
  if (bob_set == NULL) return 69;

  static const uint8_t greeting[] = "hello bob";
  const uint8_t *start_values[] = {(const uint8_t *)database_path, bob_profile,
                                   greeting};
  const size_t start_lengths[] = {strlen(database_path), bob_profile_len,
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
  if (!acknowledge_outbox(database_path, initial_outer, initial_outer_len)) return 132;

  const uint64_t bob_active_ids[] = {3};
  size_t bob_prekey_response_len = 0;
  uint8_t *bob_prekey_response =
      prekey_response(bob_account_id, bob_device_id, bob_active_ids, 1,
                      &bob_prekey_response_len);
  const uint8_t *bob_reconcile_values[] = {(const uint8_t *)bob_path,
                                           bob_prekey_response};
  const size_t bob_reconcile_lengths[] = {strlen(bob_path),
                                          bob_prekey_response_len};
  size_t bob_reconcile_len = 0;
  uint8_t *bob_reconcile =
      vector_request(bob_reconcile_values, bob_reconcile_lengths, 2,
                     &bob_reconcile_len);
  if (bob_prekey_response == NULL || bob_reconcile == NULL ||
      mesh_messenger_reconcile_prekeys(bob_reconcile, bob_reconcile_len,
                                       &response) != MESH_LIBRARY_OK ||
      response.len != 4 || read_u32(response.data) != 1) {
    return 156;
  }
  mesh_library_free_returned_bytes(&response);
  free(bob_reconcile);
  free(bob_prekey_response);

  const uint8_t *receive_values[] = {(const uint8_t *)bob_path, initial_outer};
  const size_t receive_lengths[] = {strlen(bob_path), initial_outer_len};
  size_t receive_request_len = 0;
  uint8_t *receive_request =
      vector_request(receive_values, receive_lengths, 2, &receive_request_len);
  char *before_failed_receive = encrypted_database_state(bob_path);
  if (receive_request == NULL || before_failed_receive == NULL ||
      !set_receive_write_failure(bob_path, 1)) {
    return 139;
  }
  int32_t failed_receive = mesh_messenger_receive_initial(
      receive_request, receive_request_len, &response);
  mesh_library_free_returned_bytes(&response);
  if (!set_receive_write_failure(bob_path, 0) ||
      failed_receive != MESH_LIBRARY_ERR_APPLICATION) {
    return 140;
  }
  char *after_failed_receive = encrypted_database_state(bob_path);
  if (after_failed_receive == NULL ||
      strcmp(before_failed_receive, after_failed_receive) != 0) {
    return 141;
  }
  free(before_failed_receive);
  free(after_failed_receive);

  if (
      mesh_messenger_receive_initial(receive_request, receive_request_len,
                                     &response) != MESH_LIBRARY_OK ||
      response.len != sizeof(greeting) - 1 ||
      memcmp(response.data, greeting, sizeof(greeting) - 1) != 0) {
    return 30;
  }
  mesh_library_free_returned_bytes(&response);
  if (mesh_messenger_receive_initial(receive_request, receive_request_len,
                                     &response) !=
      MESH_LIBRARY_ERR_APPLICATION) {
    return 118;
  }
  mesh_library_free_returned_bytes(&response);

  /* A different initial session still names Bob's original advertised id=2.
     It must not fall back to the remaining id=3 secret. */
  if (mesh_messenger_start_conversation(start_request, start_request_len,
                                        &response) != MESH_LIBRARY_OK ||
      response.len == 0) {
    return 142;
  }
  size_t reused_outer_len = (size_t)response.len;
  uint8_t *reused_outer = malloc(reused_outer_len);
  if (reused_outer == NULL) return 143;
  memcpy(reused_outer, response.data, reused_outer_len);
  mesh_library_free_returned_bytes(&response);
  if (!acknowledge_outbox(database_path, reused_outer, reused_outer_len)) return 144;
  const uint8_t *reused_values[] = {(const uint8_t *)bob_path, reused_outer};
  const size_t reused_lengths[] = {strlen(bob_path), reused_outer_len};
  size_t reused_request_len = 0;
  uint8_t *reused_request =
      vector_request(reused_values, reused_lengths, 2, &reused_request_len);
  if (reused_request == NULL ||
      mesh_messenger_receive_initial(reused_request, reused_request_len,
                                     &response) !=
          MESH_LIBRARY_ERR_APPLICATION) {
    return 145;
  }
  mesh_library_free_returned_bytes(&response);
  free(reused_request);
  free(reused_outer);
  free(receive_request);
  free(start_request);

  const uint8_t *alice_peer_values[] = {(const uint8_t *)database_path, bob_profile};
  const size_t alice_peer_lengths[] = {strlen(database_path), bob_profile_len};
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
  if (!acknowledge_outbox(bob_path, reply_outer, reply_outer_len)) return 133;
  free(send_request);

  const size_t packet_offset = 70;
  const size_t ratchet_offset = packet_offset + 9;
  const size_t message_number_offset = ratchet_offset + 74;
  const size_t ciphertext_length_offset = ratchet_offset + 90;
  if (reply_outer_len < ciphertext_length_offset + 4 ||
      read_u32(reply_outer + 66) != reply_outer_len - packet_offset ||
      read_u32(reply_outer + packet_offset) != 1 ||
      reply_outer[packet_offset + 4] != 2 ||
      read_u32(reply_outer + packet_offset + 5) !=
          reply_outer_len - ratchet_offset ||
      memcmp(reply_outer + ratchet_offset + 1, "RAT", 3) != 0) {
    return 119;
  }
  size_t ratchet_ciphertext_len =
      read_u32(reply_outer + ciphertext_length_offset);
  if (ratchet_ciphertext_len < 16 ||
      ratchet_offset + 94 + ratchet_ciphertext_len != reply_outer_len) {
    return 120;
  }

  uint8_t *rejected_outer = malloc(reply_outer_len);
  if (rejected_outer == NULL) return 121;
  memcpy(rejected_outer, reply_outer, reply_outer_len);
  write_u32(rejected_outer + message_number_offset, 65);
  const uint8_t *jump_values[] = {(const uint8_t *)database_path, rejected_outer};
  const size_t jump_lengths[] = {strlen(database_path), reply_outer_len};
  size_t jump_request_len = 0;
  uint8_t *jump_request =
      vector_request(jump_values, jump_lengths, 2, &jump_request_len);
  if (jump_request == NULL ||
      mesh_messenger_receive_message(jump_request, jump_request_len,
                                     &response) !=
          MESH_LIBRARY_ERR_APPLICATION) {
    return 122;
  }
  mesh_library_free_returned_bytes(&response);
  free(jump_request);

  memcpy(rejected_outer, reply_outer, reply_outer_len);
  rejected_outer[ratchet_offset + 94 + ratchet_ciphertext_len - 1] ^= 1;
  const uint8_t *tamper_values[] = {(const uint8_t *)database_path, rejected_outer};
  const size_t tamper_lengths[] = {strlen(database_path), reply_outer_len};
  size_t tamper_request_len = 0;
  uint8_t *tamper_request =
      vector_request(tamper_values, tamper_lengths, 2, &tamper_request_len);
  free(rejected_outer);
  if (tamper_request == NULL ||
      mesh_messenger_receive_message(tamper_request, tamper_request_len,
                                     &response) !=
          MESH_LIBRARY_ERR_APPLICATION) {
    return 123;
  }
  mesh_library_free_returned_bytes(&response);
  free(tamper_request);

  const uint8_t *reply_receive_values[] = {(const uint8_t *)database_path,
                                           reply_outer};
  const size_t reply_receive_lengths[] = {strlen(database_path), reply_outer_len};
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

  static const uint8_t synced_body[] = "synced hello";
  const uint8_t *alice_fanout_values[] = {
      (const uint8_t *)database_path, bob_set, linked_set, synced_body};
  const size_t alice_fanout_lengths[] = {
      strlen(database_path), bob_set_len, linked_set_len, sizeof(synced_body) - 1};
  size_t alice_fanout_request_len = 0;
  uint8_t *alice_fanout_request = vector_request(
      alice_fanout_values, alice_fanout_lengths, 4,
      &alice_fanout_request_len);
  char *before_failed_fanout = encrypted_database_state(database_path);
  if (alice_fanout_request == NULL || before_failed_fanout == NULL ||
      !set_outbox_write_failure(database_path, 1)) {
    return 129;
  }
  int32_t failed_fanout = mesh_messenger_send_fanout(
      alice_fanout_request, alice_fanout_request_len, &response);
  mesh_library_free_returned_bytes(&response);
  if (!set_outbox_write_failure(database_path, 0) ||
      failed_fanout != MESH_LIBRARY_ERR_APPLICATION) {
    return 130;
  }
  char *after_failed_fanout = encrypted_database_state(database_path);
  if (after_failed_fanout == NULL ||
      strcmp(before_failed_fanout, after_failed_fanout) != 0) {
    return 131;
  }
  free(before_failed_fanout);
  free(after_failed_fanout);
  if (
      mesh_messenger_send_fanout(alice_fanout_request,
                                 alice_fanout_request_len,
                                 &response) != MESH_LIBRARY_OK) {
    return 70;
  }
  size_t fanout_count = 0;
  size_t fanout_first_len = 0;
  size_t fanout_second_len = 0;
  uint8_t *fanout_first =
      output_list_item(response.data, (size_t)response.len, 0, &fanout_count,
                       &fanout_first_len);
  uint8_t *fanout_second =
      output_list_item(response.data, (size_t)response.len, 1, &fanout_count,
                       &fanout_second_len);
  mesh_library_free_returned_bytes(&response);
  free(alice_fanout_request);
  if (fanout_count != 2 || fanout_first == NULL || fanout_second == NULL ||
      fanout_first_len < 52 || fanout_second_len < 52) {
    return 71;
  }

  /* No network submission occurred. A later public call must reopen SQLite
     and recover the advanced ratchet's exact envelopes from encrypted storage. */
  int32_t retry_list = mesh_messenger_outbox_list(
      (const uint8_t *)database_path, strlen(database_path), &response);
  if (retry_list != MESH_LIBRARY_OK) {
    fprintf(stderr, "outbox retry failed: status=%d payload=%.*s\n",
            retry_list, (int)response.len,
            response.data == NULL ? (uint8_t *)"" : response.data);
    return 124;
  }
  size_t retry_count = 0;
  size_t retry_first_len = 0;
  size_t retry_second_len = 0;
  uint8_t *retry_first = output_list_item(
      response.data, (size_t)response.len, 0, &retry_count, &retry_first_len);
  uint8_t *retry_second = output_list_item(
      response.data, (size_t)response.len, 1, &retry_count,
      &retry_second_len);
  mesh_library_free_returned_bytes(&response);
  if (retry_count != 2 || retry_first_len != fanout_first_len ||
      retry_second_len != fanout_second_len ||
      memcmp(retry_first, fanout_first, fanout_first_len) != 0 ||
      memcmp(retry_second, fanout_second, fanout_second_len) != 0 ||
      !acknowledge_outbox(database_path, retry_first, retry_first_len) ||
      !acknowledge_outbox(database_path, retry_second, retry_second_len)) {
    return 125;
  }
  free(retry_first);
  free(retry_second);
  if (mesh_messenger_outbox_list((const uint8_t *)database_path, strlen(database_path),
                                 &response) != MESH_LIBRARY_OK ||
      response.len != 8 || read_u32(response.data + 4) != 0) {
    return 126;
  }
  mesh_library_free_returned_bytes(&response);
  const uint8_t *bob_mailbox = NULL;
  const uint8_t *linked_mailbox = NULL;
  if (!profile_mailbox(bob_profile, bob_profile_len, &bob_mailbox) ||
      !profile_mailbox(linked_profile, linked_profile_len, &linked_mailbox)) {
    return 72;
  }
  uint8_t *bob_fanout =
      memcmp(fanout_first + 20, bob_mailbox, 32) == 0 ? fanout_first
                                                      : fanout_second;
  size_t bob_fanout_len = bob_fanout == fanout_first ? fanout_first_len
                                                      : fanout_second_len;
  uint8_t *self_fanout = bob_fanout == fanout_first ? fanout_second
                                                     : fanout_first;
  size_t self_fanout_len = self_fanout == fanout_first ? fanout_first_len
                                                        : fanout_second_len;
  if (memcmp(self_fanout + 20, linked_mailbox, 32) != 0) {
    return 73;
  }
  const uint8_t *bob_fanout_receive_values[] = {
      (const uint8_t *)bob_path, bob_fanout};
  const size_t bob_fanout_receive_lengths[] = {strlen(bob_path),
                                               bob_fanout_len};
  size_t bob_fanout_receive_len = 0;
  uint8_t *bob_fanout_receive = vector_request(
      bob_fanout_receive_values, bob_fanout_receive_lengths, 2,
      &bob_fanout_receive_len);
  if (bob_fanout_receive == NULL ||
      mesh_messenger_receive_message(bob_fanout_receive,
                                     bob_fanout_receive_len,
                                     &response) != MESH_LIBRARY_OK ||
      response.len != sizeof(synced_body) - 1 ||
      memcmp(response.data, synced_body, sizeof(synced_body) - 1) != 0) {
    return 74;
  }
  mesh_library_free_returned_bytes(&response);
  free(bob_fanout_receive);
  const uint8_t *self_receive_values[] = {(const uint8_t *)linked_path,
                                          self_fanout};
  const size_t self_receive_lengths[] = {strlen(linked_path), self_fanout_len};
  size_t self_receive_len = 0;
  uint8_t *self_receive = vector_request(self_receive_values,
                                         self_receive_lengths, 2,
                                         &self_receive_len);
  if (self_receive == NULL ||
      mesh_messenger_receive_initial(self_receive, self_receive_len,
                                     &response) != MESH_LIBRARY_OK ||
      response.len != sizeof(synced_body) - 1 ||
      memcmp(response.data, synced_body, sizeof(synced_body) - 1) != 0) {
    return 75;
  }
  mesh_library_free_returned_bytes(&response);
  free(self_receive);
  free(fanout_first);
  free(fanout_second);

  const uint8_t *linked_bob_peer_values[] = {(const uint8_t *)linked_path,
                                             bob_profile};
  const size_t linked_bob_peer_lengths[] = {strlen(linked_path),
                                            bob_profile_len};
  size_t linked_bob_peer_len = 0;
  uint8_t *linked_bob_peer = vector_request(
      linked_bob_peer_values, linked_bob_peer_lengths, 2,
      &linked_bob_peer_len);
  if (linked_bob_peer == NULL ||
      mesh_messenger_load_history(linked_bob_peer, linked_bob_peer_len,
                                  &response) != MESH_LIBRARY_OK ||
      !bytes_contains(response.data, (size_t)response.len, synced_body,
                      sizeof(synced_body) - 1)) {
    return 76;
  }
  mesh_library_free_returned_bytes(&response);

  static const uint8_t fanout_reply[] = "all alice devices";
  const uint8_t *bob_fanout_values[] = {(const uint8_t *)bob_path,
                                        claimed_linked_set, bob_set,
                                        fanout_reply};
  const size_t bob_fanout_lengths[] = {
      strlen(bob_path), claimed_linked_set_len, bob_set_len,
      sizeof(fanout_reply) - 1};
  size_t bob_fanout_request_len = 0;
  uint8_t *bob_fanout_request = vector_request(
      bob_fanout_values, bob_fanout_lengths, 4, &bob_fanout_request_len);
  if (bob_fanout_request == NULL ||
      mesh_messenger_send_fanout(bob_fanout_request, bob_fanout_request_len,
                                 &response) != MESH_LIBRARY_OK) {
    return 77;
  }
  size_t bob_reply_first_len = 0;
  size_t bob_reply_second_len = 0;
  uint8_t *bob_reply_first = output_list_item(
      response.data, (size_t)response.len, 0, &fanout_count,
      &bob_reply_first_len);
  uint8_t *bob_reply_second = output_list_item(
      response.data, (size_t)response.len, 1, &fanout_count,
      &bob_reply_second_len);
  mesh_library_free_returned_bytes(&response);
  free(bob_fanout_request);
  if (fanout_count != 2 || bob_reply_first == NULL ||
      bob_reply_second == NULL || bob_reply_first_len < 52 ||
      bob_reply_second_len < 52) {
    return 78;
  }
  if (!acknowledge_outbox(bob_path, bob_reply_first, bob_reply_first_len) ||
      !acknowledge_outbox(bob_path, bob_reply_second, bob_reply_second_len)) {
    return 127;
  }
  const uint8_t *root_mailbox = NULL;
  if (!profile_mailbox(profile, profile_len, &root_mailbox)) return 79;
  uint8_t *root_reply =
      memcmp(bob_reply_first + 20, root_mailbox, 32) == 0 ? bob_reply_first
                                                          : bob_reply_second;
  size_t root_reply_len = root_reply == bob_reply_first ? bob_reply_first_len
                                                         : bob_reply_second_len;
  uint8_t *linked_reply = root_reply == bob_reply_first ? bob_reply_second
                                                         : bob_reply_first;
  size_t linked_reply_len = linked_reply == bob_reply_first
                                ? bob_reply_first_len
                                : bob_reply_second_len;
  const uint8_t *root_receive_values[] = {(const uint8_t *)database_path, root_reply};
  const size_t root_receive_lengths[] = {strlen(database_path), root_reply_len};
  size_t root_receive_len = 0;
  uint8_t *root_receive = vector_request(root_receive_values,
                                         root_receive_lengths, 2,
                                         &root_receive_len);
  if (root_receive == NULL ||
      mesh_messenger_receive_message(root_receive, root_receive_len,
                                     &response) != MESH_LIBRARY_OK ||
      response.len != sizeof(fanout_reply) - 1) {
    return 80;
  }
  mesh_library_free_returned_bytes(&response);
  free(root_receive);
  const uint8_t *linked_reply_values[] = {(const uint8_t *)linked_path,
                                          linked_reply};
  const size_t linked_reply_lengths[] = {strlen(linked_path), linked_reply_len};
  size_t linked_reply_request_len = 0;
  uint8_t *linked_reply_request = vector_request(
      linked_reply_values, linked_reply_lengths, 2,
      &linked_reply_request_len);
  if (linked_reply_request == NULL ||
      mesh_messenger_receive_initial(linked_reply_request,
                                     linked_reply_request_len,
                                     &response) != MESH_LIBRARY_OK ||
      response.len != sizeof(fanout_reply) - 1) {
    return 81;
  }
  mesh_library_free_returned_bytes(&response);
  free(linked_reply_request);
  free(bob_reply_first);
  free(bob_reply_second);
  if (mesh_messenger_load_history(linked_bob_peer, linked_bob_peer_len,
                                  &response) != MESH_LIBRARY_OK ||
      !bytes_contains(response.data, (size_t)response.len, synced_body,
                      sizeof(synced_body) - 1) ||
      !bytes_contains(response.data, (size_t)response.len, fanout_reply,
                      sizeof(fanout_reply) - 1)) {
    return 82;
  }
  mesh_library_free_returned_bytes(&response);
  if (mesh_messenger_safety_number(linked_bob_peer, linked_bob_peer_len,
                                   &response) != MESH_LIBRARY_OK ||
      response.len != sizeof(safety_number) ||
      memcmp(response.data, safety_number, sizeof(safety_number)) != 0) {
    return 86;
  }
  mesh_library_free_returned_bytes(&response);
  free(linked_bob_peer);

  size_t revoked_set_len = 0;
  uint8_t *revoked_set = device_set_with_revoked(
      profile, profile_len, linked_device_id, 3, &revoked_set_len);
  if (revoked_set == NULL) return 83;
  const uint8_t *revoked_fanout_values[] = {
      (const uint8_t *)bob_path, revoked_set, bob_set, fanout_reply};
  const size_t revoked_fanout_lengths[] = {
      strlen(bob_path), revoked_set_len, bob_set_len,
      sizeof(fanout_reply) - 1};
  size_t revoked_fanout_request_len = 0;
  uint8_t *revoked_fanout_request = vector_request(
      revoked_fanout_values, revoked_fanout_lengths, 4,
      &revoked_fanout_request_len);
  if (revoked_fanout_request == NULL ||
      mesh_messenger_send_fanout(revoked_fanout_request,
                                 revoked_fanout_request_len,
                                 &response) != MESH_LIBRARY_OK) {
    return 84;
  }
  uint8_t *only_active = output_list_item(
      response.data, (size_t)response.len, 0, &fanout_count, &root_reply_len);
  mesh_library_free_returned_bytes(&response);
  free(revoked_fanout_request);
  free(revoked_set);
  if (fanout_count != 1 || only_active == NULL || root_reply_len < 52 ||
      memcmp(only_active + 20, root_mailbox, 32) != 0) {
    return 85;
  }
  if (!acknowledge_outbox(bob_path, only_active, root_reply_len)) return 128;
  free(only_active);

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
  const uint8_t *blocked_send_values[] = {(const uint8_t *)database_path, bob_profile,
                                          blocked_body};
  const size_t blocked_send_lengths[] = {strlen(database_path), bob_profile_len,
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
  if (!acknowledge_outbox(database_path, blocked_outer, blocked_outer_len)) return 134;
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
  const uint8_t *disappear_values[] = {(const uint8_t *)database_path, bob_profile,
                                       disappear_action, one_second};
  const size_t disappear_lengths[] = {strlen(database_path), bob_profile_len, 1, 4};
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
  const uint8_t *ephemeral_values[] = {(const uint8_t *)database_path, bob_profile,
                                       ephemeral_body};
  const size_t ephemeral_lengths[] = {strlen(database_path), bob_profile_len,
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
  if (!acknowledge_outbox(database_path, ephemeral_outer, ephemeral_outer_len)) return 135;
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
  free(bob_set);
  free(linked_set);
  free(claimed_linked_set);
  free(claimed_linked_profile);
  free(bob_profile);
  free(bob_path);
  free(linked_profile);
  free(linked_path);
  free(profile);

  if (mesh_library_shutdown() != MESH_LIBRARY_OK) return 17;
  puts("mobile core host proof passed");
  return 0;
}
