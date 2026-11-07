#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include "proof.h"

static void mesh_erase_and_free(void *allocation, size_t length) {
  if (allocation == NULL) return;
  volatile uint8_t *bytes = (volatile uint8_t *)allocation;
  while (length != 0) { *bytes++ = 0; --length; }
  free(allocation);
}

static void mesh_throw_library_failure(JNIEnv *env, int32_t status, const MeshLibraryBytes *response) {
  if ((*env)->ExceptionCheck(env)) return;
  jclass error = (*env)->FindClass(env, "java/lang/IllegalStateException");
  if (error == NULL || (*env)->ExceptionCheck(env)) return;
  size_t payload_len = response->data == NULL ? 0 : response->len > 1048576 ? 1048576 : (size_t)response->len;
  size_t message_len = payload_len + 64;
  char *message = (char *)malloc(message_len);
  if (message == NULL) {
    (*env)->ThrowNew(env, error, "Mesh library call failed");
    return;
  }
  snprintf(message, message_len, "Mesh library call failed (status=%d): %.*s", (int)status, (int)payload_len, response->data == NULL ? "" : (const char *)response->data);
  (*env)->ThrowNew(env, error, message);
  mesh_erase_and_free(message, message_len);
}

JNIEXPORT jint JNICALL Java_mesh_MeshLibrary_initializeNative(JNIEnv *env, jclass cls) { (void)env; (void)cls; return mesh_library_init(); }
JNIEXPORT jint JNICALL Java_mesh_MeshLibrary_shutdownNative(JNIEnv *env, jclass cls) { (void)env; (void)cls; return mesh_library_shutdown(); }

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_proof_1caller_1pc(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_inbox_proof_caller_pc((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_proof_1batch_1selection(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_inbox_proof_batch_selection((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_proof_1path_1selection(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_inbox_proof_path_selection((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_proof_1whole_1argument(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_inbox_proof_whole_argument((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_proof_1wire_1argument(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_inbox_proof_wire_argument((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_initialize(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_initialize((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_validate_1outer(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_validate_outer((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_persist_1envelope(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_store_envelope((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_create_1account_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_create_account((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_load_1profile_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_load_profile((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_create_1signup_1draft_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_create_signup_draft((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_signup_1draft_1state_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_signup_draft_state((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1action_1recovery_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_action_recovery((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1signup_1policy_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_signup_policy((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1signup_1policy_1view_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_signup_policy_view((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_signup_1draft_1rename_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_signup_draft_rename((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_signup_1draft_1free_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_signup_draft_free((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_signup_1draft_1free_1complete_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_signup_draft_free_complete((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1signup_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_signup((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1signup_1recover_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_signup_recover((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_register_1signup_1policy_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_register_signup_policy((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1attachment_1prepare_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_attachment_prepare((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1attachment_1recover_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_attachment_recover((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1attachment_1receipt_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_attachment_receipt((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1attachment_1part_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_attachment_part((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1attachment_1part_1recover_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_attachment_part_recover((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1attachment_1prune_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_attachment_prune((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1attachment_1preview_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_attachment_preview((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1attachments_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_attachments((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_attachment_1download_1plan_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_attachment_download_plan((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_replenish_1prekeys_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_replenish_prekeys((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_reconcile_1prekeys_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_reconcile_prekeys((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_create_1link_1request_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_create_link_request((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_device_1link_1sas_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_device_link_sas((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_authorize_1device_1link_1for_1set_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_authorize_device_link_for_set((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_complete_1device_1link_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_complete_device_link((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_inspect_1device_1set_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_inspect_device_set((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_create_1device_1revocation_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_create_device_revocation((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_account_1deletion_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_account_deletion((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_erase_1account_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_erase_account((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_device_1departure_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_device_departure((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_forget_1on_1proof_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_forget_on_proof((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_receive_1initial_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_receive_initial((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_prepare_1fanout_1prekeys_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_prepare_fanout_prekeys((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_send_1fanout_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_send_fanout((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1key_1package_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_group_key_package((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1invite_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_group_invite((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1invitation_1accept_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_group_invitation_accept((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1invitation_1complete_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_group_invitation_complete((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1invitation_1decline_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_group_invitation_decline((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1invitations_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_group_invitations((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1create_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_group_create((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1add_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_group_add((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1remove_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_group_remove((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1send_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_group_send((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1receive_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_group_receive((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1list_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_group_list((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1inspect_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_group_inspect((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1history_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_group_history((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1forget_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_group_forget((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_receive_1message_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_receive_message((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_update_1conversation_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_update_conversation((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_push_1intent_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_push_intent((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_push_1action_1complete_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_push_action_complete((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_push_1status_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_push_status((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_list_1conversations_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_list_conversations((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_load_1history_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_load_history((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 16794632ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_safety_1number_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_safety_number((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_import_1contact_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_import_contact((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_directory_1entry_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_directory_entry((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_directory_1lookup_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_directory_lookup((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_transparency_1lookup_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_transparency_lookup((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_register_1request_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_register_request((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_renew_1devices_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_renew_devices((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_resolve_1request_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_resolve_request((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_resolve_1plan_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_resolve_plan((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_verify_1transparency_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_verify_transparency((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_transparency_1fork_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_transparency_fork((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_bounty_1status_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_bounty_status((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_bounty_1set_1enabled_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_bounty_set_enabled((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_bounty_1commit_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_bounty_commit((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_bounty_1unavailable_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_bounty_unavailable((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_bounty_1transfer_1status_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_bounty_transfer_status((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_bounty_1transfer_1recover_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_bounty_transfer_recover((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_bounty_1transfer_1cancel_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_bounty_transfer_cancel((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_bounty_1transfer_1prepare_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_bounty_transfer_prepare((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_bounty_1transfer_1commit_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_bounty_transfer_commit((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_bounty_1transfer_1submit_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_bounty_transfer_submit((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_anchor_1check_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_anchor_check((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_fork_1filing_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_fork_filing((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_privacy_1submission_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_privacy_submission((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_mailbox_1fetch_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_mailbox_fetch((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_mailbox_1synchronize_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_mailbox_synchronize((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_mailbox_1stream_1open_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_mailbox_stream_open((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_mailbox_1stream_1poll_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_mailbox_stream_poll((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_mailbox_1stream_1close_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_mailbox_stream_close((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_process_1delivery_1batch_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_process_delivery_batch((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_outbox_1list_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_outbox_list((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_outbox_1drain_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_outbox_drain((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_outbox_1ack_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_outbox_ack((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_outbox_1fail_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_outbox_fail((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_outbox_1page_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_outbox_page((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_journal_1load_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_journal_load((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_journal_1save_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_journal_save((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_presentation_1load_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_presentation_load((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_presentation_1save_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_presentation_save((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_attachment_1prepare_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_attachment_prepare((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_attachment_1seal_1chunk_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_attachment_seal_chunk((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1discover_1online_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_discover_online((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1purchase_1continue_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_purchase_continue((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1payment_1handoff_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_payment_handoff((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1action_1continue_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_action_continue((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1signup_1policy_1online_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_signup_policy_online((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1discovery_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_discovery((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1admit_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_admit((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1prepare_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_prepare((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1prepare_1again_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_prepare_again((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1quote_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_quote((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1payment_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_payment((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1finalize_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_finalize((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1recover_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_recover((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1purchases_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_purchases((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1balance_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_balance((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1reserve_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_reserve((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1reservation_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_reservation((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1retention_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_retention((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1retention_1recover_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_retention_recover((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1receipt_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_receipt((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1payment_1url_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_payment_url((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1payment_1signature_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_payment_signature((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1wallet_1quote_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_wallet_quote((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1wallet_1prepare_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_wallet_prepare((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1wallet_1commit_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_wallet_commit((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1wallet_1submit_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_wallet_submit((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1postage_1candidate_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_postage_candidate((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1postage_1preview_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_postage_preview((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1postage_1prepare_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_postage_prepare((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1postage_1recover_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_postage_recover((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1postage_1receipt_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_postage_receipt((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1postage_1inventory_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_postage_inventory((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_postage_1policy_1view_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_postage_policy_view((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_postage_1policy_1prepare_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_postage_policy_prepare((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1postage_1continue_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_postage_continue((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_postage_1policy_1publish_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_postage_policy_publish((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_directory_1register_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_directory_register((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_prekeys_1synchronize_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_prekeys_synchronize((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1attachment_1grant_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_attachment_grant((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1attachment_1upload_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_attachment_upload((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1attachment_1complete_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_attachment_complete((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credit_1attachment_1delete_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_credit_attachment_delete((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_attachment_1fetch_1chunk_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_attachment_fetch_chunk((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_attachment_1upload_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 16830000ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_attachment_upload((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_attachment_1discard_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_attachment_discard((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_directory_1resolve_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_directory_resolve((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_push_1flow_1intent_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_push_flow_intent((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_push_1flow_1complete_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_push_flow_complete((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_push_1flow_1send_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_push_flow_send((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_push_1flow_1begin_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 40243ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_push_flow_begin((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 4096ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_push_1flow_1validate_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 4154ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_push_flow_validate((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 4096ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_account_1delete_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 40238ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_account_delete((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 4096ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_account_1discard_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 40238ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_account_discard((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 4096ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_account_1capabilities_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 40238ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_account_capabilities((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 4096ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_devices_1renew_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 309364ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_devices_renew((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 4096ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_device_1revoke_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 309384ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_device_revoke((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 4096ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_journal_1load_1bound_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 40498ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_journal_load_bound((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 262144ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_journal_1save_1bound_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 302646ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_journal_save_bound((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 4096ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_fanout_1send_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 88740ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_fanout_send((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 4096ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_network_1counter_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_network_counter((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1policy_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 1048576ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_group_policy((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 1048576ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1create_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 42004ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_backup_create((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 16801001ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1preview_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 16841207ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_backup_preview((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 8192ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1import_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 16841239ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_backup_import((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 4096ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1list_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 40239ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_backup_list((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 4096ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1remove_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 40271ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_backup_remove((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 4096ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1overview_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 40271ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_backup_overview((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 8192ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1page_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 40313ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_backup_page((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 135168ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1pending_1state_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 40239ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_backup_pending_state((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 46ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1pending_1resume_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 44371ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_backup_pending_resume((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 16796869ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1pending_1discard_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 40271ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_backup_pending_discard((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 34ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1pending_1repair_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 40239ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_backup_pending_repair((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 32ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_view_1once_1consume_1native_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  MeshLibraryBytes response = {0};
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request == NULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_INVALID_ARGUMENT, &response);
    return NULL;
  }
  jsize request_len = (*env)->GetArrayLength(env, request);
  if ((*env)->ExceptionCheck(env)) return NULL;
  if (request_len < 0 || (uint64_t)request_len > 40271ULL) {
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
    return NULL;
  }
  uint8_t *request_data = NULL;
  if (request_len != 0) {
    request_data = (uint8_t *)malloc((size_t)request_len);
    if (request_data == NULL) {
      mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &response);
      return NULL;
    }
    (*env)->GetByteArrayRegion(env, request, 0, request_len, (jbyte *)request_data);
    if ((*env)->ExceptionCheck(env)) {
      mesh_erase_and_free(request_data, (size_t)request_len);
      return NULL;
    }
  }
  int32_t status = mesh_messenger_view_once_consume((const uint8_t *)request_data, (uint64_t)request_len, &response);
  mesh_erase_and_free(request_data, (size_t)request_len);
  if ((*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len > 16777225ULL || response.len > INT32_MAX || (response.len != 0 && response.data == NULL)) {
    MeshLibraryBytes invalid_response = {0};
    mesh_throw_library_failure(env, MESH_LIBRARY_ERR_OUTPUT_TOO_LARGE, &invalid_response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (result == NULL || (*env)->ExceptionCheck(env)) {
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  if ((*env)->ExceptionCheck(env)) return NULL;
  return result;
}
