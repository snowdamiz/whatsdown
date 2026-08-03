#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include "libmessenger_mobile.h"

static void mesh_throw_library_failure(JNIEnv *env, int32_t status, const MeshLibraryBytes *response) {
  jclass error = (*env)->FindClass(env, "java/lang/IllegalStateException");
  size_t payload_len = response->len > 1048576 ? 1048576 : (size_t)response->len;
  size_t message_len = payload_len + 64;
  char *message = (char *)malloc(message_len);
  if (message == NULL) {
    (*env)->ThrowNew(env, error, "Mesh library call failed");
    return;
  }
  snprintf(message, message_len, "Mesh library call failed (status=%d): %.*s", (int)status, (int)payload_len, response->data == NULL ? "" : (const char *)response->data);
  (*env)->ThrowNew(env, error, message);
  free(message);
}

JNIEXPORT jint JNICALL Java_mesh_MeshLibrary_initializeNative(JNIEnv *env, jclass cls) { (void)env; (void)cls; return mesh_library_init(); }
JNIEXPORT jint JNICALL Java_mesh_MeshLibrary_shutdownNative(JNIEnv *env, jclass cls) { (void)env; (void)cls; return mesh_library_shutdown(); }

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_initialize(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_initialize((const uint8_t *)request_data, (uint64_t)request_len, &response);
  (*env)->ReleaseByteArrayElements(env, request, request_data, JNI_ABORT);
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_validate_1outer(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_validate_outer((const uint8_t *)request_data, (uint64_t)request_len, &response);
  (*env)->ReleaseByteArrayElements(env, request, request_data, JNI_ABORT);
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_persist_1envelope(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_store_envelope((const uint8_t *)request_data, (uint64_t)request_len, &response);
  (*env)->ReleaseByteArrayElements(env, request, request_data, JNI_ABORT);
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_create_1account_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_create_account((const uint8_t *)request_data, (uint64_t)request_len, &response);
  (*env)->ReleaseByteArrayElements(env, request, request_data, JNI_ABORT);
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_load_1profile_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_load_profile((const uint8_t *)request_data, (uint64_t)request_len, &response);
  (*env)->ReleaseByteArrayElements(env, request, request_data, JNI_ABORT);
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_start_1conversation_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_start_conversation((const uint8_t *)request_data, (uint64_t)request_len, &response);
  (*env)->ReleaseByteArrayElements(env, request, request_data, JNI_ABORT);
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  return result;
}

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_receive_1initial_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_receive_initial((const uint8_t *)request_data, (uint64_t)request_len, &response);
  (*env)->ReleaseByteArrayElements(env, request, request_data, JNI_ABORT);
  if (status != MESH_LIBRARY_OK) {
    mesh_throw_library_failure(env, status, &response);
    mesh_library_free_returned_bytes(&response);
    return NULL;
  }
  jbyteArray result = (*env)->NewByteArray(env, (jsize)response.len);
  if (response.len != 0) (*env)->SetByteArrayRegion(env, result, 0, (jsize)response.len, (const jbyte *)response.data);
  mesh_library_free_returned_bytes(&response);
  return result;
}
