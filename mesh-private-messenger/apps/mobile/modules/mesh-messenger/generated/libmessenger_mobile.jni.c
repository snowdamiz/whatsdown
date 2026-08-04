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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_replenish_1prekeys_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_replenish_prekeys((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_reconcile_1prekeys_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_reconcile_prekeys((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_create_1link_1request_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_create_link_request((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_device_1link_1sas_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_device_link_sas((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_authorize_1device_1link_1for_1set_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_authorize_device_link_for_set((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_complete_1device_1link_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_complete_device_link((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_inspect_1device_1set_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_inspect_device_set((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_create_1device_1revocation_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_create_device_revocation((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_prepare_1fanout_1prekeys_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_prepare_fanout_prekeys((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_send_1fanout_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_send_fanout((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1key_1package_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_group_key_package((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1create_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_group_create((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1add_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_group_add((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1remove_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_group_remove((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1send_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_group_send((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1receive_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_group_receive((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1list_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_group_list((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1inspect_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_group_inspect((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1history_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_group_history((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_receive_1message_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_receive_message((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_update_1conversation_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_update_conversation((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_push_1intent_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_push_intent((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_push_1action_1complete_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_push_action_complete((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_push_1status_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_push_status((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_list_1conversations_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_list_conversations((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_load_1history_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_load_history((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_safety_1number_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_safety_number((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_import_1contact_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_import_contact((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_directory_1entry_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_directory_entry((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_directory_1lookup_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_directory_lookup((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_transparency_1lookup_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_transparency_lookup((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_verify_1transparency_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_verify_transparency((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_privacy_1submission_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_privacy_submission((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_mailbox_1fetch_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_mailbox_fetch((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_process_1delivery_1batch_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_process_delivery_batch((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_outbox_1list_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_outbox_list((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_outbox_1ack_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_outbox_ack((const uint8_t *)request_data, (uint64_t)request_len, &response);
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
