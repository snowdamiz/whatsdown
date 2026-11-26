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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_account_1deletion_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_account_deletion((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_erase_1account_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_erase_account((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_device_1departure_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_device_departure((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_forget_1on_1proof_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_forget_on_proof((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1invite_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_group_invite((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1invitation_1accept_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_group_invitation_accept((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1invitation_1complete_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_group_invitation_complete((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1invitation_1decline_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_group_invitation_decline((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1invitations_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_group_invitations((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1forget_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_group_forget((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_register_1request_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_register_request((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_renew_1devices_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_renew_devices((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_oblivious_1encapsulate_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_oblivious_encapsulate((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_oblivious_1decapsulate_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_oblivious_decapsulate((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_resolve_1request_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_resolve_request((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_transparency_1anchor_1requests_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_transparency_anchor_requests((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_transparency_1anchor_1proof_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_transparency_anchor_proof((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_anchor_1check_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_anchor_check((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_gossip_1check_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_gossip_check((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_trust_1alarm_1details_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_trust_alarm_details((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_wallet_1rpc_1urls_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_wallet_rpc_urls((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_network_1status_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_network_status((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_outbox_1fail_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_outbox_fail((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_outbox_1page_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_outbox_page((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_journal_1load_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_journal_load((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_journal_1save_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_journal_save((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1begin_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_backup_begin((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1confirm_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_backup_confirm((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1status_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_backup_status((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1prepare_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_backup_prepare((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1part_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_backup_part((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1finish_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_backup_finish((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1disable_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_backup_disable((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1restore_1slots_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_backup_restore_slots((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1restore_1begin_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_backup_restore_begin((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1restore_1chunk_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_backup_restore_chunk((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1restore_1finish_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_backup_restore_finish((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1restore_1identity_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_backup_restore_identity((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_backup_1restore_1account_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_backup_restore_account((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_presentation_1load_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_presentation_load((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_presentation_1save_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_presentation_save((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_attachment_1prepare_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_attachment_prepare((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_attachment_1seal_1chunk_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_attachment_seal_chunk((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_attachment_1open_1chunk_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_attachment_open_chunk((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_expiry_1purge_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_expiry_purge((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1timer_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_group_timer((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1timer_1state_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_group_timer_state((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_send_1view_1once_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_send_view_once((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1send_1view_1once_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_group_send_view_once((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_open_1view_1once_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_open_view_once((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_group_1open_1view_1once_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_group_open_view_once((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_safety_1code_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_safety_code((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_safety_1code_1check_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_safety_code_check((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credits_1status_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_credits_status((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credits_1refresh_1keys_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_credits_refresh_keys((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credits_1quote_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_credits_quote((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credits_1issue_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_credits_issue((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credits_1postage_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_credits_postage((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credits_1postage_1quote_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_credits_postage_quote((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credits_1retention_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_credits_retention((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credits_1signup_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_credits_signup((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credits_1register_1at_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_credits_register_at((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credits_1spend_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_credits_spend((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credits_1settle_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_credits_settle((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credits_1inbox_1policy_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_credits_inbox_policy((const uint8_t *)request_data, (uint64_t)request_len, &response);
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

JNIEXPORT jbyteArray JNICALL Java_mesh_MeshLibrary_credits_1group_1handover_1export(JNIEnv *env, jclass cls, jbyteArray request) {
  (void)cls;
  jsize request_len = (*env)->GetArrayLength(env, request);
  jbyte *request_data = (*env)->GetByteArrayElements(env, request, NULL);
  MeshLibraryBytes response = {0};
  int32_t status = mesh_messenger_credits_group_handover((const uint8_t *)request_data, (uint64_t)request_len, &response);
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
