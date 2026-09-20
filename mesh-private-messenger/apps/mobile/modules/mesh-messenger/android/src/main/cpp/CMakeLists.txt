cmake_minimum_required(VERSION 3.22.1)
project(mesh_messenger)

set(MODULE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../..")
set(GENERATED_DIR "${MODULE_ROOT}/generated")
set(CORE_ARCHIVE "${MODULE_ROOT}/native/android/${ANDROID_ABI}/libmessenger_mobile.a")

if(NOT EXISTS "${CORE_ARCHIVE}")
  message(FATAL_ERROR "Missing ${CORE_ARCHIVE}; run scripts/build-mobile-native.sh android")
endif()

add_library(mesh_messenger_core STATIC IMPORTED)
set_target_properties(mesh_messenger_core PROPERTIES IMPORTED_LOCATION "${CORE_ARCHIVE}")

add_library(messenger_mobile SHARED
  "${GENERATED_DIR}/libmessenger_mobile.jni.c"
  MeshMessengerHost.cpp
)
target_include_directories(messenger_mobile PRIVATE "${GENERATED_DIR}")
target_link_libraries(messenger_mobile PRIVATE mesh_messenger_core log android dl m)
