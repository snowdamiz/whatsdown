# Native JNI resolves these exact private callback names. They deliberately
# have no Java/Mesh/JS callers and must survive release shrinking unchanged.
-keep class expo.modules.meshmessenger.MeshMessengerWalletStore {
    *;
}
# The shared Host callback bridge resolves these by class/method name too.
-keep class expo.modules.meshmessenger.MeshMessengerPushMaterial {
    *;
}
-keep class expo.modules.meshmessenger.MeshMessengerSecureStore {
    *;
}
