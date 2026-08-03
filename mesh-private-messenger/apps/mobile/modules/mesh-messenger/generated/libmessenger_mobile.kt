package mesh

object MeshLibrary {
    init {
        System.loadLibrary("messenger_mobile")
        val status = initializeNative()
        check(status == 0) { "Mesh library initialization failed (status=$status)" }
    }

    @JvmStatic fun ensureInitialized() = Unit
    @JvmStatic private external fun initializeNative(): Int
    @JvmStatic external fun shutdownNative(): Int
    @JvmStatic external fun initialize(request: ByteArray): ByteArray
    @JvmStatic external fun validate_outer(request: ByteArray): ByteArray
    @JvmStatic external fun persist_envelope(request: ByteArray): ByteArray
    @JvmStatic external fun create_account_export(request: ByteArray): ByteArray
    @JvmStatic external fun load_profile_export(request: ByteArray): ByteArray
}
