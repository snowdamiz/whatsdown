package expo.modules.meshmessenger

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import mesh.MeshLibrary

class MeshMessengerModule : Module() {
    private val lock = Any()
    private var started = false

    override fun definition() = ModuleDefinition {
        Name("MeshMessenger")

        AsyncFunction("invoke") { symbol: String, request: ByteArray ->
            synchronized(lock) {
                startIfNeeded()
                when (symbol) {
                    "mesh_messenger_initialize" -> MeshLibrary.initialize(request)
                    "mesh_messenger_validate_outer" -> MeshLibrary.validate_outer(request)
                    "mesh_messenger_store_envelope" -> MeshLibrary.persist_envelope(request)
                    "mesh_messenger_create_account" -> MeshLibrary.create_account_export(request)
                    "mesh_messenger_load_profile" -> MeshLibrary.load_profile_export(request)
                    else -> throw IllegalArgumentException("unknown_export")
                }
            }
        }

        OnDestroy {
            synchronized(lock) {
                if (started) {
                    MeshMessengerHost.unregisterSecureStore()
                    MeshLibrary.shutdownNative()
                    started = false
                }
            }
        }
    }

    private fun startIfNeeded() {
        if (started) return
        val context = appContext.reactContext
            ?: throw IllegalStateException("React context is unavailable")
        MeshMessengerSecureStore.install(context)
        MeshLibrary.ensureInitialized()
        val status = MeshMessengerHost.registerSecureStore()
        check(status == 0) { "Secure-store registration failed (status=$status)" }
        started = true
    }
}

internal object MeshMessengerHost {
    @JvmStatic external fun registerSecureStore(): Int
    @JvmStatic external fun unregisterSecureStore()
}
