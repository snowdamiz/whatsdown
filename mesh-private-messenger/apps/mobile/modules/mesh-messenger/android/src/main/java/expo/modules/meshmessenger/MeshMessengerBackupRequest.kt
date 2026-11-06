package expo.modules.meshmessenger

internal object MeshMessengerBackupRequest {
    private val maximumInputs = mapOf(
        "mesh_messenger_backup_create" to 42004,
        "mesh_messenger_backup_preview" to 16841207,
        "mesh_messenger_backup_import" to 16841239,
        "mesh_messenger_backup_list" to 40239,
        "mesh_messenger_backup_remove" to 40271,
        "mesh_messenger_backup_overview" to 40271,
        "mesh_messenger_backup_page" to 40313,
        "mesh_messenger_backup_pending_state" to 40239,
        "mesh_messenger_backup_pending_resume" to 44371,
        "mesh_messenger_backup_pending_discard" to 40271,
        "mesh_messenger_backup_pending_repair" to 40239
    )

    // Only bounded public framing is admitted here. Core independently checks
    // profile bytes, code/selection policy, custody, rows and current authority.
    fun validate(symbol: String, request: ByteArray, expectedDatabase: ByteArray) {
        val maximum = maximumInputs[symbol]
        require(maximum != null && request.size <= maximum && request.size >= 5 && request[0] == 1.toByte()) { "invalid_backup_native_request" }
        fun length(offset: Int): Long {
            require(offset >= 0 && offset <= request.size - 4) { "invalid_backup_native_request" }
            var value = 0L
            for (i in 0..3) value = (value shl 8) or (request[offset + i].toLong() and 255)
            return value
        }
        val pathCount = length(1)
        require(pathCount in 1..4096 && request.size >= 5 + pathCount && expectedDatabase.size.toLong() == pathCount) { "invalid_backup_native_request" }
        val count = pathCount.toInt()
        require((0 until count).all { request[5 + it] == expectedDatabase[it] }) { "invalid_backup_native_request" }
        if (!symbol.startsWith("mesh_messenger_backup_pending_")) return
        val pathEnd = 5 + count
        val profileCount = length(pathEnd)
        require(profileCount in 1..36134 && profileCount <= request.size - pathEnd - 4) { "invalid_backup_native_request" }
        val commonEnd = pathEnd + 4 + profileCount.toInt()
        when (symbol) {
            "mesh_messenger_backup_pending_state", "mesh_messenger_backup_pending_repair" ->
                require(request.size == commonEnd) { "invalid_backup_native_request" }
            "mesh_messenger_backup_pending_discard" ->
                require(request.size == commonEnd + 32) { "invalid_backup_native_request" }
            "mesh_messenger_backup_pending_resume" -> {
                val codeCount = length(commonEnd + 32)
                require(codeCount in 1..4096 && request.size.toLong() == commonEnd + 36 + codeCount) { "invalid_backup_native_request" }
            }
            else -> error("invalid_backup_native_request")
        }
    }
}
