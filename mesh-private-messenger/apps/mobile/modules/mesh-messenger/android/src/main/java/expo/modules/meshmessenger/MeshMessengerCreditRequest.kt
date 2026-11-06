package expo.modules.meshmessenger

import java.nio.ByteBuffer

// Host authority check only. Mesh owns operation schemas and credit policy.
internal object MeshMessengerCreditRequest {
    fun requiresValidation(symbol: String): Boolean =
        symbol.startsWith("mesh_messenger_credit_") || symbol.startsWith("mesh_messenger_postage_policy_") || symbol in listOf("mesh_messenger_fanout_send", "mesh_messenger_journal_load_bound", "mesh_messenger_journal_save_bound", "mesh_messenger_attachment_fetch_chunk", "mesh_messenger_attachment_upload", "mesh_messenger_attachment_discard", "mesh_messenger_directory_resolve", "mesh_messenger_outbox_drain", "mesh_messenger_push_flow_begin", "mesh_messenger_account_delete", "mesh_messenger_account_discard", "mesh_messenger_account_capabilities", "mesh_messenger_devices_renew", "mesh_messenger_device_revoke", "mesh_messenger_push_flow_intent", "mesh_messenger_push_flow_complete", "mesh_messenger_push_flow_send")

    fun validate(symbol: String, request: ByteArray, database: ByteArray) {
        val known = mapOf("mesh_messenger_attachment_upload" to 4, "mesh_messenger_attachment_discard" to 2, "mesh_messenger_directory_resolve" to 2, "mesh_messenger_outbox_drain" to 2, "mesh_messenger_credit_attachment_grant" to 2, "mesh_messenger_credit_attachment_upload" to 3, "mesh_messenger_credit_attachment_complete" to 2, "mesh_messenger_credit_attachment_delete" to 2, "mesh_messenger_attachment_fetch_chunk" to 3, "mesh_messenger_credit_discover_online" to 1, "mesh_messenger_credit_purchase_continue" to 2,
            "mesh_messenger_credit_action_continue" to 3, "mesh_messenger_credit_signup_policy_online" to 1, "mesh_messenger_credit_postage_continue" to 2,
            "mesh_messenger_postage_policy_view" to 2, "mesh_messenger_postage_policy_prepare" to 2, "mesh_messenger_postage_policy_publish" to 4)
        val ordinary = mapOf("mesh_messenger_fanout_send" to intArrayOf(4096,36134,65,1,32000,32,16384), "mesh_messenger_journal_load_bound" to intArrayOf(4096,36134,256), "mesh_messenger_journal_save_bound" to intArrayOf(4096,36134,256,262144), "mesh_messenger_push_flow_begin" to intArrayOf(4096,36134,1), "mesh_messenger_account_delete" to intArrayOf(4096,36134), "mesh_messenger_account_discard" to intArrayOf(4096,36134), "mesh_messenger_account_capabilities" to intArrayOf(4096,36134), "mesh_messenger_devices_renew" to intArrayOf(4096,305260), "mesh_messenger_device_revoke" to intArrayOf(4096,305260,16), "mesh_messenger_directory_resolve" to intArrayOf(4096,65), "mesh_messenger_outbox_drain" to intArrayOf(4096,1),
            "mesh_messenger_push_flow_intent" to intArrayOf(4096,1), "mesh_messenger_push_flow_complete" to intArrayOf(4096,50,1),
            "mesh_messenger_push_flow_send" to intArrayOf(4096,50))[symbol]
        if (!requiresValidation(symbol)) return
        val fanout = symbol == "mesh_messenger_fanout_send"
        val upload = symbol == "mesh_messenger_attachment_upload"
        val maximumFields = ordinary?.size ?: when (symbol) {
            "mesh_messenger_credit_attachment_prepare" -> 5
            "mesh_messenger_attachment_upload" -> 4
            "mesh_messenger_credit_attachment_part", "mesh_messenger_credit_postage_prepare", "mesh_messenger_postage_policy_publish" -> 4
            else -> 3
        }
        require(request.size in 4..(if (upload) 16_782_000 else ordinary?.sumOf { it + 4 } ?: 5_250_024) && database.size in 1..4096) { "invalid_credit_request" }
        val frame = ByteBuffer.wrap(request)
        val count = ordinary?.size ?: frame.int
        require(count in 1..maximumFields && (known[symbol] == null || count == known[symbol])) { "invalid_credit_request" }
        repeat(count) { index ->
            require(frame.remaining() >= 4) { "invalid_credit_request" }
            val size = frame.int
            val maximum = if (upload) intArrayOf(4096,255,127,16_777_216)[index] else ordinary?.get(index) ?: 1_050_000
            require(size in (if (ordinary != null && !(fanout && index >= 4)) 1 else 0)..maximum && size <= frame.remaining()) { "invalid_credit_request" }
            if (index == 0) {
                val path = ByteArray(size).also { frame.get(it) }
                require(path.contentEquals(database)) { "invalid_credit_request" }
            } else frame.position(frame.position() + size)
        }
        require(!frame.hasRemaining()) { "invalid_credit_request" }
    }
}
