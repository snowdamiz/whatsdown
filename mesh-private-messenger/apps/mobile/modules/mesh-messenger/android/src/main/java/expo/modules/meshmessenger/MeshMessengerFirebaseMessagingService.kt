package expo.modules.meshmessenger

import android.content.Intent
import android.os.Bundle
import com.google.firebase.messaging.RemoteMessage
import expo.modules.notifications.service.ExpoFirebaseMessagingService

/** Remote transport carries a wake signal. Private content comes from scoped sync. */
open class MeshMessengerFirebaseMessagingService : ExpoFirebaseMessagingService() {
    companion object {
        private const val RECEIVE="com.google.android.c2dm.intent.RECEIVE"
        private const val DIRECT_BOOT="com.google.firebase.messaging.RECEIVE_DIRECT_BOOT"
        private const val TOKEN="com.google.firebase.messaging.NEW_TOKEN"
        private const val WAKE="{\"kind\":\"encrypted-wakeup\"}"
        private const val GENERIC="New encrypted activity"
    }

    // Firebase may auto-display and log an intent before onMessageReceived.
    // Never hand its SDK the original extras, notification fields or analytics.
    override fun handleIntent(intent: Intent) {
        val action=intent.action
        if(action==TOKEN) {
            val token=text(intent,"token",4096) ?: return
            super.handleIntent(Intent(TOKEN).putExtra("token",token))
            return
        }
        if(action!=RECEIVE && action!=DIRECT_BOOT) return
        val safe=Intent(action)
        // Only transport acknowledgement/dedup metadata stays inside Firebase.
        // It is removed again before any Expo delegate, logger or TaskManager.
        (text(intent,"google.message_id",1024) ?: text(intent,"message_id",1024))?.let {
            safe.putExtra("google.message_id",it)
        }
        try {
            if(intent.hasExtra("google.product_id")) safe.putExtra("google.product_id",intent.getIntExtra("google.product_id",0))
        } catch(_: RuntimeException) { /* No untrusted object crosses ingress. */ }
        val type=text(intent,"message_type",32)
        safe.putExtra("message_type",when(type) {
            null,"gcm" -> "gcm"
            "deleted_messages","send_event","send_error" -> type
            else -> "send_event" // Acknowledge an unsupported type without a UI/task wake.
        })
        safe.putExtra("body",WAKE)
        if(text(intent,"message",128)==GENERIC || text(intent,"gcm.n.e",4)=="1" ||
            text(intent,"gcm.notification.e",4)=="1") safe.putExtra("message",GENERIC)
        super.handleIntent(safe)
    }

    override fun onMessageReceived(remoteMessage: RemoteMessage) {
        val alert=try { remoteMessage.notification!=null || remoteMessage.data["message"]==GENERIC }
            catch(_: RuntimeException) { false }
        val fresh=Bundle().apply {
            putString("body",WAKE)
            if(alert) putString("message",GENERIC)
        }
        super.onMessageReceived(RemoteMessage(fresh))
    }

    private fun text(intent: Intent,key: String,max: Int): String? = try {
        intent.getStringExtra(key)?.takeIf { it.isNotEmpty() && it.length<=max &&
            !it.contains('\u0000') && !it.contains('\n') && !it.contains('\r') }
    } catch(_: RuntimeException) { null }
}
