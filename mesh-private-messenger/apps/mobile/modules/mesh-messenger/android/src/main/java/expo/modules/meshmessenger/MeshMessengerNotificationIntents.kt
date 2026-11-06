package expo.modules.meshmessenger

import android.app.Activity
import android.app.PendingIntent
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Looper

/** App-owned entry point called before React/Expo sees a launch Intent. */
object MeshMessengerNotificationIntents {
    private const val ACTION = "app.morse.mesh.NOTICE_OPEN"
    private const val IDENTIFIER = "app.morse.mesh.NOTICE_ID"
    private val identifier = Regex("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")
    private val ingressKeys = setOf(IDENTIFIER, "app.morse.mesh.APP_LOCK_INBOX", "google.message_id",
        "notificationResponse", "textInputNotificationResponse")

    @JvmStatic fun consumeBeforeReact(activity: Activity, intent: Intent?) {
        check(Looper.myLooper() == Looper.getMainLooper()) { "native_notice_owner_required" }
        // Installation is process-idempotent and precedes React startup, including
        // ordinary launches. Policy and orphan IO run on the existing worker.
        MeshMessengerAppLock.install(activity.application)
        if(intent == null) return
        var notice=false
        val id=try {
            val extras=intent.extras
            val keys=extras?.keySet().orEmpty()
            notice=intent.action == ACTION || keys.any { it in ingressKeys }
            if(!notice) return
            // Only our direct immutable intent has this exact shape. Never
            // deserialize legacy response bytes merely to recover a route.
            if(intent.action == ACTION && keys == setOf(IDENTIFIER)) {
                (extras?.get(IDENTIFIER) as? String)?.takeIf { it.length == 36 && identifier.matches(it) }
            } else null
        } catch (_: RuntimeException) {
            // Malformed parcelables must not escape into Expo/React caches.
            notice=true;null
        }
        if(!notice) return
        intent.replaceExtras(null as Bundle?)
        intent.data=null;intent.clipData=null;intent.selector=null;intent.action=Intent.ACTION_MAIN
        if(id == null) MeshMessengerAppLock.recordInboxOpen()
        else MeshMessengerAppLock.receiveNativeNotice(id,activity)
    }

    internal fun forNotice(activity: Activity, id: String): PendingIntent {
        require(id.length == 36 && identifier.matches(id)) { "invalid_notice_identifier" }
        val intent=Intent(activity,activity.javaClass).setAction(ACTION)
            .setData(Uri.parse("morse-notification://open/$id"))
            .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            .putExtra(IDENTIFIER,id)
        // Data makes each issuance a distinct OS PendingIntent without using a
        // message ID, scope, title or body in its identity or extras.
        return PendingIntent.getActivity(activity,0,intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
    }
}
