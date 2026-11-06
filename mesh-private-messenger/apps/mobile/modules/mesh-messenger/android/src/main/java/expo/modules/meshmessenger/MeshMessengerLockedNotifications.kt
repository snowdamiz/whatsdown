package expo.modules.meshmessenger

import android.app.AlarmManager
import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import expo.modules.notifications.service.NotificationsService
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicInteger

/** Fixed generic restrictive policy with app-owned opaque message tap authority. */
internal object MeshMessengerLockedNotifications {
    const val INBOX_EXTRA = "app.morse.mesh.APP_LOCK_INBOX"
    private const val GENERIC_TAG = "app-lock/encrypted-activity"
    private const val STORE = "expo.modules.notifications.SharedPreferencesNotificationsStore"
    private const val PREFIX = "notification_request-"
    private val publication = Any()
    private val building = AtomicInteger()
    @Volatile private var draining = false
    private lateinit var app: Application
    fun install(application: Application) { app = application }
    fun revokeSystemDelegation() {
        if (Build.VERSION.SDK_INT >= 29) {
            val system=app.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            // Manifest defaults do not clear Firebase's previously initialized
            // proxy setting on upgrade. Revoke OS authority before boot admits IO.
            system.setNotificationDelegate(null)
            check(system.notificationDelegate == null) { "notification_delegation_unavailable" }
        }
    }
    private fun manager() = NotificationManagerCompat.from(app)
    fun consumeIntent(intent: Intent?) {
        if (intent?.getBooleanExtra(INBOX_EXTRA,false) == true) {
            intent.removeExtra(INBOX_EXTRA); MeshMessengerAppLock.recordInboxOpen()
        }
    }
    private fun inboxIntent(): PendingIntent {
        val launch = app.packageManager.getLaunchIntentForPackage(app.packageName) ?: error("notification_launch_unavailable")
        launch.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP).putExtra(INBOX_EXTRA,true)
        return PendingIntent.getActivity(app,0x4d414c31,launch,PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
    }
    private fun fixedGeneric(): android.app.Notification {
        if (Build.VERSION.SDK_INT >= 26) (app.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).createNotificationChannel(
            NotificationChannel("encrypted-wakeups",app.getString(R.string.morse_al1_activity_channel),NotificationManager.IMPORTANCE_DEFAULT))
        return NotificationCompat.Builder(app,"encrypted-wakeups")
            .setSmallIcon(app.applicationInfo.icon).setContentTitle(app.getString(R.string.morse_al1_app_name))
            .setContentText(app.getString(R.string.morse_al1_generic_activity)).setContentIntent(inboxIntent())
            .setAutoCancel(true).setVisibility(NotificationCompat.VISIBILITY_PRIVATE).build()
    }
    fun genericWakeup() = synchronized(publication) {
        if (!draining && manager().areNotificationsEnabled()) manager().notify(GENERIC_TAG,0,fixedGeneric())
    }
    fun publish(frame: String, expected: String) = MeshMessengerAppLock.scoped(expected) {
        require(frame.toByteArray(Charsets.UTF_8).size <= 16_384) { "invalid_notice_frame" }
        val value=JSONObject(frame)
        require(value.opt("version")==1 && value.keys().asSequence().toSet()==setOf("version","id","title","body","scope","mention") && value.get("mention") is Boolean) { "invalid_notice_frame" }
        fun text(key: String, max: Int): String = (value.get(key) as? String)?.also { require(it.toByteArray(Charsets.UTF_8).size<=max && '\u0000' !in it) { "invalid_notice_frame" } } ?: error("invalid_notice_frame")
        val id=text("id",1024);val title=text("title",4096);val body=text("body",8192);val scope=text("scope",1024)
        require(id.isNotEmpty() && scope.isNotEmpty()) { "invalid_notice_frame" }
        require(scope.length <= 70 && Regex("(?:chat/[a-f0-9]{32}|group/[a-f0-9]{64})").matches(scope)) { "invalid_notice_scope" }
        building.incrementAndGet()
        try {
            // Only OS display fields reach NotificationCompat. Neither an Expo
            // request nor a private route/message ID is serialized into extras.
            val built = if (!MeshMessengerAppLock.restrictionActive() && MeshMessengerAppLock.notificationActivityOrNull(expected) != null) {
                val system = app.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                if (Build.VERSION.SDK_INT >= 26 && system.getNotificationChannel("messages") == null) {
                    system.createNotificationChannel(NotificationChannel("messages",
                        app.getString(R.string.morse_al1_messages_channel),NotificationManager.IMPORTANCE_HIGH).apply {
                        lockscreenVisibility = android.app.Notification.VISIBILITY_PRIVATE
                    })
                }
                val metadata=runCatching { app.packageManager.getApplicationInfo(app.packageName,
                    android.content.pm.PackageManager.GET_META_DATA).metaData }.getOrNull()
                val icon=metadata?.getInt("expo.modules.notifications.default_notification_icon",app.applicationInfo.icon) ?: app.applicationInfo.icon
                NotificationCompat.Builder(app,"messages").setSmallIcon(icon)
                    .setContentTitle(title).setContentText(body).setStyle(NotificationCompat.BigTextStyle().bigText(body))
                    .setAutoCancel(true).setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
                    .setPriority(NotificationCompat.PRIORITY_HIGH).setDefaults(NotificationCompat.DEFAULT_SOUND)
                    .apply { metadata?.getInt("expo.modules.notifications.default_notification_color")?.takeIf { it != 0 }?.let {
                        setColor(app.resources.getColor(it,app.theme))
                    } }.build()
            } else null
            synchronized(publication) {
                if(draining || !manager().areNotificationsEnabled()) return@synchronized
                MeshMessengerAppLock.requireEpoch(expected)
                if(MeshMessengerAppLock.restrictionActive() || built == null ||
                    MeshMessengerAppLock.notificationActivityOrNull(expected) == null) {
                    manager().notify(GENERIC_TAG,0,fixedGeneric())
                } else MeshMessengerAppLock.publishNativeNotice(expected,scope) { identifier ->
                    // Short synchronous OS intent/publication shares the gate's
                    // revoke ordering. All parsing/building/provider IO is above.
                    val notice=requireNotNull(built)
                    notice.contentIntent=MeshMessengerNotificationIntents.forNotice(
                        MeshMessengerAppLock.notificationActivity(expected),identifier)
                    manager().notify(identifier,0,notice)
                }
            }
        } finally { building.decrementAndGet() }
    }

    fun drainLegacy() {
        synchronized(publication) { draining=true }
        try {
            val deadline=android.os.SystemClock.elapsedRealtime()+5_000
            while(building.get()!=0) { check(android.os.SystemClock.elapsedRealtime()<deadline) { "notice_drain_timeout" }; Thread.sleep(10) }
            synchronized(publication) {
                val preferences=app.getSharedPreferences(STORE,Context.MODE_PRIVATE)
                val ids=preferences.all.keys.filter { it.startsWith(PREFIX) }.map { it.removePrefix(PREFIX) }
                check(ids.size<=10_000) { "notice_drain_limit" }
                val alarm=app.getSystemService(Context.ALARM_SERVICE) as AlarmManager
                for(id in ids) {
                    // Exact SDK58.1.5 URI and selected-component request codes,
                    // for BOTH pre-upgrade stock and future owned alarm receivers.
                    for(component in listOf(NotificationsService::class.java.name,MeshMessengerNotificationsService::class.java.name)) {
                        val data=Uri.parse("expo-notifications://notifications/").buildUpon().appendPath("scheduled").appendPath(id).appendPath("trigger").build()
                        val intent=Intent(NotificationsService.NOTIFICATION_EVENT_ACTION,data).setComponent(ComponentName(app.packageName,component))
                            .putExtra(NotificationsService.EVENT_TYPE_KEY,"trigger").putExtra(NotificationsService.IDENTIFIER_KEY,id)
                        val flags=PendingIntent.FLAG_NO_CREATE or if(Build.VERSION.SDK_INT>=31)PendingIntent.FLAG_MUTABLE else 0
                        PendingIntent.getBroadcast(app,component.hashCode(),intent,flags)?.let { alarm.cancel(it);it.cancel() }
                    }
                }
                val editor=preferences.edit();ids.forEach { editor.remove(PREFIX+it) };check(editor.commit()) { "notice_drain_persistence" }
                check(preferences.all.keys.none { it.startsWith(PREFIX) }) { "notice_drain_readback" }
                // Cancels real tag/id pairs, including child id0, group summary
                // hash IDs and foreign identifiers; never rely on parsed bodies.
                manager().activeNotifications.forEach { manager().cancel(it.tag,it.id) }
                manager().cancelAll()
                repeat(20) { if(manager().activeNotifications.isEmpty())return; Thread.sleep(10) }
                error("notice_drain_incomplete")
            }
        } finally { synchronized(publication) { draining=false } }
    }
}
