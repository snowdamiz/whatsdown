package expo.modules.meshmessenger

import android.content.Context
import android.content.Intent
import android.os.Bundle
import com.google.firebase.messaging.RemoteMessage
import expo.modules.notifications.notifications.model.Notification
import expo.modules.notifications.notifications.model.NotificationBehaviorRecord
import expo.modules.notifications.notifications.model.NotificationRequest
import expo.modules.notifications.notifications.model.RemoteNotificationContent
import expo.modules.notifications.notifications.model.triggers.FirebaseNotificationTrigger
import expo.modules.notifications.service.NotificationsService
import java.util.UUID

/** Legacy Expo entry points carry no authority to retain or route private data. */
class MeshMessengerNotificationsService : NotificationsService() {
    override fun onPresentNotification(context: Context, intent: Intent) {
        // Never deserialize or build an old private Expo request. The app's
        // current message publisher owns private display and opaque tap IDs.
        val behavior=intent.getParcelableExtra<NotificationBehaviorRecord>(NOTIFICATION_BEHAVIOR_KEY)
        if(behavior?.shouldPresentAlert != false) MeshMessengerLockedNotifications.genericWakeup()
    }
    override fun onReceiveNotification(context: Context, intent: Intent) {
        if(MeshMessengerAppLock.restrictionActive()) {
            MeshMessengerLockedNotifications.genericWakeup()
            return
        }
        // Preserve only the alert-versus-silent distinction. Actual Expo/JS
        // receives a fresh fixed wake payload and no original ID, title, body,
        // route, attachment, trigger, action or transport metadata.
        val visible=runCatching {
            val content=intent.getParcelableExtra<Notification>(NOTIFICATION_KEY)?.notificationRequest?.content
            content != null && (!content.title.isNullOrEmpty() || !content.text.isNullOrEmpty())
        }.getOrDefault(false)
        val message=RemoteMessage(Bundle().apply {
            putString("body","{\"kind\":\"encrypted-wakeup\"}")
            if(visible) putString("message",context.getString(R.string.morse_al1_generic_activity))
        })
        val replacement=Notification(NotificationRequest(UUID.randomUUID().toString(),
            RemoteNotificationContent(message),FirebaseNotificationTrigger(message)))
        getHandlingDelegate(context).handleNotification(replacement)
    }
    override fun onReceiveNotificationResponse(context: Context, intent: Intent) {
        // Legacy actions never restore a conversation route or enter Expo's
        // pending-response cache, even while the app-lock policy is disabled.
        MeshMessengerAppLock.recordInboxOpen()
        val launch=context.packageManager.getLaunchIntentForPackage(context.packageName)
        launch?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)?.let(context::startActivity)
    }
    override fun onScheduleNotification(context: Context, intent: Intent) {
        // Morse publishes new messages through the native publisher. Retired
        // Expo schedules cannot create another plaintext store or alarm.
        MeshMessengerLockedNotifications.genericWakeup()
    }
    override fun onNotificationTriggered(context: Context, intent: Intent) {
        MeshMessengerLockedNotifications.genericWakeup()
    }
    override fun onSetupScheduledNotifications(context: Context, intent: Intent) {
        MeshMessengerLockedNotifications.drainLegacy()
    }
}
