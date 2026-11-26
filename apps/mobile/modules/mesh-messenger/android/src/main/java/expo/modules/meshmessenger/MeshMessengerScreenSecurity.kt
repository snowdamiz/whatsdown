package expo.modules.meshmessenger

import android.app.Activity
import android.view.WindowManager

/**
 * Message content must not appear in screenshots, screen recordings, casts, or
 * the recents thumbnail. FLAG_SECURE belongs to a window, so it is applied when
 * the module starts and again each time the activity returns to the foreground.
 */
internal object MeshMessengerScreenSecurity {
    fun protect(activity: Activity?) {
        activity ?: return
        activity.runOnUiThread {
            activity.window?.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE,
            )
        }
    }
}
