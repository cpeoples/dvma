package com.dvma

import android.util.Log
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification

/**
 * notification_listener_authorization_bypass (CWE-862 / CWE-306, Android
 * CVE-2025-22427 / CVE-2025-26442 class).
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * A real NotificationListenerService. Notification-listener access is a
 * powerful capability normally gated behind an explicit user grant; once bound
 * this listener reads the contents (title/text) of every posted notification -
 * including the sensitive OTP/balance body posted by [PlatformIpc] - and
 * records what it read. The declared service + the sensitive read is the real
 * artifact; binding still requires the user grant (the CVE class is about that
 * grant being obtainable without proper consent / above the lock screen).
 */
class DvmaNotificationListener : NotificationListenerService() {

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        val extras = sbn?.notification?.extras ?: return
        val title = extras.getCharSequence("android.title")?.toString() ?: ""
        val text = extras.getCharSequence("android.text")?.toString() ?: ""
        if (title.isEmpty() && text.isEmpty()) return
        val evidence = "listener read notification from ${sbn.packageName}: " +
            "title=\"$title\" text=\"$text\" (contents disclosed to a bound listener)"
        EvidenceStore.record(KEY, evidence)
        Log.w(TAG, evidence)
    }

    companion object {
        const val KEY = "notification_listener_authorization_bypass"
        private const val TAG = EvidenceStore.TAG
    }
}
