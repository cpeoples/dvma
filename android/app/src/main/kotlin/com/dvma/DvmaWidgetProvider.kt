package com.dvma

import android.appwidget.AppWidgetProvider
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * remoteviews_widget_action_injection (CWE-926 / CWE-862).
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * A genuine home-screen AppWidget component. Its RemoteViews click handler is
 * driven by a MUTABLE PendingIntent whose transfer parameters are taken from
 * (attacker-influenceable) config extras rather than being bound to a fixed
 * immutable action. When the widget tap / injected action fires, this provider
 * performs the privileged transfer with the injected parameters and no re-auth,
 * recording the effect. Declared in the manifest so the widget is real; the
 * PlatformIpc surface also exercises the same RemoteViews + mutable PI via a
 * notification for devices where a widget can't be placed under test.
 */
class DvmaWidgetProvider : AppWidgetProvider() {

    override fun onReceive(context: Context, intent: Intent) {
        super.onReceive(context, intent)
        val action = intent.action ?: return
        if (action.endsWith(".action.WIDGET_TRANSFER")) {
            val amount = intent.getStringExtra("amount") ?: "5000"
            val account = intent.getStringExtra("toAccount") ?: "acct-attacker-999"
            // VULN: the transfer parameters came from widget-config extras that
            // flowed through a mutable PendingIntent; run it with no re-auth.
            val evidence = "widget action $action fired: transfer \$$amount -> $account " +
                "with parameters injected via config extras + mutable PendingIntent (no re-auth)"
            EvidenceStore.record(KEY, evidence)
            Log.w(TAG, evidence)
        }
    }

    companion object {
        const val KEY = "remoteviews_widget_action_injection"
        private const val TAG = EvidenceStore.TAG
    }
}
