package com.dvma.attacker

/**
 * Single source of truth (attacker side) for the DVMA app it targets.
 *
 * FOR AUTHORIZED SECURITY-TRAINING USE ONLY.
 *
 * DVMA's own package is authored once in `config/app.json` (the repo-wide
 * single source of truth). A separate app cannot read another app's config at
 * runtime, so the attacker mirrors that value here in ONE place - kept in sync
 * automatically by `dart run tool/sync_app_id.dart` (do not edit [PKG] by
 * hand; edit config/app.json and re-run the sync tool).
 *
 * These action/permission names are the public IPC surface DVMA exposes; they
 * are derived from [PKG] exactly as DVMA derives them from
 * `BuildConfig.APPLICATION_ID`, so the two apps agree by construction.
 */
object Dvma {
    /** DVMA's applicationId - synced from config/app.json by tool/sync_app_id.dart. */
    const val PKG = "com.dvma"

    /** Unprotected OTP broadcast action DVMA fires (cross_app_otp_credential_leak). */
    const val ACTION_OTP_ISSUED = "$PKG.action.OTP_ISSUED"

    /** Signature-level permission gating DVMA's secure OTP delivery path. */
    const val PERMISSION_RECEIVE_OTP = "$PKG.permission.RECEIVE_OTP"

    // Broadcast IPC actions. Receive-side actions are ones DVMA's exported
    // receivers accept (the attacker sends them); send-side actions are ones
    // DVMA emits (the attacker receives/reorders them).
    const val ACTION_LOCATION_UPDATE = "$PKG.action.LOCATION_UPDATE"   // attacker sends
    const val ACTION_APPLY_PROMO = "$PKG.action.APPLY_PROMO"           // attacker sends
    const val ACTION_SHARE_SESSION = "$PKG.action.SHARE_SESSION"       // attacker receives
    const val ACTION_ENTITLEMENT_CHECK = "$PKG.action.ENTITLEMENT_CHECK" // attacker reorders
    const val ACTION_ROLE_DELEGATE = "$PKG.action.ROLE_DELEGATE"       // attacker receives

    // Exported components the attacker starts directly (class names, not actions).
    const val ADMIN_ACTIVITY = "$PKG.AdminActivity" // exported_android_components
    const val URL_DISPATCH_ACTIVITY = "$PKG.UrlDispatchActivity" // exported_component_arbitrary_url_activity
    const val STATE_CONTROL_ACTIVITY = "$PKG.StateControlActivity" // exported_component_state_manipulation
    const val DEPUTY_ACTIVITY = "$PKG.DeputyActivity" // confused_deputy_intent_validation
    const val PROXY_ACTIVITY = "$PKG.ProxyActivity" // intent_redirection
    const val LAUNCHER_ACTIVITY = "$PKG.LauncherActivity" // intent_arg_injection_rce
    const val ADMIN_ALIAS = "$PKG.AdminAlias" // activity_alias_exposure
    const val WEBVIEW_ACTIVITY = "$PKG.WebViewActivity" // cross_app_scripting
    const val INTERNAL_ADMIN_ACTIVITY = "$PKG.InternalAdminActivity" // intent_redirection target
    const val PRIVILEGED_SERVICE = "$PKG.PrivilegedService" // privileged_service_binding_exposure
    const val HIJACK_TARGET_ACTIVITY = "$PKG.HijackTargetActivity" // activity_task_stack_hijacking

    /** Privileged action the confused-deputy Activity checks (only the string). */
    const val ACTION_WRITE_SECURE_SETTING = "$PKG.action.WRITE_SECURE_SETTING"

    /** First-hop trigger for android_capability_composition_chain. */
    const val ACTION_CHAIN_TRIGGER = "$PKG.action.CHAIN_TRIGGER"
    const val CHAIN_ENTRY_RECEIVER = "$PKG.ChainEntryReceiver"
}
