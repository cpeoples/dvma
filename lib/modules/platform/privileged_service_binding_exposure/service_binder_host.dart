/// Privileged Service Binding Exposure helper.
///
/// INTENTIONALLY VULNERABLE (CWE-284 / CWE-749 / CWE-862, Android service IPC
/// MASTG-KNOW-0133): an exported/bindable Service exposes a privileged Binder
/// interface (AIDL / Messenger) that any app can `bindService()` to and call
/// with no caller-identity or permission check. An untrusted client can then
/// invoke privileged operations (read a secret, elevate its role) or read state
/// another client established. The BINDING model is the security boundary: the
/// service must verify the caller before handing out a usable binder.
///
/// This is an offline + deterministic SIMULATION. [ServiceBinderHost] models a
/// service holding a secret and a per-connection role. The vulnerable [bind]
/// hands any caller a live [PrivilegedBinder] with no check, so an untrusted
/// client reads the secret and elevates its role, and state set by one client
/// is visible to another. The secure [bindSafe] verifies the caller against a
/// signature-level allowlist before returning a usable binder.
library;

/// A live connection to the service returned by a successful bind. Calling a
/// privileged method routes back into the host.
class PrivilegedBinder {
  PrivilegedBinder._(this._host, this.callerPackage, this._enforceCaller);

  final ServiceBinderHost _host;

  /// The package that established this connection.
  final String callerPackage;

  /// Whether this binder re-checks the caller on each privileged call.
  final bool _enforceCaller;

  /// Read the service's protected secret.
  ServiceCallResult readSecret() =>
      _host.handleReadSecret(callerPackage, _enforceCaller);

  /// Elevate the caller's role to admin within the shared service state.
  ServiceCallResult elevateRole() =>
      _host.handleElevateRole(callerPackage, _enforceCaller);
}

/// The outcome of a bindService() attempt.
class ServiceBindResult {
  const ServiceBindResult({
    required this.callerPackage,
    required this.bound,
    required this.callerChecked,
    this.binder,
    this.denyReason,
  });

  final String callerPackage;

  /// Whether a usable binder was returned to the caller.
  final bool bound;

  /// Whether the service verified the caller identity before binding.
  final bool callerChecked;

  /// The live connection, when [bound] is true.
  final PrivilegedBinder? binder;

  /// Why the secure path refused to bind.
  final String? denyReason;
}

/// The outcome of invoking a privileged method over a binder.
class ServiceCallResult {
  const ServiceCallResult({
    required this.callerPackage,
    required this.method,
    required this.privilegedCallSucceeded,
    required this.value,
    required this.callerChecked,
    this.denyReason,
  });

  final String callerPackage;

  /// The privileged method invoked.
  final String method;

  /// Whether the privileged operation actually executed for the caller.
  final bool privilegedCallSucceeded;

  /// The value the call returned (e.g. the secret, or the new role).
  final String value;

  /// Whether the service verified the caller before performing the operation.
  final bool callerChecked;

  /// Why the secure path denied the call.
  final String? denyReason;
}

class ServiceBinderHost {
  /// The service's protected secret, meant only for trusted clients.
  static const String secret = 'svc-master-key:4F91-A2C7-DE30';

  /// The app's own trusted, same-signature client.
  static const String trustedPackage = 'com.dvma.app';

  /// An untrusted third-party app that binds to the exported service.
  static const String attackerPackage = 'com.evil.binder';

  /// Callers permitted (same signature) to obtain a usable binder.
  static const Set<String> allowedCallers = {trustedPackage};

  /// Shared service state: roles established by connected clients. This is what
  /// lets state set by client A leak to client B.
  final Map<String, String> _roles = <String, String>{};

  String roleOf(String callerPackage) => _roles[callerPackage] ?? 'guest';

  /// VULN: return a usable binder to ANY caller without checking identity, the
  /// result of exporting the service (`android:exported="true"`) with no
  /// `android:permission` and no `checkCallingPermission()` in `onBind`.
  ServiceBindResult bind(String callerPackage) {
    return ServiceBindResult(
      callerPackage: callerPackage,
      bound: true,
      callerChecked: false,
      binder: PrivilegedBinder._(this, callerPackage, false),
    );
  }

  /// SECURE contrast: verify the caller against a signature-level allowlist
  /// (e.g. via `getPackageManager().checkSignatures` / a signature permission)
  /// before returning a usable binder, refusing untrusted callers.
  ServiceBindResult bindSafe(String callerPackage) {
    if (!allowedCallers.contains(callerPackage)) {
      return ServiceBindResult(
        callerPackage: callerPackage,
        bound: false,
        callerChecked: true,
        denyReason:
            'caller $callerPackage failed signature check - bind '
            'refused',
      );
    }
    return ServiceBindResult(
      callerPackage: callerPackage,
      bound: true,
      callerChecked: true,
      binder: PrivilegedBinder._(this, callerPackage, true),
    );
  }

  /// Handle a readSecret() call. When [enforceCaller] is set, re-check the
  /// caller identity on the transaction (defense in depth).
  ServiceCallResult handleReadSecret(String callerPackage, bool enforceCaller) {
    if (enforceCaller && !allowedCallers.contains(callerPackage)) {
      return ServiceCallResult(
        callerPackage: callerPackage,
        method: 'readSecret',
        privilegedCallSucceeded: false,
        value: '(denied)',
        callerChecked: true,
        denyReason: 'caller $callerPackage not permitted to read secret',
      );
    }
    return ServiceCallResult(
      callerPackage: callerPackage,
      method: 'readSecret',
      privilegedCallSucceeded: true,
      value: secret,
      callerChecked: enforceCaller,
    );
  }

  /// Handle an elevateRole() call. Mutates shared service state so the effect
  /// is observable by other connections.
  ServiceCallResult handleElevateRole(
    String callerPackage,
    bool enforceCaller,
  ) {
    if (enforceCaller && !allowedCallers.contains(callerPackage)) {
      return ServiceCallResult(
        callerPackage: callerPackage,
        method: 'elevateRole',
        privilegedCallSucceeded: false,
        value: roleOf(callerPackage),
        callerChecked: true,
        denyReason: 'caller $callerPackage not permitted to elevate role',
      );
    }
    _roles[callerPackage] = 'admin';
    return ServiceCallResult(
      callerPackage: callerPackage,
      method: 'elevateRole',
      privilegedCallSucceeded: true,
      value: 'admin',
      callerChecked: enforceCaller,
    );
  }
}
