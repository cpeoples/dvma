/// App Group shared-container privilege amplification helper.
///
/// INTENTIONALLY VULNERABLE (CWE-200 / CWE-732 / CWE-668): the main app stores
/// secrets (an auth token, API keys) in an Apple App Group shared container /
/// shared UserDefaults keyed by an app-group id (`group.com.example.dvma`).
/// every member of that app group - including a less-trusted keyboard or share
/// extension - can read and write every item with no per-item access control.
/// A low-trust extension therefore reads the auth token it should never see,
/// or tampers with a value the main app trusts. The finding is not "an App
/// Group is used"; it is that sensitive items are over-shared across the whole
/// group with no per-item scoping (OWASP MASTG-BEST-0068).
///
/// This is an offline + deterministic SIMULATION. [AppGroupContainer] models
/// the shared store; [GroupReader]s carry a [TrustLevel]. The vulnerable
/// [read]/[write] ignore trust and item sensitivity; the secure
/// [readSafe]/[writeSafe] enforce per-item access scoping so sensitive items
/// are only served to / mutated by entitled (main-app) readers.
library;

/// How much the app group treats a given member.
enum TrustLevel {
  /// The first-party main app: the legitimate owner of the secrets.
  mainApp,

  /// A first-party share extension: semi-trusted, no need for the auth token.
  shareExtension,

  /// A low-trust custom keyboard extension: must never see secrets.
  lowTrustKeyboardExtension,
}

/// A member of the app group that reads/writes the shared container.
class GroupReader {
  const GroupReader({required this.id, required this.trust});

  /// A human-facing identifier (e.g. "keyboard extension").
  final String id;

  /// The reader's trust level, used only by the SECURE path.
  final TrustLevel trust;
}

/// An item stored in the shared container.
class ContainerItem {
  const ContainerItem({
    required this.key,
    required this.value,
    required this.sensitive,
  });

  final String key;
  final String value;

  /// True for secrets that must be scoped to the main app only.
  final bool sensitive;
}

/// The outcome of a read (or tamper-write) against the shared container.
class ContainerAccessResult {
  const ContainerAccessResult({
    required this.reader,
    required this.key,
    required this.read,
    required this.value,
    required this.sensitiveExposed,
    this.wrote = false,
    this.denyReason,
  });

  /// The member that attempted the access.
  final GroupReader reader;

  /// The key that was requested.
  final String key;

  /// True when a value was returned to the reader.
  final bool read;

  /// The value returned (empty when denied).
  final String value;

  /// True when a SENSITIVE item was served to / mutated by a non-entitled
  /// reader - the hit.
  final bool sensitiveExposed;

  /// True when a write/tamper was applied.
  final bool wrote;

  /// Why the secure path refused (null on the vulnerable path).
  final String? denyReason;
}

class AppGroupContainer {
  AppGroupContainer();

  /// The app-group id all members share.
  static const String appGroupId = 'group.com.example.dvma';

  /// Sensitive key the main app persists - the auth token.
  static const String authTokenKey = 'auth.session.token';

  /// A non-sensitive shared key (e.g. UI theme) legitimately group-wide.
  static const String themeKey = 'ui.theme';

  /// A realistic auth token value written by the main app.
  static const String authTokenValue = 'eyJhbGciOiJIUzI1NiJ9.sess-9F2A-7C41';

  /// The low-trust keyboard extension attacker in this scenario.
  static const GroupReader keyboardExtension = GroupReader(
    id: 'keyboard extension',
    trust: TrustLevel.lowTrustKeyboardExtension,
  );

  /// The first-party main app (entitled to the secrets).
  static const GroupReader mainApp = GroupReader(
    id: 'main app',
    trust: TrustLevel.mainApp,
  );

  /// Backing store, keyed by item key.
  final Map<String, ContainerItem> _store = <String, ContainerItem>{};

  /// Seed the container as the main app would on launch: a sensitive auth
  /// token plus a benign shared theme value.
  void seedAsMainApp() {
    _store[authTokenKey] = const ContainerItem(
      key: authTokenKey,
      value: authTokenValue,
      sensitive: true,
    );
    _store[themeKey] = const ContainerItem(
      key: themeKey,
      value: 'dark',
      sensitive: false,
    );
  }

  /// VULN: return ANY item to ANY group member. Membership in the app group is
  /// treated as sufficient authorization; there is no per-item ACL, so a
  /// low-trust keyboard extension reads the main app's auth token.
  ContainerAccessResult read(GroupReader reader, String key) {
    final item = _store[key];
    if (item == null) {
      return ContainerAccessResult(
        reader: reader,
        key: key,
        read: false,
        value: '',
        sensitiveExposed: false,
      );
    }
    return ContainerAccessResult(
      reader: reader,
      key: key,
      read: true,
      value: item.value,
      // Any non-main-app reader receiving a sensitive item is the leak.
      sensitiveExposed: item.sensitive && reader.trust != TrustLevel.mainApp,
    );
  }

  /// VULN: allow ANY group member to overwrite ANY item. A low-trust extension
  /// tampers with a value the main app later trusts (integrity loss).
  ContainerAccessResult write(GroupReader reader, String key, String value) {
    final existing = _store[key];
    final sensitive = existing?.sensitive ?? false;
    _store[key] = ContainerItem(key: key, value: value, sensitive: sensitive);
    return ContainerAccessResult(
      reader: reader,
      key: key,
      read: false,
      value: value,
      wrote: true,
      sensitiveExposed: sensitive && reader.trust != TrustLevel.mainApp,
    );
  }

  /// SECURE contrast: enforce per-item access scoping. Sensitive items are
  /// only served to entitled (main-app) readers; a low-trust extension is
  /// denied. Non-sensitive items remain shareable group-wide by design.
  ContainerAccessResult readSafe(GroupReader reader, String key) {
    final item = _store[key];
    if (item == null) {
      return ContainerAccessResult(
        reader: reader,
        key: key,
        read: false,
        value: '',
        sensitiveExposed: false,
        denyReason: 'no such item',
      );
    }
    if (item.sensitive && reader.trust != TrustLevel.mainApp) {
      return ContainerAccessResult(
        reader: reader,
        key: key,
        read: false,
        value: '',
        sensitiveExposed: false,
        denyReason:
            'reader "${reader.id}" not entitled to sensitive item "$key"',
      );
    }
    return ContainerAccessResult(
      reader: reader,
      key: key,
      read: true,
      value: item.value,
      sensitiveExposed: false,
    );
  }

  /// SECURE contrast: only entitled readers may mutate sensitive items, so a
  /// low-trust extension cannot tamper with values the main app trusts.
  ContainerAccessResult writeSafe(
    GroupReader reader,
    String key,
    String value,
  ) {
    final existing = _store[key];
    final sensitive = existing?.sensitive ?? false;
    if (sensitive && reader.trust != TrustLevel.mainApp) {
      return ContainerAccessResult(
        reader: reader,
        key: key,
        read: false,
        value: existing?.value ?? '',
        wrote: false,
        sensitiveExposed: false,
        denyReason:
            'reader "${reader.id}" not entitled to write sensitive item "$key"',
      );
    }
    _store[key] = ContainerItem(key: key, value: value, sensitive: sensitive);
    return ContainerAccessResult(
      reader: reader,
      key: key,
      read: false,
      value: value,
      wrote: true,
      sensitiveExposed: false,
    );
  }
}
