/// Cross-Profile (Work/Personal) Data & Capability Leakage helper.
///
/// INTENTIONALLY VULNERABLE (CWE-200 / CWE-668 / CWE-863, Android managed-
/// profile cross-profile leakage class): the managed (work) profile and the
/// primary (personal) profile are a security boundary, but the app crosses it
/// unsafely. A forwarded intent / URI grant / shared item moves between
/// profiles with no policy check and no required user affordance, so a WORK
/// secret (a corporate credential) lands on a PERSONAL surface (or vice-versa).
/// This is a tenant-boundary violation on top of Android's cross-profile
/// intent-forwarding machinery, distinct from ordinary intent redirection.
///
/// The secure contrast enforces a cross-profile policy: only whitelisted,
/// non-sensitive item types may cross, and only with the required user
/// affordance. Sensitive work data is denied - the crossing never happens.
///
/// Offline + deterministic: everything is modeled in-memory. A test can assert
/// the vuln path lands a work credential on a personal surface while the secure
/// path denies it with a cross-profile-policy reason.
library;

/// The two Android profiles that form the tenant boundary.
enum Profile { work, personal }

/// A category of data crossing the profile boundary. Only [publicLink] is safe
/// to forward under policy; the rest are sensitive.
enum DataKind { credential, contact, file, publicLink }

/// A data item tagged with the profile it originated in.
class DataItem {
  const DataItem({
    required this.label,
    required this.value,
    required this.kind,
    required this.origin,
    required this.sensitive,
  });

  /// A human label (e.g. "corporate VPN password").
  final String label;

  /// The item's payload (a secret for sensitive kinds).
  final String value;

  /// The category of the item.
  final DataKind kind;

  /// The profile the item belongs to (its tenant).
  final Profile origin;

  /// Whether the item is sensitive and must not cross the boundary.
  final bool sensitive;
}

/// A destination surface, itself owned by a profile (e.g. a personal share
/// sheet, a personal clipboard).
class Surface {
  const Surface({required this.name, required this.owner});

  /// A human label for the surface (e.g. "personal share sheet").
  final String name;

  /// The profile that owns this surface.
  final Profile owner;
}

/// The outcome of attempting to forward an item to a surface.
class ForwardResult {
  const ForwardResult({
    required this.item,
    required this.fromProfile,
    required this.toProfile,
    required this.surface,
    required this.crossed,
    required this.boundaryViolated,
    required this.landedValue,
    this.denyReason,
  });

  /// The item that was forwarded.
  final DataItem item;

  /// The profile the forward originated from.
  final Profile fromProfile;

  /// The profile the forward targeted.
  final Profile toProfile;

  /// The destination surface.
  final Surface surface;

  /// Whether the item actually crossed onto the destination surface.
  final bool crossed;

  /// True when sensitive data crossed the profile boundary - the hit.
  final bool boundaryViolated;

  /// The value that landed on the destination surface (empty when denied).
  final String landedValue;

  /// Why the crossing was denied (secure path).
  final String? denyReason;
}

/// Routes data items across the work/personal profile boundary.
class CrossProfileRouter {
  CrossProfileRouter();

  /// A realistic WORK credential that must never reach a personal surface.
  static const DataItem workCredential = DataItem(
    label: 'corporate VPN password',
    value: 'CORP-VPN{n3ver-cr0ss-pr0files}',
    kind: DataKind.credential,
    origin: Profile.work,
    sensitive: true,
  );

  /// A benign public link that policy allows to cross.
  static const DataItem publicLink = DataItem(
    label: 'public docs link',
    value: 'https://docs.example/handbook',
    kind: DataKind.publicLink,
    origin: Profile.work,
    sensitive: false,
  );

  /// A personal-owned destination surface (the attacker-reachable surface for
  /// a work secret).
  static const Surface personalShareSheet = Surface(
    name: 'personal share sheet',
    owner: Profile.personal,
  );

  /// Data kinds that policy permits to cross the profile boundary.
  static const Set<DataKind> _crossingAllowlist = {DataKind.publicLink};

  /// VULN: forward ANY item across profiles with no policy check and no user
  /// affordance. The item lands on the destination surface regardless of
  /// sensitivity or tenant, so a work credential leaks onto a personal
  /// surface.
  ForwardResult forward(DataItem item, Profile from, Profile to, Surface dest) {
    // No boundary check whatsoever - the item is simply placed on the surface.
    final crosses = from != to;
    return ForwardResult(
      item: item,
      fromProfile: from,
      toProfile: to,
      surface: dest,
      crossed: true,
      boundaryViolated: crosses && item.sensitive,
      landedValue: item.value,
    );
  }

  /// SECURE contrast: enforce the cross-profile policy. A crossing is only
  /// permitted for whitelisted, non-sensitive item types, and only via the
  /// required user affordance. Sensitive work data is denied, so the crossing
  /// never happens.
  ForwardResult forwardSafe(
    DataItem item,
    Profile from,
    Profile to,
    Surface dest, {
    bool userAffordanceGranted = false,
  }) {
    final crosses = from != to;
    if (crosses) {
      if (item.sensitive || !_crossingAllowlist.contains(item.kind)) {
        return ForwardResult(
          item: item,
          fromProfile: from,
          toProfile: to,
          surface: dest,
          crossed: false,
          boundaryViolated: false,
          landedValue: '',
          denyReason:
              'denied by cross-profile policy: sensitive/non-allowlisted '
              'item may not cross the work/personal profile boundary',
        );
      }
      if (!userAffordanceGranted) {
        return ForwardResult(
          item: item,
          fromProfile: from,
          toProfile: to,
          surface: dest,
          crossed: false,
          boundaryViolated: false,
          landedValue: '',
          denyReason:
              'denied by cross-profile policy: required user affordance '
              'for cross-profile forwarding was not granted',
        );
      }
    }
    // Same-profile move, or an allowlisted non-sensitive item with affordance.
    return ForwardResult(
      item: item,
      fromProfile: from,
      toProfile: to,
      surface: dest,
      crossed: true,
      boundaryViolated: false,
      landedValue: item.value,
    );
  }
}
