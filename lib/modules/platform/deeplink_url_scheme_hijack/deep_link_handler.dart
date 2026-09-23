/// Deep-link handler.
///
/// INTENTIONALLY VULNERABLE (CWE-939 / CWE-20): the custom `dvma://` scheme is
/// unverified (any app can register it too) and its parameters are trusted
/// as-is. A crafted link can drive authenticated actions or open arbitrary
/// redirect targets. A safe handler uses verified App Links / Universal Links
/// and validates every parameter.
///
/// Pure Dart so a unit test can assert a hostile link is honored.
class DeepLinkHandler {
  DeepLinkHandler._();

  /// The claimable custom scheme (not verified, CWE-939).
  static const String scheme = 'dvma';

  /// Parses + "routes" a deep link, trusting all params.
  static Map<String, String> handle(String link) {
    final uri = Uri.parse(link);
    final result = <String, String>{'host': uri.host, 'path': uri.path};
    // Trusts params blindly: e.g. reset-password token, open-redirect target,
    // or an "authenticated=true" flag supplied by the caller.
    uri.queryParameters.forEach((k, v) => result['param:$k'] = v);
    if (uri.host == 'reset') {
      result['action'] =
          'PASSWORD RESET honored for token '
          '"${uri.queryParameters['token'] ?? ''}" (no origin check)';
    } else if (uri.queryParameters.containsKey('next')) {
      result['action'] = 'OPEN REDIRECT to ${uri.queryParameters['next']}';
    }
    return result;
  }

  static const String hostileSample =
      'dvma://reset?token=attacker_chosen&next=https://evil.example';
}
