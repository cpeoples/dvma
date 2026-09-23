/// Deep Link Authentication Bypass helper.
///
/// INTENTIONALLY VULNERABLE (CWE-288 / CWE-306): a deep link routes directly to
/// an authenticated screen/function, skipping the app-lock / login gate that
/// the normal in-app navigation path enforces. Because the deep-link router
/// honors the requested target WITHOUT checking whether the user is
/// authenticated, an attacker-triggered link (e.g. `dvma://wallet`) opens a
/// sensitive screen and returns its content while the user is logged out (the
/// Groww CVE-2026-12065 class).
///
/// This is an offline + deterministic simulation of the real mechanism: routes
/// and their `requiresAuth` flags are an in-memory table and "navigating"
/// returns the resulting screen + content string rather than pushing a real
/// route. A test can assert [navigate] returns the wallet content while logged
/// out, and [navigateSafe] redirects to login.
class DeeplinkAuthRouter {
  DeeplinkAuthRouter({this.isAuthenticated = false});

  /// Whether an app-lock / login gate has been satisfied for this session.
  bool isAuthenticated;

  /// Route table: path -> (requiresAuth, sensitive content served).
  static const Map<String, _Route> _routes = {
    '/wallet': _Route(
      requiresAuth: true,
      content: 'WALLET BALANCE: \$8,412.55',
    ),
    '/transfer': _Route(
      requiresAuth: true,
      content: 'TRANSFER FUNDS: from acct 0042 (limit \$50,000)',
    ),
    '/home': _Route(requiresAuth: false, content: 'Public landing page'),
    '/login': _Route(requiresAuth: false, content: 'Login screen'),
  };

  /// Maps a `dvma://<name>` deep link to a route path.
  static String? _pathFor(String deepLink) {
    final uri = Uri.tryParse(deepLink);
    if (uri == null) return null;
    // Support both dvma://wallet and dvma://open/wallet-style links.
    final name = uri.host.isNotEmpty
        ? uri.host
        : (uri.pathSegments.isNotEmpty ? uri.pathSegments.last : '');
    if (name.isEmpty) return null;
    return '/$name';
  }

  /// VULN: follow the deep link's target even for auth-required routes WITHOUT
  /// checking [isAuthenticated]. The sensitive screen + its content is returned
  /// regardless of login state.
  static NavResult navigate(DeeplinkAuthRouter router, String deepLink) {
    final path = _pathFor(deepLink);
    final route = path == null ? null : _routes[path];
    if (route == null) {
      return const NavResult(
        screen: null,
        content: null,
        redirectedToLogin: false,
        reason: 'unknown route',
      );
    }
    // No auth gate: whatever the link points at is opened.
    return NavResult(
      screen: path,
      content: route.content,
      redirectedToLogin: false,
      reason: route.requiresAuth
          ? 'opened protected route without auth check'
          : 'opened public route',
    );
  }

  /// SECURE contrast: enforce the auth gate. Protected routes redirect to
  /// login (returning no sensitive content) unless [isAuthenticated] is true.
  static NavResult navigateSafe(DeeplinkAuthRouter router, String deepLink) {
    final path = _pathFor(deepLink);
    final route = path == null ? null : _routes[path];
    if (route == null) {
      return const NavResult(
        screen: null,
        content: null,
        redirectedToLogin: false,
        reason: 'unknown route',
      );
    }
    if (route.requiresAuth && !router.isAuthenticated) {
      return const NavResult(
        screen: '/login',
        content: null,
        redirectedToLogin: true,
        reason: 'protected route requires auth - redirected to login',
      );
    }
    return NavResult(
      screen: path,
      content: route.content,
      redirectedToLogin: false,
      reason: 'authorized',
    );
  }
}

class _Route {
  const _Route({required this.requiresAuth, required this.content});
  final bool requiresAuth;
  final String content;
}

/// Outcome of a simulated deep-link navigation.
class NavResult {
  const NavResult({
    required this.screen,
    required this.content,
    required this.redirectedToLogin,
    required this.reason,
  });

  /// The screen/route that was opened, or null when the route is unknown.
  final String? screen;

  /// The sensitive content served by the opened screen, or null.
  final String? content;

  /// Whether the secure router redirected the caller to the login gate.
  final bool redirectedToLogin;

  /// Human-readable explanation of the outcome.
  final String reason;
}
