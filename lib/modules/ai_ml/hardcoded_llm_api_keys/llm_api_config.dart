/// Hardcoded LLM API-key holder.
///
/// INTENTIONALLY VULNERABLE (CWE-798): a cloud-LLM API key is shipped as a
/// string constant in the app binary, extractable with `strings`/jadx. Anyone
/// who pulls the APK gets a working key and can rack up charges on the owner's
/// account. Keys must live server-side behind a proxy, never in the client.
class LlmApiConfig {
  LlmApiConfig._();

  /// Hardcoded provider API key (fake, but shaped like a real one).
  static const String apiKey =
      'sk-DVMA00hardcodedTESTkeyAA11bb22cc33dd44ee55ff6677';

  static const String endpoint = 'https://api.openai-like.example/v1/chat';

  /// The Authorization header the client sends, key travels in every request.
  static String authorizationHeader() => 'Bearer $apiKey';

  /// What `strings` would surface from the binary.
  static String extractableString() => 'API_KEY=$apiKey';
}
