/// Single source of truth for DVMA's build-time configuration.
///
/// Every `--dart-define` the app understands is read *here* and nowhere else,
/// so there is one place to see and override the app's identity, module gating,
/// network endpoints, and live-LLM backends. Populate these from a flavor file:
///
/// ```sh
/// flutter run --dart-define-from-file=config/flavors/dev.json
/// ```
///
/// The values are compile-time constants (`String.fromEnvironment` requires a
/// `const` context), grouped into cohesive records so callers consume a typed
/// surface, [AppConfig.fromEnvironment] builds the runtime config object from
/// [app]/[gating]/[network], and [LlmConfig.fromEnvironment] wires the live
/// backend chain from [llm]. No other file should call `*.fromEnvironment`.
library;

/// App identity: what this build calls itself and where it thinks it runs.
typedef AppIdentity = ({String flavor, String appId, String platformOverride});

/// Module-gating knobs: which categories/modules are live and how loud.
typedef ModuleGating = ({
  bool enableAll,
  bool verboseLogging,
  String enabledCategories,
  String disabledVulns,
});

/// Endpoints the *real* network modules send genuine traffic to (a local
/// capture listener by default, so nothing leaves the trainee's network).
typedef NetworkEndpoints = ({
  String captureBase,
  String llmApiBase,
  String insecureUpdateUrl,
});

/// One OpenAI-compatible chat backend: where to POST, which model, and the
/// bearer key (empty when the endpoint is keyless).
typedef LlmBackend = ({String endpoint, String model, String key});

/// Live-LLM wiring for the AI modules: the master switch plus each backend in
/// the fallback chain (custom endpoint -> OpenRouter -> keyless Pollinations).
typedef LlmSettings = ({
  bool liveEnabled,
  LlmBackend custom,
  LlmBackend openRouter,
  String pollinationsEndpoint,
});

/// The compile-time configuration surface. Grouped getters return typed records
/// so no caller has to know a define's raw name.
abstract final class DvmaEnv {
  // App identity

  static const AppIdentity app = (
    flavor: String.fromEnvironment('DVMA_FLAVOR', defaultValue: 'dev'),
    // The single source of truth is the Android `applicationId`
    // (android/app/build.gradle.kts); flavor JSON forwards it so Dart and
    // native agree without hardcoding.
    appId: String.fromEnvironment('DVMA_APP_ID', defaultValue: 'com.dvma'),
    // Optional override of the detected platform (`android`/`ios`), used to
    // exercise the other platform's catalog in tests.
    platformOverride: String.fromEnvironment('DVMA_PLATFORM', defaultValue: ''),
  );

  // Module gating

  static const ModuleGating gating = (
    enableAll: bool.fromEnvironment('DVMA_ENABLE_ALL', defaultValue: true),
    verboseLogging: bool.fromEnvironment(
      'DVMA_VERBOSE_LOGGING',
      defaultValue: true,
    ),
    enabledCategories: String.fromEnvironment(
      'DVMA_ENABLED_CATEGORIES',
      defaultValue:
          'storage,crypto,auth,network,platform,code_quality,'
          'resilience,supply_chain,privacy,input_validation,ai_ml,agentic,'
          'ai_mobile,native_bridge,system_provider',
    ),
    disabledVulns: String.fromEnvironment(
      'DVMA_DISABLED_VULNS',
      defaultValue: '',
    ),
  );

  // Network endpoints
  // `10.0.2.2` is the host loopback as seen from the Android emulator, so real
  // packets hit the trainee's own capture listener. Override for a physical
  // device with `--dart-define=DVMA_CAPTURE_BASE=http://<host-ip>:8080`.

  static const NetworkEndpoints network = (
    captureBase: String.fromEnvironment(
      'DVMA_CAPTURE_BASE',
      defaultValue: 'http://10.0.2.2:8080',
    ),
    llmApiBase: String.fromEnvironment(
      'DVMA_LLM_API_BASE',
      defaultValue: 'http://10.0.2.2:8080',
    ),
    insecureUpdateUrl: String.fromEnvironment(
      'DVMA_INSECURE_UPDATE_URL',
      defaultValue: 'http://10.0.2.2:8080/model/update',
    ),
  );

  // Live-LLM backends
  // The AI modules make a real model call out of the box. The default backend
  // is the KEYLESS Pollinations endpoint, so no credential is required or
  // committed. To use OpenRouter (better at exhibiting the prompt-injection /
  // system-prompt-leak behavior), pass a disposable free-tier key via
  // --dart-define=DVMA_OPENROUTER_KEY=sk-or-...
  // A key living in source is itself a DVMA anti-pattern (see the
  // hardcoded_llm_api_keys module), so we deliberately do not ship one. Point
  // `DVMA_LLM_ENDPOINT` at a local Ollama/LM Studio to run fully offline.

  static const LlmSettings llm = (
    liveEnabled: bool.fromEnvironment('DVMA_LLM_LIVE', defaultValue: true),
    custom: (
      endpoint: String.fromEnvironment('DVMA_LLM_ENDPOINT', defaultValue: ''),
      model: String.fromEnvironment('DVMA_LLM_MODEL', defaultValue: ''),
      key: String.fromEnvironment('DVMA_LLM_KEY', defaultValue: ''),
    ),
    openRouter: (
      endpoint: 'https://openrouter.ai/api/v1/chat/completions',
      // Small free model that reliably exhibits the prompt-injection /
      // system-prompt-leak behavior the demos need (frontier models refuse).
      model: String.fromEnvironment(
        'DVMA_OPENROUTER_MODEL',
        defaultValue: 'liquid/lfm-2.5-2.6b:free',
      ),
      // Empty by default: OpenRouter is only used when a key is supplied at
      // build time; otherwise we fall through to the keyless Pollinations
      // endpoint below. No credential is committed to source.
      key: String.fromEnvironment('DVMA_OPENROUTER_KEY', defaultValue: ''),
    ),
    pollinationsEndpoint: 'https://text.pollinations.ai/openai',
  );
}
