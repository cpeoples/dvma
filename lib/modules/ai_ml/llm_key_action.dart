import 'package:flutter/material.dart';

import '../../core/config/dvma_env.dart';
import '../../core/test_ids.dart';
import 'mock_llm.dart';

/// App-bar action for the AI modules: lets a user paste their own OpenRouter
/// key at runtime so the demos hit a real hosted model instead of the keyless
/// Pollinations fallback. The key is held in memory only (via
/// [LlmConfig.setLive]) and never written to disk; clearing reverts to whatever
/// [LlmConfig.fromEnvironment] selected.
class LlmKeyAction extends StatelessWidget {
  const LlmKeyAction({super.key});

  Future<void> _edit(BuildContext context) async {
    final controller = TextEditingController();
    final action = await showDialog<_KeyAction>(
      context: context,
      builder: (context) => AlertDialog(
        scrollable: true,
        title: const Text('OpenRouter key'),
        // Width-bounded; scrollable:true lets the whole dialog scroll under the
        // software keyboard so the body never overflows ("BOTTOM OVERFLOWED")
        // and the action buttons stay reachable.
        content: SizedBox(
          width: 320,
          child: _KeyDialogBody(controller: controller),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, _KeyAction.clear),
            child: const Text('Use default'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context, _KeyAction.cancel),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, _KeyAction.save),
            child: const Text('Use this key'),
          ),
        ],
      ),
    );
    if (!context.mounted) return;
    switch (action) {
      case _KeyAction.save:
        final key = controller.text.trim();
        if (key.isEmpty) return;
        LlmConfig.setLive(
          OpenRouterLlm(
            apiKey: key,
            model: DvmaEnv.llm.openRouter.model,
            endpoint: Uri.parse(DvmaEnv.llm.openRouter.endpoint),
          ),
        );
        _toast(context, 'Using your OpenRouter key for AI modules.');
      case _KeyAction.clear:
        // Revert to whatever the build-time environment configured.
        LlmConfig.fromEnvironment();
        _toast(context, 'Reverted to the default AI backend.');
      case _KeyAction.cancel:
      case null:
        break;
    }
  }

  void _toast(BuildContext context, String message) {
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(message)));
  }

  @override
  Widget build(BuildContext context) {
    return testTapId(
      DvmaTestIds.demoAction('llm_key'),
      IconButton(
        tooltip: 'Set your OpenRouter key',
        icon: const Icon(Icons.key),
        onPressed: () => _edit(context),
      ),
    );
  }
}

enum _KeyAction { save, clear, cancel }

/// The editable body of the key dialog: an obscured field with a show/hide
/// toggle and a live character count, so a user can reveal what they pasted to
/// catch a double-paste or stray whitespace before committing the key.
class _KeyDialogBody extends StatefulWidget {
  const _KeyDialogBody({required this.controller});

  final TextEditingController controller;

  @override
  State<_KeyDialogBody> createState() => _KeyDialogBodyState();
}

class _KeyDialogBodyState extends State<_KeyDialogBody> {
  bool _obscure = true;

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Paste an OpenRouter key to run the AI modules against a real '
          'hosted model. Held in memory only - it clears when the app '
          'restarts and is never stored on the device.',
        ),
        const SizedBox(height: 12),
        TextField(
          controller: widget.controller,
          autofocus: true,
          obscureText: _obscure,
          decoration: InputDecoration(
            labelText: 'sk-or-...',
            border: const OutlineInputBorder(),
            // Reveal toggle so you can confirm exactly what was pasted.
            suffixIcon: IconButton(
              tooltip: _obscure ? 'Show key' : 'Hide key',
              icon: Icon(_obscure ? Icons.visibility : Icons.visibility_off),
              onPressed: () => setState(() => _obscure = !_obscure),
            ),
          ),
        ),
        const SizedBox(height: 4),
        // A live length readout makes an accidental double-paste obvious even
        // while the key is still obscured.
        ValueListenableBuilder<TextEditingValue>(
          valueListenable: widget.controller,
          builder: (context, value, _) {
            final n = value.text.trim().length;
            return Text(
              n == 0 ? 'No key entered' : '$n characters',
              style: Theme.of(context).textTheme.bodySmall,
            );
          },
        ),
      ],
    );
  }
}
