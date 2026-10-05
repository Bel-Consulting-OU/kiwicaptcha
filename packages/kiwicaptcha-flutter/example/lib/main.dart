import 'package:flutter/material.dart';
import 'package:kiwicaptcha/kiwicaptcha.dart';

/// The four-setting quickstart: endpoint, sitekey, scope and the
/// verified-token callback.
void main() => runApp(const KiwiExampleApp());

class KiwiExampleApp extends StatelessWidget {
  const KiwiExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('KiwiCaptcha')),
        body: const LoginForm(),
      ),
    );
  }
}

class LoginForm extends StatefulWidget {
  const LoginForm({super.key});

  @override
  State<LoginForm> createState() => _LoginFormState();
}

class _LoginFormState extends State<LoginForm> {
  String? _token;
  String? _error;

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        KiwiCaptcha(
          endpoint: Uri.parse('https://api.example.com/api/kcaptcha/challenge'),
          scope: 'login',
          sitekey: null,
          onVerify: (token) => setState(() {
            _token = token;
            _error = null;
          }),
          onError: (message) => setState(() => _error = message),
          onExpire: () => setState(() => _error = 'the check expired, press Retry'),
        ),
        if (_error != null) Text(_error!, style: const TextStyle(color: Colors.red)),
        if (_token != null) Text('token ready (${_token!.length} chars)'),
      ],
    );
  }
}
