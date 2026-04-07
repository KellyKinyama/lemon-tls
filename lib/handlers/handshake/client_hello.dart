import 'dart:typed_data';

import 'package:lemon_tls/handlers/extensions/extensions.dart';

import '../message_types.dart';

class ClientHello extends HandShakeMessageType {
  @override
  // Uint8List body;
  TLS_MESSAGE_TYPE message;
  int legacy_version;
  TLS_VERSION version_hint;
  Uint8List random;
  Uint8List session_id;
  Uint8List body;
  List<int> cipher_suites;
  List<int> legacy_compression;
  List<TlsExtension> extensions;

  ClientHello({
    required this.message,
    required this.legacy_version,
    required this.version_hint,
    required this.random,
    required this.session_id,
    required this.cipher_suites,
    required this.legacy_compression,
    required this.extensions,
    required this.body,
  }) : super(message, body);
}
