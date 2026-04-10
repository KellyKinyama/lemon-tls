import 'dart:typed_data';

import 'package:hex/hex.dart';

import '../buffer.dart';
import 'tls_messages.dart';

class ClientHello extends TlsHandshakeMessage {
  final Uint8List random;
  final List<int> cipherSuites;
  final List<TlsExtension> extensions;
  ClientHello({
    required this.random,
    required this.cipherSuites,
    required this.extensions,
  }) : super(0x01);

  @override
  String toString() {
    final suites = cipherSuites
        .map((s) => cipherSuitesMap[s] ?? 'Unknown (0x${s.toRadixString(16)})')
        .join(',\n    ');
    return '''
✅ Parsed ClientHello (Type 0x01):
- Random: ${HEX.encode(random.sublist(0, 8))}...
- Cipher Suites:
    $suites
- Extensions Count: ${extensions.length}''';
  }
}

// #############################################################################
// ## SECTION 3: PARSER LOGIC
// #############################################################################

List<TlsExtension> parseExtensions(QuicBuffer buffer) {
  if (buffer.remaining < 2) return [];
  final totalExtLen = buffer.pullUint16();
  final extensions = <TlsExtension>[];
  int extensionsRead = 0;
  while (extensionsRead < totalExtLen && buffer.remaining > 0) {
    final extType = buffer.pullUint16();
    final extLen = buffer.pullUint16();
    final extData = buffer.pullBytes(extLen);
    extensions.add(TlsExtension(extType, extData));
    extensionsRead += 4 + extLen;
  }
  return extensions;
}

ClientHello parseClientHelloBody(QuicBuffer buffer) {
  buffer.pullUint16(); // Skip legacy_version
  final random = buffer.pullBytes(32);
  buffer.pullVector(1); // Skip legacy_session_id

  final cipherSuitesBytes = buffer.pullVector(2);
  final cipherSuites = <int>[];
  final csBuffer = QuicBuffer(data: cipherSuitesBytes);
  while (!csBuffer.eof) {
    cipherSuites.add(csBuffer.pullUint16());
  }

  buffer.pullVector(1); // Skip legacy_compression_methods
  final extensions = parseExtensions(buffer);

  return ClientHello(
    random: random,
    cipherSuites: cipherSuites,
    extensions: extensions,
  );
}
