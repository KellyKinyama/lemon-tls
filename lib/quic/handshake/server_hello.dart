import 'dart:typed_data';
import 'dart:math' as math;

import '../handshake_headers.dart';
// import '../aead.dart';

// QUIC TLS extension types
const int EXT_KEY_SHARE = 0x0033;
const int EXT_SUPPORTED_VERSIONS = 0x002B;

Uint8List _u8(int v) => Uint8List.fromList([v & 0xFF]);

Uint8List _u16be(int v) {
  final out = Uint8List(2);
  ByteData.sublistView(out).setUint16(0, v, Endian.big);
  return out;
}

Uint8List _concat(List<Uint8List> parts) {
  final total = parts.fold<int>(0, (n, p) => n + p.length);
  final out = Uint8List(total);
  var off = 0;
  for (final p in parts) {
    out.setRange(off, off + p.length, p);
    off += p.length;
  }
  return out;
}

Uint8List _randomBytes(int n) {
  final rnd = math.Random.secure();
  return Uint8List.fromList(List.generate(n, (_) => rnd.nextInt(256)));
}

/// ======================================================================
/// ✅ Build a QUIC-compatible ServerHello (NO TLS record header)
///
/// Equivalent to your JS function:
///   build_server_hello(...)
///
/// QUIC requirements:
///  - session_id must be EMPTY
///  - legacy_version always 0x0303 (TLS 1.2)
///  - supported_versions extension = 0x0304 (TLS 1.3)
///  - key_share extension includes server key
/// ======================================================================
Uint8List buildServerHelloBytes({
  required Uint8List serverRandom,
  required Uint8List serverKeyShare, // server X25519 public key
  required int cipherSuite, // 0x1301, 0x1303 …
  required int group, // 0x001D = X25519
}) {
  // -----------------------------------------
  // KeyShare Extension
  // -----------------------------------------
  final keyShareExt = _concat([
    _u16be(EXT_KEY_SHARE),
    _u16be(4 + serverKeyShare.length),
    _u16be(group),
    _u16be(serverKeyShare.length),
    serverKeyShare,
  ]);

  // -----------------------------------------
  // SupportedVersions Extension
  // -----------------------------------------
  final supportedVersionsExt = _concat([
    _u16be(EXT_SUPPORTED_VERSIONS),
    _u16be(2),
    _u16be(0x0304), // TLS 1.3
  ]);

  final extensions = _concat([keyShareExt, supportedVersionsExt]);

  // -----------------------------------------
  // TLS 1.3 ServerHello body
  // -----------------------------------------
  final body = _concat([
    _u16be(0x0303), // legacy_version
    serverRandom,
    _u8(0), // session_id length = 0
    _u16be(cipherSuite),
    _u8(0), // compression = null
    _u16be(extensions.length),
    extensions,
  ]);

  // -----------------------------------------
  // TLS Handshake Header
  // message_type = 2 (ServerHello)
  // length = body.length (3 bytes)
  // -----------------------------------------
  final header = HandshakeHeader(messageType: 2, size: body.length).serialize();

  return Uint8List.fromList([...header, ...body]);
}
