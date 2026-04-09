import 'dart:math' as math;
import 'dart:typed_data';

import '../byte_reader.dart';
import '../handshake_headers.dart';
import '../aead.dart';

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

//
// ==============================
// QUIC EXTENSION TYPES
// ==============================
//
const int EXT_KEY_SHARE = 0x33;
const int EXT_SUPPORTED_VERSIONS = 0x2B;

//
// ======================================================
// ✅ QUIC‑COMPATIBLE ServerHello (NO Record Header)
// ======================================================
//
class ServerHello {
  final HandshakeHeader handshakeHeader;

  final int legacyVersion; // must be 0x0303 in TLS 1.3
  final Uint8List serverRandom; // 32 bytes
  final Uint8List sessionId; // ALWAYS empty in QUIC
  final int cipherSuite; // 0x1301, 0x1302, 0x1303

  /// Raw encoded extensions (already type + length + payload)
  final Uint8List extensionsBytes;

  ServerHello({
    required this.legacyVersion,
    required this.serverRandom,
    required this.sessionId,
    required this.cipherSuite,
    required this.extensionsBytes,
  }) : handshakeHeader = HandshakeHeader(messageType: 2, size: 0);

  //
  // ======================================================
  // ✅ QUIC VERSION: Build a minimal ServerHello
  // ======================================================
  //
  static ServerHello buildForQuic({
    required Uint8List keySharePublic,
    required CipherSuite cipherSuite,
  }) {
    // Map your enum to TLS cipher suite numbers
    final cs = switch (cipherSuite) {
      CipherSuite.aes128gcm => 0x1301,
      CipherSuite.chacha20poly1305 => 0x1303,
    };

    //
    // ----- Build KeyShare extension -----
    //
    final keyShareExt = _concat([
      _u16be(EXT_KEY_SHARE),
      _u16be(4 + keySharePublic.length),
      _u16be(0x001D), // group x25519
      _u16be(keySharePublic.length),
      keySharePublic,
    ]);

    //
    // ----- Build SupportedVersions extension -----
    //
    final supportedVersionExt = _concat([
      _u16be(EXT_SUPPORTED_VERSIONS),
      _u16be(2),
      _u16be(0x0304), // TLS 1.3
    ]);

    final exts = _concat([keyShareExt, supportedVersionExt]);

    return ServerHello(
      legacyVersion: 0x0303, // always 0x0303
      serverRandom: _randomBytes(32),
      sessionId: Uint8List(0), // QUIC ALWAYS uses empty session_id
      cipherSuite: cs,
      extensionsBytes: exts,
    );
  }

  //
  // ======================================================
  // ✅ Serialize for QUIC (NO TLS Record Header)
  // ======================================================
  //
  Uint8List serialize() {
    final body = _concat([
      _u16be(legacyVersion),
      serverRandom,
      _u8(sessionId.length),
      sessionId,
      _u16be(cipherSuite),
      _u8(0), // compression_method = null
      _u16be(extensionsBytes.length),
      extensionsBytes,
    ]);

    handshakeHeader.size = body.length;

    return Uint8List.fromList([...handshakeHeader.serialize(), ...body]);
  }

  //
  // ======================================================
  // ✅ Parse QUIC ServerHello (NO TLS Record Header)
  // ======================================================
  //
  static ServerHello deserialize(ByteReader r) {
    final hh = HandshakeHeader.deserialize(r.readBytes(4));
    if (hh.messageType != 2) {
      throw StateError("Expected ServerHello handshake message");
    }

    final version = r.readUint16be();
    final random = r.readBytes(32);

    final sidLen = r.readUint8();
    final sid = r.readBytes(sidLen);

    final cipherSuite = r.readUint16be();
    final compression = r.readUint8();
    if (compression != 0) {
      throw StateError("Invalid compression method in TLS 1.3");
    }

    final extLen = r.readUint16be();
    final extBytes = r.readBytes(extLen);

    return ServerHello(
      legacyVersion: version,
      serverRandom: random,
      sessionId: sid,
      cipherSuite: cipherSuite,
      extensionsBytes: extBytes,
    );
  }
}

//
// ==============================
// ✅ ServerHello KeyShare Parser
// ==============================
//
class ServerHelloKeyShare {
  final int group;
  final Uint8List keyExchange;

  ServerHelloKeyShare({required this.group, required this.keyExchange});

  static ServerHelloKeyShare deserialize(ByteReader r) {
    final grp = r.readUint16be();
    final kxLen = r.readUint16be();
    final kx = r.readBytes(kxLen);
    return ServerHelloKeyShare(group: grp, keyExchange: kx);
  }
}
