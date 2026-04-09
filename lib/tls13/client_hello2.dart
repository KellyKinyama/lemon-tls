import 'dart:math';
import 'dart:typed_data';

import 'record_header.dart';
import 'handshake_headers.dart';

const int EXT_SERVER_NAME = 0x00;
const int EXT_SUPPORTED_GROUPS = 0x0A;
const int EXT_SIGNATURE_ALGORITHMS = 0x0D;
const int EXT_KEY_SHARE = 0x33;
const int EXT_PSK_MODES = 0x2D;
const int EXT_SUPPORTED_VERSIONS = 0x2B;

/// --- Helpers ---
Uint8List _u8(int v) => Uint8List.fromList([v & 0xFF]);
Uint8List _u16be(int v) {
  final out = Uint8List(2);
  ByteData.sublistView(out).setUint16(0, v, Endian.big);
  return out;
}

Uint8List _concat(List<Uint8List> parts) {
  final total = parts.fold(0, (n, p) => n + p.length);
  final out = Uint8List(total);
  var offset = 0;
  for (final p in parts) {
    out.setRange(offset, offset + p.length, p);
    offset += p.length;
  }
  return out;
}

Uint8List _randomBytes(int n) {
  final rnd = Random.secure();
  return Uint8List.fromList(List.generate(n, (_) => rnd.nextInt(256)));
}

/// Base extension
abstract class ClientHelloExtension {
  Uint8List serialize();
}

/// ---------------------
/// ✅ Server Name (SNI)
/// ---------------------
class ExtensionServerName extends ClientHelloExtension {
  final Uint8List host;

  ExtensionServerName(this.host);

  @override
  Uint8List serialize() {
    print("🔧 [EXT] SNI host='${String.fromCharCodes(host)}'");

    final name = _concat([
      _u8(0), // host_name
      _u16be(host.length),
      host,
    ]);

    final list = _concat([_u16be(name.length), name]);

    return _concat([_u16be(EXT_SERVER_NAME), _u16be(list.length), list]);
  }
}

/// ---------------------
/// ✅ Supported Groups
/// ---------------------
class ExtensionSupportedGroups extends ClientHelloExtension {
  @override
  Uint8List serialize() {
    print("🔧 [EXT] SupportedGroups");

    final groups = _concat([
      _u16be(0x001D), // x25519
      _u16be(0x0017), // secp256r1
      _u16be(0x0018), // secp384r1
    ]);

    final list = _concat([_u16be(groups.length), groups]);

    return _concat([_u16be(EXT_SUPPORTED_GROUPS), _u16be(list.length), list]);
  }
}

/// ---------------------
/// ✅ Signature Algorithms
/// ---------------------
class ExtensionSignatureAlgorithms extends ClientHelloExtension {
  @override
  Uint8List serialize() {
    print("🔧 [EXT] SignatureAlgorithms");

    final sigs = _concat([
      _u16be(0x0403), // ecdsa_secp256r1_sha256
      _u16be(0x0804), // rsa_pss_rsae_sha256
      _u16be(0x0401), // rsa_pkcs1_sha256
      _u16be(0x0503), // ecdsa_secp384r1_sha384
      _u16be(0x0805), // rsa_pss_rsae_sha384
      _u16be(0x0806), // rsa_pss_rsae_sha512
      _u16be(0x0601), // rsa_pkcs1_sha512
    ]);

    final list = _concat([_u16be(sigs.length), sigs]);

    return _concat([
      _u16be(EXT_SIGNATURE_ALGORITHMS),
      _u16be(list.length),
      list,
    ]);
  }
}

/// ---------------------
/// ✅ KeyShare (X25519)
/// ---------------------
class ExtensionKeyShare extends ClientHelloExtension {
  final Uint8List key;

  ExtensionKeyShare(this.key);

  @override
  Uint8List serialize() {
    print("🔧 [EXT] KeyShare x25519 pub=${key.length} bytes");

    final entry = _concat([
      _u16be(0x001D), // x25519
      _u16be(key.length),
      key,
    ]);

    final list = _concat([_u16be(entry.length), entry]);

    return _concat([_u16be(EXT_KEY_SHARE), _u16be(list.length), list]);
  }
}

/// ---------------------
/// ✅ PSK Key Exchange Modes
/// ---------------------
class ExtensionPSKKeyExchangeModes extends ClientHelloExtension {
  @override
  Uint8List serialize() {
    print("🔧 [EXT] PSK Key Exchange Modes");

    return _concat([
      _u16be(EXT_PSK_MODES),
      _u16be(2),
      _u8(1), // length
      _u8(1), // psk_ke
    ]);
  }
}

/// ---------------------
/// ✅ SupportedVersions
/// ---------------------
class ExtensionSupportedVersions extends ClientHelloExtension {
  @override
  Uint8List serialize() {
    print("🔧 [EXT] SupportedVersions TLS1.3");

    final list = _concat([_u8(2), _u16be(0x0304)]);

    return _concat([_u16be(EXT_SUPPORTED_VERSIONS), _u16be(list.length), list]);
  }
}

/// --------------------------
/// ✅ FULL CORRECTED CLIENTHELLO
/// --------------------------
class ClientHello {
  final RecordHeader recordHeader;
  final HandshakeHeader handshakeHeader;

  final Uint8List clientRandom = _randomBytes(32);
  final Uint8List sessionId = Uint8List(0); // MUST be empty

  final Uint8List cipherSuites = Uint8List.fromList([
    0x13,
    0x01,
    0x13,
    0x02,
    0x13,
    0x03,
  ]);

  final List<ClientHelloExtension> extensions;

  ClientHello({required Uint8List domain, required Uint8List publicKeyBytes})
    : recordHeader = RecordHeader(
        rtype: 0x16,
        legacyProtoVersion: 0x0303, // FIXED
        size: 0,
      ),
      handshakeHeader = HandshakeHeader(messageType: 1, size: 0),
      extensions = [
        ExtensionServerName(domain),
        ExtensionSupportedGroups(),
        ExtensionSignatureAlgorithms(),
        ExtensionKeyShare(publicKeyBytes),
        ExtensionPSKKeyExchangeModes(),
        ExtensionSupportedVersions(),
      ];

  Uint8List _build() {
    print("📤 Building ClientHello...");

    final extBytes = _concat(extensions.map((e) => e.serialize()).toList());

    print("🔧 Extensions total length = ${extBytes.length}");

    return _concat([
      recordHeader.serialize(),
      handshakeHeader.serialize(),
      _u16be(0x0303), // legacy_version
      clientRandom,
      _u8(sessionId.length),
      sessionId,
      _u16be(cipherSuites.length),
      cipherSuites,
      _u8(1), _u8(0), // compression = null
      _u16be(extBytes.length),
      extBytes,
    ]);
  }

  Uint8List serialize() {
    final tmp = _build();
    recordHeader.size = tmp.length - 5;
    handshakeHeader.size = recordHeader.size - 4;

    final finalBytes = _build();
    print("✅ ClientHello READY: ${finalBytes.length} bytes");

    return finalBytes;
  }
}
