import 'dart:math';
import 'dart:typed_data';

import 'package:lemon_tls/tls13/server_hello.dart';

import 'byte_reader.dart';
import 'record_header.dart';
import 'handshake_headers2.dart';

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
// filepath: /c:/www/dart/lemon-tls/lib/tls13/client_hello4.dart
// ...existing code...

class ClientHello {
  final RecordHeader? recordHeader; // <-- allow null for handshake-only input
  final HandshakeHeader handshakeHeader;

  Uint8List clientRandom = _randomBytes(32);
  Uint8List sessionId = Uint8List(0);
  Uint8List cipherSuites = Uint8List.fromList([
    0x13,
    0x01,
    0x13,
    0x02,
    0x13,
    0x03,
  ]);

  final List<ClientHelloExtension> extensions;
  List<ClientHelloExtensionParsed> parsedExtensions = [];

  ClientHello({
    required Uint8List domain,
    required Uint8List publicKeyBytes,
    required this.parsedExtensions,
  }) : recordHeader = RecordHeader(
         rtype: 0x16,
         legacyProtoVersion: 0x0303,
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

  ClientHello._parsed({
    required this.recordHeader,
    required this.handshakeHeader,
    required this.clientRandom,
    required this.sessionId,
    required this.cipherSuites,
    required this.parsedExtensions,
  }) : extensions = const [];

  // ...existing _build()/serialize...

  static ClientHello deserialize(ByteReader r) {
    RecordHeader? rh;

    // If we have a TLSPlaintext record in front, parse it.
    // TLSPlaintext.type for handshake is 0x16.
    if (r.remaining >= 5) {
      final first = r.peekUint8();
      if (first == 0x16) {
        rh = RecordHeader.deserialize(r.readBytes(5));
      }
    }

    final hh = HandshakeHeader.deserialize(r.readBytes(4));
    if (hh.messageType != 0x01) {
      throw StateError('Expected ClientHello (type=1), got ${hh.messageType}');
    }

    final legacyVersion = r.readUint16be();
    final random = r.readBytes(32);

    final sidLen = r.readUint8();
    final sid = r.readBytes(sidLen);

    final csLen = r.readUint16be();
    final cs = r.readBytes(csLen);

    final compLen = r.readUint8();
    r.readBytes(compLen);

    final extTotalLen = r.readUint16be();
    final extBytes = r.readBytes(extTotalLen);
    final er = ByteReader(extBytes);

    final parsed = <ClientHelloExtensionParsed>[];

    while (er.remaining >= 4) {
      final extType = er.readUint16be();
      final extLen = er.readUint16be();
      final data = er.readBytes(extLen);
      final dr = ByteReader(data);

      switch (extType) {
        case EXT_SERVER_NAME:
          if (dr.remaining < 2) break;
          final listLen = dr.readUint16be();
          if (listLen == 0 || dr.remaining < listLen) break;
          final nameType = dr.readUint8();
          if (nameType != 0) break;
          final hostLen = dr.readUint16be();
          if (dr.remaining < hostLen) break;
          parsed.add(ClientHelloServerName(dr.readBytes(hostLen)));
          break;

        case EXT_KEY_SHARE:
          if (dr.remaining < 2) break;
          final listLen = dr.readUint16be();
          if (listLen == 0 || dr.remaining < listLen) break;
          if (dr.remaining < 4) break;
          final group = dr.readUint16be();
          final kxLen = dr.readUint16be();
          if (dr.remaining < kxLen) break;
          parsed.add(
            ClientHelloKeyShare(group: group, keyExchange: dr.readBytes(kxLen)),
          );
          break;

        case EXT_SUPPORTED_VERSIONS:
          if (dr.remaining < 1) break;
          final len = dr.readUint8();
          final vv = <int>[];
          final take = len.clamp(0, dr.remaining);
          final vbr = ByteReader(dr.readBytes(take));
          while (vbr.remaining >= 2) {
            vv.add(vbr.readUint16be());
          }
          parsed.add(ClientHelloSupportedVersions(vv));
          break;

        default:
          break;
      }
    }

    return ClientHello._parsed(
      recordHeader: rh, // <-- can be null now (handshake-only input)
      handshakeHeader: hh,
      clientRandom: random,
      sessionId: sid,
      cipherSuites: cs,
      parsedExtensions: parsed,
    );
  }
}

/// Parsed extensions for server-side consumption
abstract class ClientHelloExtensionParsed {}

class ClientHelloServerName extends ClientHelloExtensionParsed {
  final Uint8List host;
  ClientHelloServerName(this.host);
}

class ClientHelloKeyShare extends ClientHelloExtensionParsed {
  final int group; // e.g. 0x001D
  final Uint8List keyExchange; // client public key
  ClientHelloKeyShare({required this.group, required this.keyExchange});
}

class ClientHelloSupportedVersions extends ClientHelloExtensionParsed {
  final List<int> versions; // e.g. [0x0304]
  ClientHelloSupportedVersions(this.versions);
}
