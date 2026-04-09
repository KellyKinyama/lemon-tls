import 'dart:math';
import 'dart:typed_data';

import 'byte_reader.dart';
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
  ByteData.sublistView(out).setUint16(0, v & 0xFFFF, Endian.big);
  return out;
}

Uint8List _concat(List<Uint8List> parts) {
  final total = parts.fold(0, (n, p) => n + p.length);
  final out = Uint8List(total);
  var off = 0;
  for (final p in parts) {
    out.setRange(off, off + p.length, p);
    off += p.length;
  }
  return out;
}

Uint8List _randomBytes(int n) {
  final rnd = Random.secure();
  return Uint8List.fromList(List.generate(n, (_) => rnd.nextInt(256)));
}

/// ==========================================
/// TLS 1.3 ClientHello Extensions
/// ==========================================

abstract class ClientHelloExtension {
  Uint8List serialize();
}

/// ✅ SNI
class ExtensionServerName extends ClientHelloExtension {
  final Uint8List host;

  ExtensionServerName(this.host);

  @override
  Uint8List serialize() {
    final name = _concat([_u8(0), _u16be(host.length), host]);

    final list = _concat([_u16be(name.length), name]);

    return _concat([_u16be(EXT_SERVER_NAME), _u16be(list.length), list]);
  }
}

/// ✅ Supported Groups
class ExtensionSupportedGroups extends ClientHelloExtension {
  @override
  Uint8List serialize() {
    final groups = _concat([
      _u16be(0x001D), // x25519
      _u16be(0x0017), // secp256r1
      _u16be(0x0018), // secp384r1
    ]);

    final list = _concat([_u16be(groups.length), groups]);

    return _concat([_u16be(EXT_SUPPORTED_GROUPS), _u16be(list.length), list]);
  }
}

/// ✅ Signature Algorithms
class ExtensionSignatureAlgorithms extends ClientHelloExtension {
  @override
  Uint8List serialize() {
    final sigs = _concat([
      _u16be(0x0403),
      _u16be(0x0804),
      _u16be(0x0401),
      _u16be(0x0503),
      _u16be(0x0805),
      _u16be(0x0806),
      _u16be(0x0601),
    ]);

    final list = _concat([_u16be(sigs.length), sigs]);

    return _concat([
      _u16be(EXT_SIGNATURE_ALGORITHMS),
      _u16be(list.length),
      list,
    ]);
  }
}

/// ✅ KeyShare (X25519)
class ExtensionKeyShare extends ClientHelloExtension {
  final Uint8List key;

  ExtensionKeyShare(this.key);

  @override
  Uint8List serialize() {
    final entry = _concat([_u16be(0x001D), _u16be(key.length), key]);

    final list = _concat([_u16be(entry.length), entry]);

    return _concat([_u16be(EXT_KEY_SHARE), _u16be(list.length), list]);
  }
}

/// ✅ PSK Modes
class ExtensionPSKKeyExchangeModes extends ClientHelloExtension {
  @override
  Uint8List serialize() {
    return _concat([_u16be(EXT_PSK_MODES), _u16be(2), _u8(1), _u8(1)]);
  }
}

/// ✅ Supported Versions
class ExtensionSupportedVersions extends ClientHelloExtension {
  @override
  Uint8List serialize() {
    final list = _concat([
      _u8(2),
      _u16be(0x0304), // TLS 1.3
    ]);

    return _concat([_u16be(EXT_SUPPORTED_VERSIONS), _u16be(list.length), list]);
  }
}

/// ===================================================
/// ✅ FULL CORRECTED ClientHello (QUIC‑COMPATIBLE)
/// ===================================================

class ClientHello {
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

  /// ✅ QUIC constructor (NO RecordHeader)
  ClientHello({required Uint8List domain, required Uint8List publicKeyBytes})
    : handshakeHeader = HandshakeHeader(messageType: 1, size: 0),
      extensions = [
        ExtensionServerName(domain),
        ExtensionSupportedGroups(),
        ExtensionSignatureAlgorithms(),
        ExtensionKeyShare(publicKeyBytes),
        ExtensionPSKKeyExchangeModes(),
        ExtensionSupportedVersions(),
      ];

  ClientHello._parsed({
    required this.handshakeHeader,
    required this.clientRandom,
    required this.sessionId,
    required this.cipherSuites,
    required this.parsedExtensions,
  }) : extensions = const [];

  /// ✅ Serialize WITHOUT TLS RecordHeader
  Uint8List serialize() {
    final body = _buildBody();
    handshakeHeader.size = body.length;

    return Uint8List.fromList([...handshakeHeader.serialize(), ...body]);
  }

  Uint8List _buildBody() {
    final extBlocks = extensions.map((e) => e.serialize()).toList();
    final extBytes = _concat(extBlocks);

    return _concat([
      _u16be(0x0303), // legacy_version
      clientRandom,
      _u8(sessionId.length),
      sessionId,
      _u16be(cipherSuites.length),
      cipherSuites,
      _u8(1), _u8(0), // compression_methods = null
      _u16be(extBytes.length),
      extBytes,
    ]);
  }

  /// ✅ QUIC deserializer (NO TLS RecordHeader)
  static ClientHello deserialize(ByteReader r) {
    final hh = HandshakeHeader.deserialize(r.readBytes(4));

    if (hh.messageType != 1) {
      throw StateError('Expected ClientHello');
    }

    final legacy = r.readUint16be();
    final random = r.readBytes(32);

    final sidLen = r.readUint8();
    final sid = r.readBytes(sidLen);

    final csLen = r.readUint16be();
    final cs = r.readBytes(csLen);

    final compLen = r.readUint8();
    r.readBytes(compLen);

    final extLen = r.readUint16be();
    final extBytes = r.readBytes(extLen);

    final parsed = _parseExtensions(extBytes);

    return ClientHello._parsed(
      handshakeHeader: hh,
      clientRandom: random,
      sessionId: sid,
      cipherSuites: cs,
      parsedExtensions: parsed,
    );
  }
}

/// ===================================================
/// ✅ Extension Parsers
/// ===================================================

List<ClientHelloExtensionParsed> _parseExtensions(Uint8List extBytes) {
  final r = ByteReader(extBytes);
  final out = <ClientHelloExtensionParsed>[];

  while (r.remaining >= 4) {
    final extType = r.readUint16be();
    final extLen = r.readUint16be();
    final data = r.readBytes(extLen);
    final dr = ByteReader(data);

    switch (extType) {
      case EXT_SERVER_NAME:
        final listLen = dr.readUint16be();
        final nameType = dr.readUint8();
        final hostLen = dr.readUint16be();
        out.add(ClientHelloServerName(dr.readBytes(hostLen)));
        break;

      case EXT_KEY_SHARE:
        dr.readUint16be(); // list len
        final group = dr.readUint16be();
        final kxLen = dr.readUint16be();
        out.add(
          ClientHelloKeyShare(group: group, keyExchange: dr.readBytes(kxLen)),
        );
        break;

      case EXT_SUPPORTED_VERSIONS:
        final len = dr.readUint8();
        final versions = <int>[];
        for (int i = 0; i < len ~/ 2; i++) {
          versions.add(dr.readUint16be());
        }
        out.add(ClientHelloSupportedVersions(versions));
        break;

      default:
        break;
    }
  }

  return out;
}

/// ===================================================
/// ✅ Parsed Extension Types
/// ===================================================

abstract class ClientHelloExtensionParsed {}

class ClientHelloServerName extends ClientHelloExtensionParsed {
  final Uint8List host;
  ClientHelloServerName(this.host);
}

class ClientHelloKeyShare extends ClientHelloExtensionParsed {
  final int group;
  final Uint8List keyExchange;
  ClientHelloKeyShare({required this.group, required this.keyExchange});
}

class ClientHelloSupportedVersions extends ClientHelloExtensionParsed {
  final List<int> versions;
  ClientHelloSupportedVersions(this.versions);
}
