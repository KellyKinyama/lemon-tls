// ===============================
// giant single file as requested
// ===============================

import 'dart:math';
import 'dart:typed_data';

import 'record_header.dart';
import 'server_hello.dart';

// ----------------------------------------------------------
// Extension constants
// ----------------------------------------------------------
const int EXTENSION_SERVER_NAME = 0x00;
const int EXTENSION_SUPPORTED_GROUPS = 0x0A;
const int EXTENSION_SIGNATURE_ALGORITHMS = 0x0D;
const int EXTENSION_KEY_SHARE = 0x33;
const int EXTENSION_PSK_KEY_EXCHANGE_MODES = 0x2D;
const int EXTENSION_SUPPORTED_VERSIONS = 0x2B;
const int EXTENSION_EARLY_DATA = 0x2A;
const int EXTENSION_PRE_SHARED_KEY = 0x29;

// ----------------------------------------------------------
// Handshake Header
// ----------------------------------------------------------
class HandshakeHeader {
  final int messageType;
  int size;

  HandshakeHeader({required this.messageType, required this.size});

  Uint8List serialize() {
    final out = Uint8List(4);
    out[0] = messageType & 0xFF;
    out[1] = (size >> 16) & 0xFF;
    out[2] = (size >> 8) & 0xFF;
    out[3] = size & 0xFF;
    return out;
  }

  static HandshakeHeader deserialize(Uint8List bytes) {
    if (bytes.length != 4) {
      throw StateError(
        'HandshakeHeader.deserialize expects 4 bytes, got ${bytes.length}.',
      );
    }

    final bd = ByteData.sublistView(bytes);
    final msgType = bd.getUint8(0);
    final len = (bd.getUint8(1) << 16) | (bd.getUint8(2) << 8) | bd.getUint8(3);

    return HandshakeHeader(messageType: msgType, size: len);
  }
}

// ----------------------------------------------------------
// Small helpers
// ----------------------------------------------------------
Uint8List _u8(int v) => Uint8List.fromList([v & 0xFF]);

Uint8List _u16be(int v) {
  final out = Uint8List(2);
  ByteData.sublistView(out).setUint16(0, v & 0xFFFF, Endian.big);
  return out;
}

Uint8List _u32be(int v) {
  final out = Uint8List(4);
  ByteData.sublistView(out).setUint32(0, v, Endian.big);
  return out;
}

Uint8List _concat(List<Uint8List> parts) {
  final total = parts.fold<int>(0, (a, b) => a + b.length);
  final out = Uint8List(total);
  int o = 0;
  for (final p in parts) {
    out.setRange(o, o + p.length, p);
    o += p.length;
  }
  return out;
}

Uint8List _randomBytes(int n) {
  final rnd = Random.secure();
  final out = Uint8List(n);
  for (var i = 0; i < n; i++) out[i] = rnd.nextInt(256);
  return out;
}

// ----------------------------------------------------------
// Base extension class
// ----------------------------------------------------------
abstract class ClientHelloExtension {
  final int assignedValue;
  final int size; // data.length + 2
  final int someOtherSize;
  final Uint8List data;

  ClientHelloExtension(this.assignedValue, Uint8List data)
    : data = data,
      size = data.length + 2,
      someOtherSize = data.length;

  Uint8List serialize() {
    return _concat([
      _u16be(assignedValue),
      _u16be(size),
      _u16be(someOtherSize),
      data,
    ]);
  }
}

// ----------------------------------------------------------
// EARLY DATA
// ----------------------------------------------------------
class ExtensionEarlyData extends ClientHelloExtension {
  ExtensionEarlyData() : super(EXTENSION_EARLY_DATA, Uint8List(0));

  @override
  Uint8List serialize() {
    return Uint8List.fromList([0x00, 0x2A, 0x00, 0x00]);
  }
}

// ----------------------------------------------------------
// PRE SHARED KEY
// ----------------------------------------------------------
class ExtensionPreSharedKey extends ClientHelloExtension {
  ExtensionPreSharedKey({
    required Uint8List identity,
    required int obfuscatedTicketAge,
    required Uint8List binders,
  }) : super(
         EXTENSION_PRE_SHARED_KEY,
         serializePreSharedKeyExtension(
           identity: identity,
           obfuscatedTicketAge: obfuscatedTicketAge,
           binders: binders,
         ),
       );

  @override
  Uint8List serialize() {
    return _concat([_u16be(assignedValue), _u16be(data.length), data]);
  }

  static Uint8List serializePskIdentity({
    required Uint8List identity,
    required int obfuscatedTicketAge,
  }) {
    return _concat([
      _u16be(identity.length),
      identity,
      _u32be(obfuscatedTicketAge),
    ]);
  }

  static Uint8List serializeBinders({required Uint8List binders}) {
    final content = _concat([_u8(binders.length), binders]);
    return _concat([_u16be(content.length), content]);
  }

  static Uint8List serializePreSharedKeyExtension({
    required Uint8List identity,
    required int obfuscatedTicketAge,
    required Uint8List binders,
  }) {
    final id = serializePskIdentity(
      identity: identity,
      obfuscatedTicketAge: obfuscatedTicketAge,
    );

    final bindersSerialized = serializeBinders(binders: binders);

    return _concat([_u16be(id.length), id, bindersSerialized]);
  }
}

// ----------------------------------------------------------
// SERVER NAME
// ----------------------------------------------------------
class ExtensionServerName extends ClientHelloExtension {
  ExtensionServerName(Uint8List serverName)
    : super(
        EXTENSION_SERVER_NAME,
        _concat([_u8(0), _u16be(serverName.length), serverName]),
      );
}

// ----------------------------------------------------------
// SUPPORTED GROUPS
// ----------------------------------------------------------
class ExtensionSupportedGroups extends ClientHelloExtension {
  ExtensionSupportedGroups()
    : super(
        EXTENSION_SUPPORTED_GROUPS,
        _concat([_u16be(0x001D), _u16be(0x0017), _u16be(0x0018)]),
      );
}

// ----------------------------------------------------------
// SIGNATURE ALGORITHMS
// ----------------------------------------------------------
class ExtensionSignatureAlgorithms extends ClientHelloExtension {
  ExtensionSignatureAlgorithms()
    : super(
        EXTENSION_SIGNATURE_ALGORITHMS,
        _concat([
          _u16be(0x0403),
          _u16be(0x0804),
          _u16be(0x0401),
          _u16be(0x0503),
          _u16be(0x0805),
          _u16be(0x0501),
          _u16be(0x0806),
          _u16be(0x0601),
          _u16be(0x0201),
        ]),
      );
}

// ----------------------------------------------------------
// CLIENTHELLO KEY SHARE (unchanged)
// ----------------------------------------------------------
class ExtensionKeyShare extends ClientHelloExtension {
  final Uint8List publicKeyBytes;

  ExtensionKeyShare(this.publicKeyBytes)
    : super(
        EXTENSION_KEY_SHARE,
        _concat([
          _u16be(0x001D),
          _u16be(publicKeyBytes.length),
          publicKeyBytes,
        ]),
      );

  static ExtensionKeyShare deserialize(ByteData data, int offset) {
    final group = data.getUint16(offset + 4, Endian.big);
    final keyLength = data.getUint16(offset + 6, Endian.big);

    if (group != 0x001D) {
      throw UnsupportedError("Only X25519 supported");
    }

    final bytes = data.buffer.asUint8List(offset + 8, keyLength);
    return ExtensionKeyShare(bytes);
  }
}

// ----------------------------------------------------------
// PSK KEY EXCHANGE MODES (add ByteReader deserializer)
// ----------------------------------------------------------
class ExtensionPSKKeyExchangeModes extends ClientHelloExtension {
  ExtensionPSKKeyExchangeModes()
    : super(EXTENSION_PSK_KEY_EXCHANGE_MODES, Uint8List(0));

  @override
  Uint8List serialize() {
    return _concat([
      _u16be(EXTENSION_PSK_KEY_EXCHANGE_MODES),
      _u16be(0x02),
      _u8(0x01),
      _u8(0x01),
    ]);
  }

  static ExtensionPSKKeyExchangeModes deserializeByteReader(ByteReader r) {
    final type = r.readUint16be();
    final len = r.readUint16be();
    final data = r.readBytes(len);
    return ExtensionPSKKeyExchangeModes();
  }
}

// ----------------------------------------------------------
// SUPPORTED VERSIONS (corrected to use ByteReader)
// ----------------------------------------------------------
class ExtensionSupportedVersions extends ClientHelloExtension {
  final int selectedVersion;

  // ServerHello version is always 0x0304 for TLS 1.3
  ExtensionSupportedVersions(this.selectedVersion)
    : super(EXTENSION_SUPPORTED_VERSIONS, Uint8List(0));

  @override
  Uint8List serialize() {
    // ClientHello version list (unchanged)
    return _concat([
      _u16be(EXTENSION_SUPPORTED_VERSIONS),
      _u16be(0x03),
      _u8(0x02),
      _u16be(selectedVersion),
    ]);
  }

  /// Correct for ServerHello:
  /// data = ONLY 2 bytes: selected_version
  static ExtensionSupportedVersions deserializeByteReader(ByteReader r) {
    if (r.remaining < 2) {
      throw StateError(
        "SUPPORTED_VERSIONS extension truncated: expected 2 bytes, got ${r.remaining}",
      );
    }

    final version = r.readUint16be();

    print(
      "[DEBUG] ServerHello SupportedVersions = 0x${version.toRadixString(16)}",
    );

    return ExtensionSupportedVersions(version);
  }
}

// ==========================================================
// END OF FILE
// ==========================================================
