import 'dart:math';
import 'dart:typed_data';

import 'record_header.dart';
import 'handshake_headers.dart';

const int EXTENSION_SERVER_NAME = 0x00;
const int EXTENSION_SUPPORTED_GROUPS = 0x0A;
const int EXTENSION_SIGNATURE_ALGORITHMS = 0x0D;
const int EXTENSION_KEY_SHARE = 0x33;
const int EXTENSION_PSK_KEY_EXCHANGE_MODES = 0x2D;
const int EXTENSION_SUPPORTED_VERSIONS = 0x2B;
const int EXTENSION_EARLY_DATA = 0x2A;
const int EXTENSION_PRE_SHARED_KEY = 0x29;

/// --- small byte helpers (replaces Python struct.pack / b"".join) ---

Uint8List _u8(int v) => Uint8List.fromList([v & 0xFF]);

Uint8List _u16be(int v) {
  final out = Uint8List(2);
  final bd = ByteData.sublistView(out);
  bd.setUint16(0, v & 0xFFFF, Endian.big);
  return out;
}

Uint8List _u32be(int v) {
  final out = Uint8List(4);
  final bd = ByteData.sublistView(out);
  bd.setUint32(0, v & 0xFFFFFFFF, Endian.big);
  return out;
}

Uint8List _concat(List<Uint8List> parts) {
  final total = parts.fold<int>(0, (n, p) => n + p.length);
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
  final out = Uint8List(n);
  for (var i = 0; i < n; i++) {
    out[i] = rnd.nextInt(256);
  }
  return out;
}

/// --- Extensions ---

// abstract class ClientHelloExtension {
//   final int assignedValue;
//   final int size; // len(data) + 2 (matches Python)
//   final int someOtherSize; // len(data)
//   final Uint8List data;

//   ClientHelloExtension(this.assignedValue, Uint8List data)
//       : data = data,
//         size = data.length + 2,
//         someOtherSize = data.length;

//   Uint8List serialize() {
//     return _concat([
//       _u16be(assignedValue),
//       _u16be(size),
//       _u16be(someOtherSize),
//       data,
//     ]);
//   }
// }

class ExtensionEarlyData extends ClientHelloExtension {
  ExtensionEarlyData() : super(EXTENSION_EARLY_DATA, Uint8List(0));

  @override
  Uint8List serialize() {
    // Python: b"\x00*\x00\x00"
    return Uint8List.fromList([0x00, 0x2A, 0x00, 0x00]);
  }
}

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
    // Note: differs from base class; Python writes (type, len(data), data)
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
    final bindersSerialized = _concat([_u8(binders.length), binders]);

    return _concat([_u16be(bindersSerialized.length), bindersSerialized]);
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

    return _concat([_u16be(id.length), id, serializeBinders(binders: binders)]);
  }
}

class ExtensionServerName extends ClientHelloExtension {
  ExtensionServerName(Uint8List serverName)
    : super(
        EXTENSION_SERVER_NAME,
        _concat([
          _u8(0), // name_type = host_name
          _u16be(serverName.length),
          serverName,
        ]),
      );
}

class ExtensionSupportedGroups extends ClientHelloExtension {
  ExtensionSupportedGroups()
    : super(
        EXTENSION_SUPPORTED_GROUPS,
        _concat([_u16be(0x001D), _u16be(0x0017), _u16be(0x0018)]),
      );
}

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

// class ExtensionKeyShare extends ClientHelloExtension {
//   final Uint8List publicKeyBytes;

//   ExtensionKeyShare(this.publicKeyBytes)
//     : super(
//         EXTENSION_KEY_SHARE,
//         _concat([
//           _u16be(0x001D),
//           _u16be(publicKeyBytes.length),
//           publicKeyBytes,
//         ]),
//       );

//   /// Rough equivalent to the Python `.deserialize(data)` that reads from a stream.
//   /// Here we accept a ByteData + offset.
//   static ExtensionKeyShare deserialize(ByteData data, int offset) {
//     // >h >h >h >h then payload
//     final _assignedValue = data.getUint16(offset, Endian.big);
//     final _dataFollows = data.getUint16(offset + 2, Endian.big);
//     final _x25519AssignedValue = data.getUint16(offset + 4, Endian.big);
//     final publicKeyLength = data.getUint16(offset + 6, Endian.big);

//     final start = offset + 8;
//     final bytes = Uint8List(publicKeyLength);
//     for (var i = 0; i < publicKeyLength; i++) {
//       bytes[i] = data.getUint8(start + i);
//     }

//     return ExtensionKeyShare(bytes);
//   }
// }

class ExtensionPSKKeyExchangeModes extends ClientHelloExtension {
  ExtensionPSKKeyExchangeModes()
    : super(EXTENSION_PSK_KEY_EXCHANGE_MODES, Uint8List(0));

  @override
  Uint8List serialize() {
    // Python hard-coded: type, len=0x02, 0x01, 0x01
    return _concat([
      _u16be(EXTENSION_PSK_KEY_EXCHANGE_MODES),
      _u16be(0x02),
      _u8(0x01),
      _u8(0x01),
    ]);
  }
}

class ExtensionSupportedVersions extends ClientHelloExtension {
  final int dataVersion; // 0x0304

  ExtensionSupportedVersions()
    : dataVersion = 0x0304,
      super(EXTENSION_SUPPORTED_VERSIONS, Uint8List(0));

  @override
  Uint8List serialize() {
    // Python hard-coded: type, len=0x03, list_len=0x02, version
    return _concat([
      _u16be(EXTENSION_SUPPORTED_VERSIONS),
      _u16be(0x03),
      _u8(0x02),
      _u16be(dataVersion),
    ]);
  }

  static ExtensionSupportedVersions deserialize(ByteData data, int offset) {
    final _assignedValue = data.getUint16(offset, Endian.big);
    final _dataFollows = data.getUint16(offset + 2, Endian.big);
    final _assignedVersion = data.getUint16(offset + 4, Endian.big);
    return ExtensionSupportedVersions();
  }
}

/// --- ClientHello ---

class ClientHello {
  final RecordHeader recordHeader;
  final HandshakeHeader handshakeHeader;

  final int clientVersion = 0x0303;
  final Uint8List clientRandom;
  final Uint8List sessionId;
  final Uint8List cipherSuites;

  final List<ClientHelloExtension> extensions;

  ClientHello({required Uint8List domain, required Uint8List publicKeyBytes})
    : recordHeader = RecordHeader(
        rtype: 0x16,
        legacyProtoVersion: 0x0301,
        size: 0,
      ),
      handshakeHeader = HandshakeHeader(messageType: 0x01, size: 0),
      clientRandom = _randomBytes(32),
      sessionId = _randomBytes(32),
      // Python: bytes.fromhex("130113021303")
      cipherSuites = Uint8List.fromList([0x13, 0x01, 0x13, 0x02, 0x13, 0x03]),
      extensions = [
        ExtensionServerName(domain),
        ExtensionSupportedGroups(),
        ExtensionSignatureAlgorithms(),
        ExtensionKeyShare(publicKeyBytes),
        ExtensionPSKKeyExchangeModes(),
        ExtensionSupportedVersions(),
      ];

  void addExtension(ClientHelloExtension extension) {
    extensions.add(extension);
  }

  void calcRecordSize() {
    final data = _serialize();
    recordHeader.size = data.length - 5; // record header is 5 bytes
    handshakeHeader.size = recordHeader.size - 4; // handshake header is 4 bytes
  }

  Uint8List _serialize() {
    final extensionData = _concat(
      extensions.map((e) => e.serialize()).toList(),
    );
    final extensionLength = extensionData.length;

    return _concat([
      recordHeader.serialize(),
      handshakeHeader.serialize(),
      _u16be(clientVersion),
      clientRandom, // already exactly 32 bytes
      _concat([_u8(sessionId.length), sessionId]),
      _concat([_u16be(cipherSuites.length), cipherSuites]),
      _concat([_u8(1), _u8(0)]), // compression mode
      _u16be(extensionLength),
      extensionData,
    ]);
  }

  Uint8List serialize() {
    calcRecordSize();
    return _serialize();
  }
}
