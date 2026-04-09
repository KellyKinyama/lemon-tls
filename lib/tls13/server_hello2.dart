import 'dart:math' as math;
import 'dart:typed_data';

import 'aead.dart';
import 'byte_reader.dart';
import 'handshake_headers2.dart';
import 'record_header.dart';

Uint8List _u8(int v) => Uint8List.fromList([v & 0xFF]);

Uint8List _u16be(int v) {
  final out = Uint8List(2);
  ByteData.sublistView(out).setUint16(0, v & 0xFFFF, Endian.big);
  return out;
}

Uint8List _randomBytes(int n) {
  final rnd = math.Random.secure();
  return Uint8List.fromList(List.generate(n, (_) => rnd.nextInt(256)));
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

final Map<int, ClientHelloExtension Function(ByteReader)> extensionsMap = {
  EXTENSION_KEY_SHARE: (reader) {
    print("[DEBUG] Parsing KEY_SHARE extension with ${reader.remaining} bytes");
    return ServerHelloKeyShare.deserialize(reader);
  },
  EXTENSION_SUPPORTED_VERSIONS: (reader) {
    print(
      "[DEBUG] Parsing SUPPORTED_VERSIONS extension with ${reader.remaining} bytes",
    );
    return ExtensionSupportedVersions.deserializeByteReader(reader);
  },
  EXTENSION_PSK_KEY_EXCHANGE_MODES: (reader) {
    print(
      "[DEBUG] Parsing PSK_KEY_EXCHANGE_MODES extension with ${reader.remaining} bytes",
    );
    return ExtensionPSKKeyExchangeModes.deserializeByteReader(reader);
  },
};

const int _EXT_KEY_SHARE = 0x33;
const int _EXT_SUPPORTED_VERSIONS = 0x2b;

class ServerHello {
  final RecordHeader recordHeader;
  final HandshakeHeader handshakeHeader;
  final int serverVersion;
  final Uint8List serverRandom;
  final Uint8List sessionId;
  final int cipherSuite;
  final List<ClientHelloExtension> extensions;

  late Uint8List
  legacySessionIdEcho; // usually empty in your client, so echo empty
  late Uint8List
  extensionsBytes; // raw extension block payload (not incl total length)

  ServerHello({
    required this.recordHeader,
    required this.handshakeHeader,
    required this.serverVersion,
    required this.serverRandom,
    required this.sessionId,
    required this.cipherSuite,
    required this.extensions,
  });

  ServerHello._toy({
    required this.recordHeader,
    required this.handshakeHeader,
    required this.serverRandom,
    required this.legacySessionIdEcho,
    required this.cipherSuite,
    required Uint8List extensionsBytes,
  }) : serverVersion = 0x0303,
       sessionId = legacySessionIdEcho,
       extensions = const [] {
    this.extensionsBytes = extensionsBytes;
  }

  static ServerHello deserialize(ByteReader byteStream) {
    print("===== BEGIN ServerHello =====");

    final rh = RecordHeader.deserialize(byteStream.readBytes(5));
    print("[DEBUG] RecordHeader: type=${rh.rtype} size=${rh.size}");

    final hh = HandshakeHeader.deserialize(byteStream.readBytes(4));
    print("[DEBUG] HandshakeHeader: msgType=${hh.messageType} size=${hh.size}");

    final serverVersion = byteStream.readInt16be();
    print("[DEBUG] legacy_version = 0x${serverVersion.toRadixString(16)}");

    final serverRandom = byteStream.readBytes(32);
    print("[DEBUG] server_random = ${serverRandom}");

    final sessionIdLength = byteStream.readInt8();
    print("[DEBUG] session_id_length = $sessionIdLength");
    if (sessionIdLength < 0) {
      throw StateError('Invalid session_id_length: $sessionIdLength');
    }

    final sessionId = byteStream.readBytes(sessionIdLength);
    print("[DEBUG] session_id = $sessionId");

    final cipherSuite = byteStream.readInt16be();
    print("[DEBUG] cipher_suite = 0x${cipherSuite.toRadixString(16)}");

    final compression = byteStream.readUint8();
    print("[DEBUG] compression_method = $compression (should be 0)");

    var extensionsLength = byteStream.readUint16be();
    print("[DEBUG] extensions_total_length = $extensionsLength");

    final exts = <ClientHelloExtension>[];

    while (extensionsLength > 0) {
      print("---- Extension Block Remaining: $extensionsLength ----");

      final extType = byteStream.readUint16be();
      final extLen = byteStream.readUint16be();

      print(
        "[DEBUG] Extension type=0x${extType.toRadixString(16)} len=$extLen",
      );

      extensionsLength -= (4 + extLen);

      final extData = byteStream.readBytes(extLen);
      print("[DEBUG] Extension data bytes: $extData");

      final subReader = ByteReader(extData);

      final deserializer = extensionsMap[extType];
      if (deserializer != null) {
        print(
          "[DEBUG] Using registered deserializer for extType=0x${extType.toRadixString(16)}",
        );
        exts.add(deserializer(subReader));
      } else {
        print(
          "[DEBUG] No deserializer for extType=0x${extType.toRadixString(16)}, skipping",
        );
      }
    }

    print("===== END ServerHello =====");

    return ServerHello(
      recordHeader: rh,
      handshakeHeader: hh,
      serverVersion: serverVersion,
      serverRandom: serverRandom,
      sessionId: sessionId,
      cipherSuite: cipherSuite,
      extensions: exts,
    );
  }

  static ServerHello buildForToyServer({
    required Uint8List keySharePublic, // 32 bytes X25519 pubkey
    required CipherSuite cipherSuite,
  }) {
    final cipher = switch (cipherSuite) {
      CipherSuite.aes128gcm => 0x1301,
      // CipherSuite.aes256gcm => 0x1302,
      CipherSuite.chacha20poly1305 => 0x1303,
    };

    // key_share ext payload:
    //   group(2)=0x001d, kx_len(2), kx
    final keySharePayload = _concat([
      _u16be(0x001D),
      _u16be(keySharePublic.length),
      keySharePublic,
    ]);
    final keyShareExt = _concat([
      _u16be(_EXT_KEY_SHARE),
      _u16be(keySharePayload.length),
      keySharePayload,
    ]);

    // supported_versions ext payload for ServerHello = selected_version(u16)=0x0304
    final suppVerPayload = _u16be(0x0304);
    final suppVerExt = _concat([
      _u16be(_EXT_SUPPORTED_VERSIONS),
      _u16be(suppVerPayload.length),
      suppVerPayload,
    ]);

    final exts = _concat([keyShareExt, suppVerExt]);

    final rh = RecordHeader(
      rtype: 0x16, // handshake record
      legacyProtoVersion: 0x0303,
      size: 0,
    );
    final hh = HandshakeHeader(messageType: 2, size: 0);

    final tmp = _concat([
      rh.serialize(),
      hh.serialize(),
      _u16be(0x0303), // legacy_version
      _randomBytes(32),
      _u8(0), // session_id_echo length
      // session_id_echo bytes (none)
      _u16be(cipher),
      _u8(0), // compression_method
      _u16be(exts.length),
      exts,
    ]);

    rh.size = tmp.length - 5;
    hh.size = rh.size - 4;

    return ServerHello._toy(
      recordHeader: rh,
      handshakeHeader: hh,
      serverRandom: tmp.sublist(11, 11 + 32), // not used elsewhere
      legacySessionIdEcho: Uint8List(0),
      cipherSuite: cipher,
      extensionsBytes: exts,
    );
  }

  Uint8List serialize() {
    // Build extension block bytes.
    // If built via buildForToyServer(), extensionsBytes is already set.
    Uint8List exts;
    if ((extensionsBytes is Uint8List) && extensionsBytes.isNotEmpty) {
      exts = extensionsBytes;
    } else {
      // Fallback: try to serialize from parsed extensions list if present.
      // NOTE: In this file extensions are ClientHelloExtension, which in your codebase
      // appears to include (type, data) and/or serialize(); adjust if needed.
      final parts = <Uint8List>[];
      for (final e in extensions) {
        // If your ClientHelloExtension has serialize() returning full ext
        // (type+len+data), this works.
        parts.add(e.serialize());
      }
      exts = _concat(parts);
      extensionsBytes = exts;
    }

    final body = _concat([
      _u16be(serverVersion), // legacy_version (0x0303)
      (serverRandom.length == 32) ? serverRandom : _randomBytes(32),
      _u8(sessionId.length),
      sessionId,
      _u16be(cipherSuite),
      _u8(0), // compression_method
      _u16be(exts.length),
      exts,
    ]);

    // Update header sizes
    handshakeHeader.size = body.length;
    final handshakeMsg = _concat([handshakeHeader.serialize(), body]);

    recordHeader.size = handshakeMsg.length;

    return _concat([recordHeader.serialize(), handshakeMsg]);
  }
}

// -----------------------------------------------------------
// SERVERHELLO KEY SHARE — Debug added, NO logic changes
// -----------------------------------------------------------
class ServerHelloKeyShare extends ClientHelloExtension {
  final int group;
  final Uint8List keyExchange;

  ServerHelloKeyShare({required this.group, required this.keyExchange})
    : super(EXTENSION_KEY_SHARE, keyExchange);

  static ServerHelloKeyShare deserialize(ByteReader r) {
    print("[DEBUG] ServerHelloKeyShare.deserialize starting");

    final group = r.readUint16be();
    final keyLen = r.readUint16be();

    print("[DEBUG] KeyShare group=0x${group.toRadixString(16)} keyLen=$keyLen");

    final keyExchange = r.readBytes(keyLen);

    print("[DEBUG] keyExchange bytes: $keyExchange");

    return ServerHelloKeyShare(group: group, keyExchange: keyExchange);
  }
}
