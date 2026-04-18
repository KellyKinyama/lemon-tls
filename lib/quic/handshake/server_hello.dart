// server_hello.dart
import 'dart:typed_data';
import 'package:hex/hex.dart';

import '../buffer.dart';
import 'tls_messages.dart'; // for TlsHandshakeMessage + maps
import 'keyshare.dart'; // for ParsedKeyShare

class ServerHello extends TlsHandshakeMessage {
  final int legacyVersion;
  final Uint8List random;
  final Uint8List sessionId;
  final int cipherSuite;
  final int compressionMethod;
  final Uint8List? rawBytes;

  // Parsed extensions
  final int? selectedVersion; // from supported_versions
  final ParsedKeyShare? keyShareEntry; // from key_share
  final Map<int, Uint8List> extensionsRaw; // stores all extension bodies

  ServerHello({
    required this.legacyVersion,
    required this.random,
    required this.sessionId,
    required this.cipherSuite,
    required this.compressionMethod,
    required this.extensionsRaw,
    required int msgType, // ALWAYS 0x02
    this.keyShareEntry,
    this.selectedVersion,
    this.rawBytes,
  }) : super(msgType);

  // ============================================================
  // ✅ PARSE — matches your JS & Dart ServerHello builder
  // ============================================================
  static ServerHello parse(QuicBuffer buf) {
    final legacyVersion = buf.pullUint16();
    final random = buf.pullBytes(32);

    final sidLen = buf.pullUint8();
    final sessionId = buf.pullBytes(sidLen);

    final cipherSuite = buf.pullUint16();

    final compression = buf.pullUint8();

    // ----------------------------
    // Parse extensions block
    // ----------------------------
    final extLen = buf.pullUint16();
    final extEnd = buf.readOffset + extLen;

    int? version;
    ParsedKeyShare? keyShare;
    final raw = <int, Uint8List>{};

    while (buf.readOffset < extEnd) {
      final extType = buf.pullUint16();
      final eLen = buf.pullUint16();
      final extData = buf.pullBytes(eLen);

      raw[extType] = extData;

      final extBuf = QuicBuffer(data: extData);

      switch (extType) {
        // supported_versions
        case 0x002B:
          if (eLen == 2) version = extBuf.pullUint16(); // should be 0x0304
          break;

        // key_share
        case 0x0033:
          final group = extBuf.pullUint16();
          final keyLen = extBuf.pullUint16();
          final key = extBuf.pullBytes(keyLen);
          keyShare = ParsedKeyShare(group, key);
          break;

        default:
          // leave extension data in raw[]
          break;
      }
    }

    return ServerHello(
      legacyVersion: legacyVersion,
      random: random,
      sessionId: sessionId,
      cipherSuite: cipherSuite,
      compressionMethod: compression,
      extensionsRaw: raw,
      keyShareEntry: keyShare,
      selectedVersion: version,
      msgType: 0x02,
      rawBytes: buf.data.sublist(0, buf.readOffset),
    );
  }

  // ============================================================
  // ✅ Debug Print
  // ============================================================
  @override
  String toString() {
    final ks = keyShareEntry != null
        ? "group=0x${keyShareEntry!.group.toRadixString(16)}, key=${HEX.encode(keyShareEntry!.pub)}"
        : "null";

    final ver = selectedVersion != null
        ? "0x${selectedVersion!.toRadixString(16)}"
        : "null";

    return '''
✅ Parsed ServerHello:
  legacy_version: 0x${legacyVersion.toRadixString(16)}
  random: ${HEX.encode(random.sublist(0, 8))}...
  session_id: ${HEX.encode(sessionId)}
  cipher_suite: 0x${cipherSuite.toRadixString(16)}
  compression: $compressionMethod
  selected_version: $ver
  key_share: $ks
''';
  }
}

Uint8List buildServerHello({
  required Uint8List serverRandom,
  required Uint8List publicKey,
  required Uint8List sessionId,
  required int cipherSuite,
  required int group,
}) {
  final out = BytesBuilder();

  // --------------------------------------------------
  // Handshake body
  // --------------------------------------------------
  final body = BytesBuilder();

  // legacy_version = 0x0303
  body.add([0x03, 0x03]);

  // random (32 bytes)
  body.add(serverRandom);

  // legacy_session_id_echo
  body.addByte(sessionId.length & 0xff);
  body.add(sessionId);

  // cipher_suite
  body.add([(cipherSuite >> 8) & 0xff, cipherSuite & 0xff]);

  // legacy_compression_method = 0x00
  body.addByte(0x00);

  // --------------------------------------------------
  // Extensions
  // --------------------------------------------------
  final extensions = BytesBuilder();

  // supported_versions extension
  // type = 0x002b, len = 0x0002, value = 0x0304
  extensions.add([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);

  // key_share extension
  final keyShareBody = BytesBuilder()
    ..add([(group >> 8) & 0xff, group & 0xff])
    ..add([(publicKey.length >> 8) & 0xff, publicKey.length & 0xff])
    ..add(publicKey);

  final keyShareBytes = keyShareBody.toBytes();

  extensions.add([
    0x00, 0x33, // extension type
    (keyShareBytes.length >> 8) & 0xff,
    keyShareBytes.length & 0xff,
    ...keyShareBytes,
  ]);

  final extBytes = extensions.toBytes();

  // extensions length
  body.add([(extBytes.length >> 8) & 0xff, extBytes.length & 0xff]);

  body.add(extBytes);

  final bodyBytes = body.toBytes();

  // --------------------------------------------------
  // Handshake wrapper
  // type = 0x02 (ServerHello)
  // length = uint24
  // --------------------------------------------------
  out.addByte(0x02);
  out.add([
    (bodyBytes.length >> 16) & 0xff,
    (bodyBytes.length >> 8) & 0xff,
    bodyBytes.length & 0xff,
  ]);
  out.add(bodyBytes);

  return out.toBytes();
}
