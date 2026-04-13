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
