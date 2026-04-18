import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:lemon_tls/quic/handshake/tls_messages.dart';

import '../buffer.dart';
import '../frames/quic_frames.dart';
import 'quic_session.dart';

/// =============================================================
/// Parsed QUIC payload result
/// =============================================================
class ParsedQuicPayload {
  final List<QuicFrame> frames;
  List<CryptoFrame> cryptoFrames = [];
  final AckFrame? ack;

  List<TlsHandshakeMessage> tlsMessages;

  ParsedQuicPayload({
    required this.frames,
    this.ack,
    required this.cryptoFrames,
    required this.tlsMessages,
  });
}

/// =============================================================
/// Parse decrypted QUIC payload into frames
/// =============================================================

ParsedQuicPayload parsePayload(
  Uint8List plaintextPayload,
  QuicSession session, {
  required EncryptionLevel level,
}) {
  print('--- Parsing Decrypted QUIC Payload ---');

  final buffer = QuicBuffer(data: plaintextPayload);
  final frames = <QuicFrame>[];
  final cryptoFrames = <CryptoFrame>[];
  final tlsMessages = <TlsHandshakeMessage>[];
  AckFrame? ackFrame;

  try {
    while (!buffer.eof && buffer.byteData.getUint8(buffer.readOffset) != 0) {
      final frameType = buffer.pullVarInt();

      // =========================================================
      // ✅ CRYPTO frame (0x06)
      // =========================================================
      if (frameType == 0x06) {
        final offset = buffer.pullVarInt();
        final length = buffer.pullVarInt();
        final cryptoData = buffer.pullBytes(length);

        print('✅ Parsed CRYPTO Frame: offset=$offset, length=$length');

        // ✅ Store CRYPTO chunk
        session.cryptoChunksByLevel[level]![offset] = cryptoData;

        final assembled = session.assembleCryptoStream(level);

        // Append newly contiguous received TLS bytes to transcript
        if (assembled.isNotEmpty) {
          session.tlsTranscript.add(assembled);
          tlsMessages.addAll(parseTlsMessages(assembled, quicSession: session));

          // ✅ Extract the exact server handshake messages from the client side
          _maybeLogServerArtifacts(session);
        }
      }
      // =========================================================
      // ✅ ACK frame (0x02)
      // =========================================================
      else if (frameType == 0x02) {
        final hasECN = (frameType & 0x01) == 0x01;

        final largest = buffer.pullVarInt();
        final delay = buffer.pullVarInt();
        final rangeCount = buffer.pullVarInt();
        final firstRange = buffer.pullVarInt();

        final ranges = <dynamic>[];
        for (int i = 0; i < rangeCount; i++) {
          final gap = buffer.pullVarInt();
          final len = buffer.pullVarInt();
          ranges.add((gap: gap, length: len));
        }

        dynamic ecn;
        if (hasECN) {
          final ect0 = buffer.pullVarInt();
          final ect1 = buffer.pullVarInt();
          final ce = buffer.pullVarInt();
          ecn = {ect0: ect0, ect1: ect1, ce: ce};
        }

        ackFrame = AckFrame(
          largest: largest,
          delay: delay,
          firstRange: firstRange,
          ranges: ranges,
          ecn: ecn,
        );

        frames.add(ackFrame);
      }
      // =========================================================
      // ✅ Skip unknown frames
      // =========================================================
      else {
        print('ℹ️ Skipping frame type 0x${frameType.toRadixString(16)}');
      }
    }
  } catch (e, st) {
    print('\n🛑 Error during payload parsing: $e\n$st');
  }

  print('\n🎉 Payload parsing complete.');

  return ParsedQuicPayload(
    frames: frames,
    cryptoFrames: cryptoFrames,
    ack: ackFrame,
    tlsMessages: tlsMessages,
  );
}

String _handshakeTypeName(int type) {
  switch (type) {
    case 0x02:
      return "ServerHello";
    case 0x08:
      return "EncryptedExtensions";
    case 0x0b:
      return "Certificate";
    case 0x0f:
      return "CertificateVerify";
    case 0x14:
      return "Finished";
    default:
      return "Unknown(0x${type.toRadixString(16)})";
  }
}

/// Extracts complete TLS handshake messages from a byte stream.
/// Returns a map keyed by handshake type.
/// If multiple messages of the same type appear, the last one wins.
/// (For your current use, that's fine.)
Map<int, Uint8List> _extractHandshakeMessages(Uint8List stream) {
  final out = <int, Uint8List>{};

  int i = 0;
  while (i + 4 <= stream.length) {
    final type = stream[i];
    final len = (stream[i + 1] << 16) | (stream[i + 2] << 8) | stream[i + 3];

    // Stop if the current message is incomplete
    if (i + 4 + len > stream.length) {
      break;
    }

    out[type] = stream.sublist(i, i + 4 + len);
    i += 4 + len;
  }

  return out;
}

/// Parses useful fields out of a full ServerHello handshake message.
/// Expects the full TLS handshake message: type + 3-byte len + body.
void _logServerHelloFields(Uint8List serverHello) {
  if (serverHello.length < 4) return;

  final body = serverHello.sublist(4);
  int p = 0;

  if (body.length < 2 + 32 + 1 + 2 + 1 + 2) {
    return;
  }

  final legacyVersion = (body[p++] << 8) | body[p++];
  final serverRandom = body.sublist(p, p + 32);
  p += 32;

  final sessionIdLen = body[p++];
  final sessionId = body.sublist(p, p + sessionIdLen);
  p += sessionIdLen;

  final cipherSuite = (body[p++] << 8) | body[p++];
  final compressionMethod = body[p++];

  final extensionsLen = (body[p++] << 8) | body[p++];
  final extEnd = p + extensionsLen;

  int? selectedGroup;
  Uint8List? serverPublicKey;

  while (p + 4 <= body.length && p < extEnd) {
    final extType = (body[p++] << 8) | body[p++];
    final extLen = (body[p++] << 8) | body[p++];
    final extData = body.sublist(p, p + extLen);
    p += extLen;

    if (extType == 0x0033 && extData.length >= 4) {
      selectedGroup = (extData[0] << 8) | extData[1];
      final keyLen = (extData[2] << 8) | extData[3];
      if (4 + keyLen <= extData.length) {
        serverPublicKey = extData.sublist(4, 4 + keyLen);
      }
    }
  }

  print("🟪 [CLIENT EXTRACT] ServerHello fields");
  print("  legacy_version: $legacyVersion");
  print("  server_random: ${HEX.encode(serverRandom)}");
  print("  session_id: ${HEX.encode(sessionId)}");
  print("  cipher_suite: $cipherSuite");
  print("  compression_method: $compressionMethod");
  print("  selected_group: ${selectedGroup ?? -1}");
  if (serverPublicKey != null) {
    print("  server_public_key: ${HEX.encode(serverPublicKey)}");
  }
}

/// Logs the exact server-side handshake messages once they are all available.
/// This is the easiest way to extract:
///   - serverHelloHex
///   - encryptedExtensionsHex
///   - certificateHex
///   - certificateVerifyHex
///   - finishedHex
///
/// directly from the client side.
void _maybeLogServerArtifacts(QuicSession session) {
  // if (session.serverArtifactsLogged) {
  //   return;
  // }

  final transcript = session.tlsTranscript.toBytes();
  final msgs = _extractHandshakeMessages(transcript);

  final serverHello = msgs[0x02];
  final encryptedExtensions = msgs[0x08];
  final certificate = msgs[0x0b];
  final certificateVerify = msgs[0x0f];
  final finished = msgs[0x14];

  // Only log once we have the 4 server-flight messages you need for the Dart server.
  if (serverHello == null ||
      encryptedExtensions == null ||
      certificate == null ||
      certificateVerify == null) {
    return;
  }

  print("🟪 [CLIENT EXTRACT] Full server handshake artifacts");
  print('const String serverHelloHex = "${HEX.encode(serverHello)}";');
  print(
    'const String encryptedExtensionsHex = "${HEX.encode(encryptedExtensions)}";',
  );
  print('const String certificateHex = "${HEX.encode(certificate)}";');
  print(
    'const String certificateVerifyHex = "${HEX.encode(certificateVerify)}";',
  );

  if (finished != null) {
    print('const String finishedHex = "${HEX.encode(finished)}";');
  }

  _logServerHelloFields(serverHello);

  // session.serverArtifactsLogged = true;
  print("✅ Extracted server handshake values from the client side");
}
