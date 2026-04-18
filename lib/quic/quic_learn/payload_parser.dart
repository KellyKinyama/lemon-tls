import 'dart:typed_data';

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
