import 'dart:typed_data';

import '../buffer.dart';
import '../frames/quic_frames.dart';
import '../quic_session.dart';

/// =============================================================
/// Parsed QUIC payload result
/// =============================================================
class ParsedQuicPayload {
  final List<QuicFrame> frames;
  final AckFrame? ack;

  ParsedQuicPayload({required this.frames, this.ack});
}

/// =============================================================
/// Parse decrypted QUIC payload into frames
/// =============================================================
ParsedQuicPayload parsePayload(
  Uint8List plaintextPayload,
  QUICSession session,
) {
  print('--- Parsing Decrypted QUIC Payload ---');

  final buffer = QuicBuffer(data: plaintextPayload);
  final frames = <QuicFrame>[];
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

        frames.add(CryptoFrame(offset: offset, data: cryptoData));
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

        print(ackFrame);
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

  return ParsedQuicPayload(frames: frames, ack: ackFrame);
}
