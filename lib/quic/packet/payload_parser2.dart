import 'dart:typed_data';

import '../buffer.dart';
import '../frames/quic_frames.dart';
import '../handshake/certificate.dart';
import '../handshake/client_hello.dart';
import '../handshake/encrypted_extensions.dart';
import '../handshake/finished.dart';
import '../handshake/server_hello.dart';
import '../handshake/tls_messages.dart';
import '../quic_session.dart';

/// Returns a tuple: (frames, ackInfo, metadata)
(dynamic, dynamic, {int? largest, int? firstRange, int? delay, String? type})
parsePayload(Uint8List plaintextPayload, QUICSession session) {
  print('--- Parsing Decrypted QUIC Payload ---');
  final buffer = QuicBuffer(data: plaintextPayload);

  final frames = <dynamic>[]; // ← the FIX: collect frames here
  dynamic ackInfo;
  int? largestPn;
  int? firstRange;
  int? delayField;

  try {
    while (!buffer.eof && buffer.byteData.getUint8(buffer.readOffset) != 0) {
      final frameType = buffer.pullVarInt();

      // ---------------------------------------------------------
      // ✅ CRYPTO FRAME
      // ---------------------------------------------------------
      if (frameType == 0x06) {
        final offset = buffer.pullVarInt();
        final length = buffer.pullVarInt();
        final cryptoData = buffer.pullBytes(length);

        print('✅ Parsed CRYPTO Frame: offset=$offset, length=$length');

        frames.add(CryptoFrame(offset: offset, data: cryptoData));
      }
      // ---------------------------------------------------------
      // ✅ ACK FRAME
      // ---------------------------------------------------------
      else if (frameType == 0x02) {
        final hasECN = (frameType & 0x01) == 0x01;
        largestPn = buffer.pullVarInt();
        delayField = buffer.pullVarInt();
        final rangeCount = buffer.pullVarInt();
        firstRange = buffer.pullVarInt();

        final ranges = [];
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

        ackInfo = (
          type: 'ack',
          largest: largestPn,
          delay: delayField,
          firstRange: firstRange,
          ranges: ranges,
          ecn: ecn,
        );

        print(ackInfo);
        frames.add(ackInfo);
      }
      // ---------------------------------------------------------
      // ✅ SKIP FRAME
      // ---------------------------------------------------------
      else {
        print('ℹ️ Skipping frame type 0x${frameType.toRadixString(16)}');
      }
    }
  } catch (e, st) {
    print('\n🛑 Error during payload parsing: $e,\nStack trace: $st');
  }

  print('\n🎉 Payload parsing complete.');

  return (
    frames,
    ackInfo,
    largest: largestPn,
    firstRange: firstRange,
    delay: delayField,
    type: ackInfo == null ? null : 'ack',
  );
}
