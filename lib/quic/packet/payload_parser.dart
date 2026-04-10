import 'dart:typed_data';

import '../buffer.dart';
import '../handshake/client_hello.dart';
import '../handshake/tls_messages.dart';
import '../quic_session.dart';

// #############################################################################
// ## SECTION 1: UTILITY BUFFER CLASS
// #############################################################################

// #############################################################################
// ## SECTION 2: TLS DATA CLASSES
// #############################################################################

// (Other server-side data classes omitted for brevity)

// #############################################################################
// ## SECTION 3: PARSER LOGIC
// #############################################################################

// #############################################################################
// ## SECTION 4: DEMONSTRATION
// #############################################################################

void parsePayload(Uint8List plaintextPayload, QUICSession session) {
  print('--- Parsing Decrypted QUIC Payload ---');
  final buffer = QuicBuffer(data: plaintextPayload);

  try {
    while (!buffer.eof && buffer.byteData.getUint8(buffer.readOffset) != 0) {
      final frameType = buffer.pullVarInt();

      if (frameType == 0x06) {
        final offset = buffer.pullVarInt();
        final length = buffer.pullVarInt();
        final cryptoData = buffer.pullBytes(length);

        print('✅ Parsed CRYPTO Frame: offset=$offset, length=$length');

        final tlsMessages = parseTlsMessages(cryptoData);

        for (final msg in tlsMessages) {
          print(msg);

          if (msg is ClientHello) {
            print("✅ Saving ClientHello in session");

            // STORE PARSED STRUCT
            session.clientHello = msg;

            // STORE RAW BYTES FOR TRANSCRIPT
            session.clientHelloRaw = cryptoData;

            // Add to transcript
            session.transcript.add(cryptoData);
          }
        }
      } else {
        print('ℹ️ Skipping frame type 0x${frameType.toRadixString(16)}');
      }
    }
  } catch (e) {
    print('\n🛑 Error during payload parsing: $e');
  }

  print('\n🎉 Payload parsing complete.');
}

// void main() {
//   // The ClientHello payload from RFC 9001, Appendix A.2
//   final rfcClientHelloPayload =
//       (BytesBuilder()
//             ..add(
//               HEX.decode(
//                 '060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868'
//                 '04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578'
//                 '616d706c652e636f6dff01000100000a00080006001d00170018001000070005'
//                 '04616c706e000500050100000000003300260024001d00209370b2c9caa47fba'
//                 'baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400'
//                 '0d0010000e0403050306030203080408050806002d00020101001c0002400100'
//                 '3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000'
//                 '75300901100f088394c8f03e51570806048000ffff',
//               ),
//             )
//             ..add(Uint8List(920)) // Padding to simulate a real initial packet
//             )
//           .toBytes();

//   print("--- Running with RFC 9001 ClientHello Payload ---");
//   parsePayload(rfcClientHelloPayload);
// }
