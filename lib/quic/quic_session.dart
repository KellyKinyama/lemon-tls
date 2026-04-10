import 'dart:typed_data';

import 'package:hex/hex.dart';

import 'handshake/client_hello.dart';
import 'packet/payload_parser.dart';
import 'quic_keys.dart';

class QUICSession {
  final Uint8List dcid;
  final String address;
  final int port;

  InitialKeys? initialRead;
  InitialKeys? initialWrite;

  int largestPn = -1;
  // State for keys, stream limits, largest PN, etc., would be managed here.

  // ✅ Store the parsed ClientHello here
  ClientHello? clientHello;

  // ✅ TLS handshake transcript (per-session)
  final List<Uint8List> transcript = [];

  Uint8List? clientHelloRaw;

  QUICSession({required this.dcid, required this.address, required this.port});

  // Mock method to simulate processing decrypted frames
  void handleDecryptedPacket(Uint8List plaintext) {
    // In a full implementation, this calls the frame parser and stream handlers.
    print(
      'Session ${HEX.encode(dcid)} received ${plaintext.length} bytes of plaintext.',
    );

    parsePayload(plaintext, this);
  }
}
