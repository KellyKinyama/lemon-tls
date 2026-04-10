import 'dart:math' as math;
import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:x25519/x25519.dart';

import 'crypto.dart';
import 'handshake/client_hello.dart';
import 'packet/payload_parser.dart';
import 'quic_keys.dart';

import 'package:elliptic/elliptic.dart';
import 'package:elliptic/ecdh.dart';

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

  // X25519 ephemeral keypair
  late QuicKeyPair x25519;

  // P‑256 ephemeral keypair
  late Uint8List p256Priv;
  late Uint8List p256Pub;

  // 32‑byte TLS server_random
  late Uint8List serverRandom;

  QUICSession({required this.dcid, required this.address, required this.port}) {
    x25519 = QuicKeyPair.generate();

    var aliceKeyPair = generateKeyPair();
    // Generate P‑256 keypair
    p256Priv = Uint8List.fromList(aliceKeyPair.privateKey);
    p256Pub = Uint8List.fromList(aliceKeyPair.publicKey);

    // if (p256Pub.length != 65 || p256Pub[0] != 0x04) {
    //   throw Exception(
    //     "Generated P-256 pubkey must be uncompressed (65 bytes).",
    //   );
    // }

    // Random bytes for ServerHello
    final rnd = math.Random.secure();
    serverRandom = Uint8List.fromList(
      List.generate(32, (_) => rnd.nextInt(256)),
    );
  }

  // Mock method to simulate processing decrypted frames
  void handleDecryptedPacket(Uint8List plaintext) {
    // In a full implementation, this calls the frame parser and stream handlers.
    print(
      'Session ${HEX.encode(dcid)} received ${plaintext.length} bytes of plaintext.',
    );

    parsePayload(plaintext, this);
  }
}
