// ===========================================================
// TLS 1.3 KeySchedule
// ===========================================================

import 'dart:typed_data';
// import '../crypto/hkdf.dart';
// import '../crypto/crypto_utils.dart';
import '../hkdf.dart';

class Tls13KeySchedule {
  late Uint8List earlySecret;
  late Uint8List handshakeSecret;
  late Uint8List masterSecret;

  late Uint8List clientHandshakeTrafficSecret;
  late Uint8List serverHandshakeTrafficSecret;

  late Uint8List clientAppTrafficSecret;
  late Uint8List serverAppTrafficSecret;

  late Uint8List clientHandshakeKey;
  late Uint8List serverHandshakeKey;

  late Uint8List clientHandshakeIV;
  late Uint8List serverHandshakeIV;

  late Uint8List clientAppKey;
  late Uint8List serverAppKey;

  late Uint8List clientAppIV;
  late Uint8List serverAppIV;

  Uint8List deriveSecret(Uint8List secret, String label, Uint8List ctx) {
    return hkdfExpandLabel(secret, ctx, label, 32);
  }

  void computeHandshakeSecrets({
    required Uint8List sharedSecret,
    required Uint8List helloHash,
  }) {
    earlySecret = hkdfExtract(Uint8List(0), salt: Uint8List(32));

    handshakeSecret = hkdfExtract(
      sharedSecret,
      salt: deriveSecret(earlySecret, "derived", Uint8List(0)),
    );

    clientHandshakeTrafficSecret = deriveSecret(
      handshakeSecret,
      "c hs traffic",
      helloHash,
    );

    serverHandshakeTrafficSecret = deriveSecret(
      handshakeSecret,
      "s hs traffic",
      helloHash,
    );

    clientHandshakeKey = hkdfExpandLabel(
      clientHandshakeTrafficSecret,
      Uint8List(0),
      "key",
      16,
    );
    serverHandshakeKey = hkdfExpandLabel(
      serverHandshakeTrafficSecret,
      Uint8List(0),
      "key",
      16,
    );

    clientHandshakeIV = hkdfExpandLabel(
      clientHandshakeTrafficSecret,
      Uint8List(0),
      "iv",
      12,
    );
    serverHandshakeIV = hkdfExpandLabel(
      serverHandshakeTrafficSecret,
      Uint8List(0),
      "iv",
      12,
    );
  }

  void computeApplicationSecrets(Uint8List hash) {
    masterSecret = hkdfExtract(
      Uint8List(0),
      salt: deriveSecret(handshakeSecret, "derived", Uint8List(0)),
    );

    clientAppTrafficSecret = deriveSecret(masterSecret, "c ap traffic", hash);

    serverAppTrafficSecret = deriveSecret(masterSecret, "s ap traffic", hash);

    clientAppKey = hkdfExpandLabel(
      clientAppTrafficSecret,
      Uint8List(0),
      "key",
      16,
    );
    serverAppKey = hkdfExpandLabel(
      serverAppTrafficSecret,
      Uint8List(0),
      "key",
      16,
    );

    clientAppIV = hkdfExpandLabel(
      clientAppTrafficSecret,
      Uint8List(0),
      "iv",
      12,
    );
    serverAppIV = hkdfExpandLabel(
      serverAppTrafficSecret,
      Uint8List(0),
      "iv",
      12,
    );
  }
}
