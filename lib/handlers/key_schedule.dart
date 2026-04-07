import 'dart:typed_data';

import '../hkdf.dart';
// import 'hkdf.dart';            // ✅ your HKDF file
// import 'crypto_utils.dart';    // ✅ your SHA256 + HMAC file

class Tls13KeySchedule {
  Uint8List earlySecret = Uint8List(32);
  Uint8List handshakeSecret = Uint8List(32);
  Uint8List masterSecret = Uint8List(32);

  Uint8List clientHandshakeTrafficSecret = Uint8List(32);
  Uint8List serverHandshakeTrafficSecret = Uint8List(32);

  Uint8List clientAppTrafficSecret = Uint8List(32);
  Uint8List serverAppTrafficSecret = Uint8List(32);

  Uint8List clientHandshakeKey = Uint8List(16);
  Uint8List serverHandshakeKey = Uint8List(16);

  Uint8List clientHandshakeIV = Uint8List(12);
  Uint8List serverHandshakeIV = Uint8List(12);

  Uint8List clientAppKey = Uint8List(16);
  Uint8List serverAppKey = Uint8List(16);

  Uint8List clientAppIV = Uint8List(12);
  Uint8List serverAppIV = Uint8List(12);

  /// RFC 8446: Derive-Secret(PRK, Label, TranscriptHash)
  Uint8List deriveSecret(
    Uint8List secret,
    String label,
    Uint8List transcriptHash,
  ) {
    return hkdfExpandLabel(secret, transcriptHash, label, 32);
  }

  /// Called after generating the ECDHE shared secret from key_share
  void computeHandshakeSecrets({
    required Uint8List sharedSecret, // ECDHE
    required Uint8List helloHash, // transcript(ClientHello + ServerHello)
  }) {
    // ----- 1. early_secret -----
    earlySecret = hkdfExtract(
      Uint8List(0), // ikm = 0
      salt: Uint8List(32), // all-zero salt
    );

    // ----- 2. handshake_secret -----
    handshakeSecret = hkdfExtract(
      sharedSecret,
      salt: deriveSecret(earlySecret, "derived", Uint8List(0)),
    );

    // ----- 3. handshake traffic secrets -----
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

    // ----- 4. handshake keys+IV -----
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

  /// Called after verifying client Finished
  void computeApplicationSecrets(Uint8List transcriptHash) {
    masterSecret = hkdfExtract(
      Uint8List(0),
      salt: deriveSecret(handshakeSecret, "derived", Uint8List(0)),
    );

    clientAppTrafficSecret = deriveSecret(
      masterSecret,
      "c ap traffic",
      transcriptHash,
    );
    serverAppTrafficSecret = deriveSecret(
      masterSecret,
      "s ap traffic",
      transcriptHash,
    );

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
