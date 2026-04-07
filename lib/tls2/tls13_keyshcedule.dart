// ============================================================================
// TLS 1.3 Key Schedule (RFC 8446 §7)
// - Uses HKDF-Extract and HKDF-Expand-Label
// - Supports Handshake + Application traffic secrets
// - Produces AEAD keys and IVs for record layer
// ============================================================================

import 'dart:typed_data';

import '../hkdf.dart';         // <-- your HKDF implementation

class Tls13KeySchedule {
  // ==========================================================================
  // Secrets (RFC 8446 terminology)
  // ==========================================================================

  late Uint8List earlySecret;                   // HKDF-Extract(0, 0)
  late Uint8List handshakeSecret;               // HKDF-Extract(ecdhe, derived)
  late Uint8List masterSecret;                  // HKDF-Extract(0, derived)

  late Uint8List clientHandshakeTrafficSecret;  // c hs traffic
  late Uint8List serverHandshakeTrafficSecret;  // s hs traffic

  late Uint8List clientAppTrafficSecret;        // c ap traffic
  late Uint8List serverAppTrafficSecret;        // s ap traffic

  // AEAD keys/IVs
  late Uint8List clientHandshakeKey;
  late Uint8List serverHandshakeKey;

  late Uint8List clientHandshakeIV;
  late Uint8List serverHandshakeIV;

  late Uint8List clientAppKey;
  late Uint8List serverAppKey;

  late Uint8List clientAppIV;
  late Uint8List serverAppIV;

  // ========================================================================
  // HKDF Label Helper (RFC 8446 §7.1)
  // ========================================================================
  Uint8List _hkdfExpandLabel(
      Uint8List secret, String label, Uint8List context, int len) {
    return hkdfExpandLabel(secret, context, label, len);
  }

  // ========================================================================
  // Derive-Secret(secret, label, context)
  // ========================================================================
  Uint8List deriveSecret(Uint8List secret, String label, Uint8List context) {
    return _hkdfExpandLabel(secret, label, context, 32);
  }

  // ========================================================================
  // Compute Handshake Secrets (after ServerHello)
  // ========================================================================
  void computeHandshakeSecrets({
    required Uint8List sharedSecret,  // result of ECDHE
    required Uint8List helloHash,     // Hash(ClientHello || ServerHello)
  }) {
    // RFC 8446: early_secret = HKDF-Extract(0, 0)
    earlySecret = hkdfExtract(Uint8List(0), salt: Uint8List(32));

    // handshake_secret = HKDF-Extract(shared_secret, Derive-Secret(early, "derived", ""))
    final derived = deriveSecret(earlySecret, "derived", Uint8List(0));

    handshakeSecret = hkdfExtract(sharedSecret, salt: derived);

    // traffic secrets
    clientHandshakeTrafficSecret =
        deriveSecret(handshakeSecret, "c hs traffic", helloHash);

    serverHandshakeTrafficSecret =
        deriveSecret(handshakeSecret, "s hs traffic", helloHash);

    // AEAD keys & IVs (AES-128-GCM)
    clientHandshakeKey =
        _hkdfExpandLabel(clientHandshakeTrafficSecret, "key", Uint8List(0), 16);
    serverHandshakeKey =
        _hkdfExpandLabel(serverHandshakeTrafficSecret, "key", Uint8List(0), 16);

    clientHandshakeIV =
        _hkdfExpandLabel(clientHandshakeTrafficSecret, "iv", Uint8List(0), 12);
    serverHandshakeIV =
        _hkdfExpandLabel(serverHandshakeTrafficSecret, "iv", Uint8List(0), 12);
  }

  // ========================================================================
  // Compute Application Traffic Secrets (after Finished)
  // ========================================================================
  void computeApplicationSecrets(Uint8List transcriptHash) {
    // master_secret = HKDF-Extract(0, Derive-Secret(handshake_secret, "derived", ""))
    final derived = deriveSecret(handshakeSecret, "derived", Uint8List(0));
    masterSecret = hkdfExtract(Uint8List(0), salt: derived);

    clientAppTrafficSecret =
        deriveSecret(masterSecret, "c ap traffic", transcriptHash);

    serverAppTrafficSecret =
        deriveSecret(masterSecret, "s ap traffic", transcriptHash);

    clientAppKey =
        _hkdfExpandLabel(clientAppTrafficSecret, "key", Uint8List(0), 16);
    serverAppKey =
        _hkdfExpandLabel(serverAppTrafficSecret, "key", Uint8List(0), 16);

    clientAppIV =
        _hkdfExpandLabel(clientAppTrafficSecret, "iv", Uint8List(0), 12);
    serverAppIV =
        _hkdfExpandLabel(serverAppTrafficSecret, "iv", Uint8List(0), 12);
  }
}
