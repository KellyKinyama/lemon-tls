// ============================================================================
// TLS 1.3 KeyShare – X25519 & P‑256 (secp256r1)
// RFC 8446 §4.2.8
// ============================================================================

import 'dart:typed_data';
import 'package:x25519/x25519.dart';
import 'package:elliptic/elliptic.dart' as elliptic;
import 'package:hex/hex.dart';

/// Result returned by TLS KeyShare generation
class Tls13KeyShareResult {
  Uint8List privateKey = Uint8List(0);
  Uint8List publicKey = Uint8List(0);
  Uint8List sharedSecret = Uint8List(0);
}

class Tls13KeyShare {
  // TLS Named Groups (RFC 8446 §4.2.7)
  static const int x25519 = 0x001D;
  static const int secp256r1 = 0x0017;

  /// Generate server ephemeral keypair + shared secret
  ///
  /// [group] – TLS group (0x001D or 0x0017)
  /// [clientPublicKey] – peer’s public key from ClientHello.key_share
  ///
  /// Returns private key, public key, and shared secret.
  static Tls13KeyShareResult generate({
    required int group,
    required Uint8List clientPublicKey,
  }) {
    final out = Tls13KeyShareResult();

    // ------------------------------------------------------------------------
    // X25519 (Montgomery curve)
    // ------------------------------------------------------------------------
    if (group == x25519) {
      final pair = generateKeyPair(); // from package:x25519

      final Uint8List priv = Uint8List.fromList(pair.privateKey);
      final Uint8List pub = Uint8List.fromList(pair.publicKey);

      final Uint8List shared = Uint8List.fromList(
        X25519(priv, clientPublicKey),
      );

      out.privateKey = priv;
      out.publicKey = pub;
      out.sharedSecret = shared;
      return out;
    }

    // ------------------------------------------------------------------------
    // secp256r1 (P‑256) ECDHE
    // ------------------------------------------------------------------------
    if (group == secp256r1) {
      final ec = elliptic.getP256();
      final privKey = ec.generatePrivateKey();

      final Uint8List priv = Uint8List.fromList(privKey.bytes);

      // Public key in uncompressed SEC1 format (04 || X || Y)
      final Uint8List pub = Uint8List.fromList(
        HEX.decode(privKey.publicKey.toHex()),
      );

      // Convert client public key (raw SEC1 uncompressed) → Elliptic format
      final clientPub = elliptic.PublicKey.fromHex(
        ec,
        HEX.encode(clientPublicKey),
      );

      // Shared secret = x-coordinate of (priv * clientPub)
      final sharedPoint = ec.scalarMul(clientPub, privKey.bytes);

      // TLS 1.3 requires the *x* coordinate, padded to 32 bytes
      final xHex = sharedPoint.X.toRadixString(16).padLeft(64, '0');
      final Uint8List shared = Uint8List.fromList(HEX.decode(xHex));

      out.privateKey = priv;
      out.publicKey = pub;
      out.sharedSecret = shared;
      return out;
    }

    throw Exception(
      "Unsupported TLS 1.3 key share group: 0x${group.toRadixString(16)}",
    );
  }
}
