// // ===========================================================
// // TLS 1.3 ECDHE KeyShare (X25519 + P-256)  — consolidated version
// // ===========================================================

// import 'dart:typed_data';
// import 'package:elliptic/elliptic.dart' as elliptic;
// import 'package:hex/hex.dart';
// import 'package:x25519/x25519.dart';
// // import '../crypto/x25519.dart'; // your X25519 implementation

// class TlsKeyShareResult {
//   Uint8List privateKey = Uint8List(0);
//   Uint8List publicKey = Uint8List(0);
//   Uint8List sharedSecret = Uint8List(0);
// }

// class TlsKeyShare {
//   static TlsKeyShareResult generate({
//     required int group,
//     required Uint8List? clientPublicKey,
//   }) {
//     final out = TlsKeyShareResult();

//     // -------------------------------------------------------
//     // X25519 (group 0x001D)
//     // -------------------------------------------------------
//     if (group == 0x001d) {
//       if (clientPublicKey != null) {
//         // Server ephemeral keys
//         final pair = generateKeyPair();
//         final priv = Uint8List.fromList(pair.privateKey);
//         final pub = Uint8List.fromList(pair.publicKey);

//         final shared = Uint8List.fromList(X25519(priv, clientPublicKey));

//         out.privateKey = priv;
//         out.publicKey = pub;
//         out.sharedSecret = shared;
//       }
//       return out;
//     }

//     // -------------------------------------------------------
//     // P‑256 (secp256r1, group 0x0017)
//     // -------------------------------------------------------
//     if (group == 0x0017) {
//       final ec = elliptic.getP256();
//       final privKey = ec.generatePrivateKey();

//       final privBytes = Uint8List.fromList(privKey.bytes);
//       final pubBytes = Uint8List.fromList(
//         HEX.decode(privKey.publicKey.toHex()),
//       );

//       if (clientPublicKey != null) {
//         final clientPub = elliptic.PublicKey.fromHex(
//           ec,
//           HEX.encode(clientPublicKey),
//         );

//         final sharedPoint = ec.scalarMul(clientPub, privKey.bytes);
//         final xHex = sharedPoint.X.toRadixString(16).padLeft(64, '0');
//         final sharedSecret = Uint8List.fromList(HEX.decode(xHex));

//         out.privateKey = privBytes;
//         out.publicKey = pubBytes;
//         out.sharedSecret = sharedSecret;
//       }

//       return out;
//     }

//     throw Exception("Unsupported group: $group");
//   }
// }
