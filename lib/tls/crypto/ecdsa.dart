// ===============================================================
// TLS 1.3 ECDSA Signer (safe utility)
// ===============================================================

import 'dart:typed_data';
import 'package:ecdsa/ecdsa.dart';
import 'package:elliptic/elliptic.dart';

Uint8List tls13EcdsaSign(
  Uint8List privateKeyBytes,
  Uint8List hash,
) {
  final curve = getP256();
  final priv = PrivateKey.fromBytes(curve, privateKeyBytes);

  final sig = signature(priv, hash);
  return Uint8List.fromList(sig.toASN1());  // DER encoding
}