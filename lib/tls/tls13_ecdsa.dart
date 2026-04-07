import 'dart:typed_data';
import 'package:ecdsa/ecdsa.dart';
import 'package:elliptic/elliptic.dart';

Uint8List tls13EcdsaSign(Uint8List privateKeyBytes, Uint8List hash) {
  final curve = getP256();
  final priv = PrivateKey.fromBytes(curve, privateKeyBytes);

  final sig = signature(priv, hash); // RFC6979 deterministic
  final asn1 = sig.toASN1(); // DER encoding required by TLS 1.3

  return Uint8List.fromList(asn1);
}
