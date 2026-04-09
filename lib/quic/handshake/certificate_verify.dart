// lib/handshake/certificate_verify.dart
import 'dart:typed_data';
import 'dart:convert';

import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart';

Uint8List _concat(List<Uint8List> xs) {
  final total = xs.fold(0, (s, b) => s + b.length);
  final out = Uint8List(total);
  int o = 0;
  for (final x in xs) {
    out.setRange(o, o + x.length, x);
    o += x.length;
  }
  return out;
}

Uint8List _u16(int v) => Uint8List.fromList([(v >> 8) & 0xff, v & 0xff]);

/// Converts raw 32-byte EC private scalar into BigInt
BigInt _privToBigInt(Uint8List priv) {
  var hex = priv.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  return BigInt.parse(hex, radix: 16);
}

/// Build CertificateVerify (TLS 1.3)
Uint8List buildCertificateVerify({
  required Uint8List privateKeyBytes, // raw 32-byte scalar
  required Uint8List transcriptHash,
}) {
  // -------------------------------------------------------------
  // Build data to sign
  // -------------------------------------------------------------
  final prefix = Uint8List.fromList(List.filled(64, 0x20));
  final context = utf8.encode("TLS 1.3, server CertificateVerify");
  final zero = Uint8List.fromList([0x00]);

  final toBeSigned = _concat([
    prefix,
    Uint8List.fromList(context),
    zero,
    transcriptHash,
  ]);

  // -------------------------------------------------------------
  // Load ECDSA Private Key (P-256)
  // -------------------------------------------------------------
  final d = _privToBigInt(privateKeyBytes);
  final curve = ECCurve_prime256v1();

  final privKey = ECPrivateKey(d, curve);

  final signer = Signer("SHA-256/ECDSA")
    ..init(true, PrivateKeyParameter(privKey));

  final sig = signer.generateSignature(toBeSigned) as ECSignature;

  // Convert r + s → ASN.1 DER sequence
  final seq = ASN1Sequence(elements: [ASN1Integer(sig.r), ASN1Integer(sig.s)]);

  final der = seq.encode();

  // -------------------------------------------------------------
  // Build handshake message
  // -------------------------------------------------------------
  final body = _concat([
    _u16(0x0403), // ecdsa_secp256r1_sha256
    _u16(der.length),
    Uint8List.fromList(der),
  ]);

  final hdr = Uint8List.fromList([
    0x0F, // CertificateVerify type
    (body.length >> 16) & 0xff,
    (body.length >> 8) & 0xff,
    body.length & 0xff,
  ]);

  return _concat([hdr, body]);
}
