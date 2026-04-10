// lib/handshake/certificate_verify.dart
import 'dart:typed_data';
import 'dart:convert';

import 'package:ecdsa/ecdsa.dart';
import 'package:elliptic/elliptic.dart';
import 'package:hex/hex.dart';

Uint8List _concat(List<Uint8List> items) {
  final total = items.fold<int>(0, (s, b) => s + b.length);
  final out = Uint8List(total);
  int o = 0;
  for (final x in items) {
    out.setRange(o, o + x.length, x);
    o += x.length;
  }
  return out;
}

Uint8List _u16(int v) => Uint8List.fromList([(v >> 8) & 0xff, v & 0xff]);

/// ✅ Build TLS 1.3 CertificateVerify using deterministic ECDSA (RFC 6979)
Uint8List buildCertificateVerify({
  required Uint8List privateKeyBytes, // server P‑256 private scalar (32 bytes)
  required Uint8List transcriptHash, // SHA256(CH || SH || EE || Cert)
}) {
  // -------------------------------------------------------------
  // ✅ Construct the *exact* TLS 1.3 "to-be-signed" structure
  // -------------------------------------------------------------
  //
  //  struct {
  //      opaque content[64] = 0x20...;
  //      opaque context_string = "TLS 1.3, server CertificateVerify";
  //      opaque zero_byte = 0x00;
  //      opaque transcript_hash[Hash.length];
  //  } CertificateVerifyInput;
  //
  final prefix = Uint8List.fromList(List.filled(64, 0x20));
  final context = Uint8List.fromList(
    utf8.encode("TLS 1.3, server CertificateVerify"),
  );
  final zero = Uint8List.fromList([0x00]);

  final toBeSigned = _concat([prefix, context, zero, transcriptHash]);

  // -------------------------------------------------------------
  // ✅ Deterministic ECDSA (RFC6979) using package:ecdsa
  // -------------------------------------------------------------
  final priv = PrivateKey.fromBytes(getP256(), privateKeyBytes.toList());

  // The ecdsa package signs arbitrary bytes, so we pass toBeSigned directly
  final sig = signature(priv, toBeSigned);

  // DER encode (TLS 1.3 requires DER ECDSA signatures)
  final der = sig.toASN1();

  // -------------------------------------------------------------
  // ✅ Build CertificateVerify handshake message
  // -------------------------------------------------------------
  //
  //  struct {
  //     SignatureScheme algorithm = 0x0403;
  //     opaque signature<0..2^16-1>;
  //  }
  //
  const int algorithm = 0x0403; // ecdsa_secp256r1_sha256

  final body = _concat([
    _u16(algorithm),
    _u16(der.length),
    Uint8List.fromList(der),
  ]);

  final hdr = Uint8List.fromList([
    0x0F, // HandshakeType::certificate_verify
    (body.length >> 16) & 0xff,
    (body.length >> 8) & 0xff,
    body.length & 0xff,
  ]);

  return _concat([hdr, body]);
}

/// ✅ Optional helper to verify CertificateVerify signatures
bool verifyCertificateVerify({
  required Uint8List publicKeyBytes,
  required Uint8List transcriptHash,
  required Uint8List signatureBytes,
}) {
  final pub = PublicKey.fromHex(getP256(), HEX.encode(publicKeyBytes));
  final sig = Signature.fromASN1(signatureBytes);
  return verify(pub, transcriptHash.toList(), sig);
}
