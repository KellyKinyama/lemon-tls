// ============================================================================
// tls_certificate_verify.dart
// TLS CertificateVerify (TLS 1.2 / 1.3 share same wire format)
// Direct Dart translation of JS build_certificate_verify() & parse_certificate_verify()
// ============================================================================

import 'dart:typed_data';

import 'tls_utils.dart';
import 'tls_write.dart';
import 'tls_read.dart';

/// ---------------------------------------------------------------------------
/// Build CertificateVerify
/// struct {
///   SignatureScheme algorithm;   // u16
///   opaque signature<0..2^16-1>; // vec<2>
/// } CertificateVerify
/// ---------------------------------------------------------------------------
Uint8List buildCertificateVerify(int scheme, dynamic signature) {
  final Uint8List sig = toU8(signature ?? Uint8List(0));
  final int alg = scheme;

  final out = Uint8List(2 + 2 + sig.length);
  int off = 0;

  off = w_u16(out, off, alg);
  off = w_u16(out, off, sig.length);
  off = w_bytes(out, off, sig);

  return out;
}

/// ---------------------------------------------------------------------------
/// Parse CertificateVerify
/// Returns: { 'scheme': int, 'signature': Uint8List }
/// ---------------------------------------------------------------------------
Map<String, dynamic> parseCertificateVerify(Uint8List body) {
  int off = 0;

  final r1 = r_u16(body, off);
  final scheme = r1[0];
  off = r1[1];

  final r2 = r_u16(body, off);
  final sigLen = r2[0];
  off = r2[1];

  final r3 = r_bytes(body, off, sigLen);
  final signature = r3[0] as Uint8List;
  off = r3[1];

  return {
    'scheme': scheme,
    'signature': signature,
  };
}