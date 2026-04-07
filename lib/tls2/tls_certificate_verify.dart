// ============================================================================
// TLS 1.3 CertificateVerify
// RFC 8446 §4.4.3
//
// struct {
//    SignatureScheme algorithm;
//    opaque signature<0..2^16-1>;
// } CertificateVerify;
// ============================================================================

import 'dart:typed_data';
import 'dart:convert';

import '../tls/crypto_hash.dart';
import '../tls/ecdsa.dart';
import 'utils.dart';

// ============================================================================
// BUILD CERTIFICATEVERIFY (TLS 1.3 SERVER)
// ============================================================================
//
// Inputs:
//   privateKey   : server ECDSA private key (P-256 raw bytes)
//   transcriptHash : Hash of all handshake messages up to Certificate
//
// The signed structure is:
//
//   "TLS 1.3, server CertificateVerify" || 0x00 || transcript_hash
//
// Output: CertificateVerify handshake body
// ============================================================================

Uint8List buildCertificateVerify({
  required Uint8List privateKey,
  required Uint8List transcriptHash,
}) {
  // --------------------------------------------------------------------------
  // RFC 8446: context string
  // --------------------------------------------------------------------------
  final context = utf8.encode("TLS 1.3, server CertificateVerify");

  final toSign = Uint8List.fromList([...context, 0x00, ...transcriptHash]);

  // Hash it
  final hashed = createHash(toSign);

  // Produce deterministic ECDSA signature (DER encoded)
  final signature = tls13EcdsaSign(privateKey, hashed);

  // Build CertificateVerify structure
  final out = Uint8List(2 + 2 + signature.length);
  int off = 0;

  // algorithm = 0x0403 (ecdsa_secp256r1_sha256)
  off = w_u16(out, off, 0x0403);

  // signature length
  off = w_u16(out, off, signature.length);

  // signature bytes
  off = w_bytes(out, off, signature);

  return out;
}

// ============================================================================
// PARSE CERTIFICATEVERIFY (for future client-side support)
// ============================================================================
//
// Returns:
//   {
//      "scheme": int,
//      "signature": Uint8List
//   }
//
// Note: does NOT verify the signature (server-only component here)
// ============================================================================

Map<String, dynamic> parseCertificateVerify(Uint8List body) {
  int off = 0;

  final algR = r_u16(body, off);
  final scheme = algR[0];
  off = algR[1];

  final lenR = r_u16(body, off);
  final sigLen = lenR[0];
  off = lenR[1];

  final sigR = r_bytes(body, off, sigLen);
  final Uint8List signature = sigR[0];
  off = sigR[1];

  return {"scheme": scheme, "signature": signature};
}
