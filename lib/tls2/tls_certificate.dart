// ============================================================================
// TLS 1.3 Certificate Message
// RFC 8446 §4.4.2
//
// struct {
//    opaque certificate_request_context<0..2^8-1>;
//    CertificateEntry certificate_list<0..2^24-1>;
// } Certificate;
//
// struct {
//    opaque cert_data<1..2^24-1>;
//    Extension extensions<0..2^16-1>;
// } CertificateEntry;
// ============================================================================

import 'dart:typed_data';

import 'tls_extensions.dart';
import 'utils.dart';
import 'tls_constants.dart';


/// ----------------------------------------------------------------------------
/// Build TLS 1.3 Certificate message
/// ----------------------------------------------------------------------------
/// Params:
/// {
///   "version": TLSVersion.TLS1_3,
///   "request_context": Uint8List,
///   "entries": [
///       {
///         "cert": Uint8List,          // DER certificate
///         "extensions": [] or Uint8List
///       }
///   ]
/// }
///
/// Returns: the TLS 1.3 Certificate handshake body.
///
/// ----------------------------------------------------------------------------

Uint8List buildCertificate(Map<String, dynamic> params) {
  final version = params["version"] ?? TLSVersion.TLS1_3;

  if (version != TLSVersion.TLS1_3) {
    throw Exception(
      "TLS 1.2 Certificate not supported here (this is TLS 1.3 only)",
    );
  }

  // ---------------------------------------------------------
  // Request context (server usually sends empty)
  // ---------------------------------------------------------
  final Uint8List context = toU8(params["request_context"] ?? Uint8List(0));

  final ctxVec = veclen(1, context);

  // ---------------------------------------------------------
  // Certificate entries
  // ---------------------------------------------------------
  final entries = (params["entries"] as List?) ?? [];

  final parts = <Uint8List>[];

  for (final e in entries) {
    // cert_data is a vec<3>
    final Uint8List certData = toU8(e["cert"]);
    final certVec = veclen(3, certData);

    // extensions is a vec<2>
    dynamic ext = e["extensions"];

    Uint8List extBytes;

    if (ext == null) {
      extBytes = veclen(2, Uint8List(0));
    } else if (ext is Uint8List) {
      // ensure vec<2>
      if (isVec2(ext)) {
        extBytes = ext;
      } else {
        extBytes = veclen(2, ext);
      }
    } else if (ext is List) {
      // extension list → vec<2>
      extBytes = buildExtensions(ext.cast<Map<String, dynamic>>());
    } else {
      extBytes = veclen(2, Uint8List(0));
    }

    parts.add(certVec);
    parts.add(extBytes);
  }

  // certificate_list is a vec<3>
  final listVec = veclen(3, concatUint8Arrays(parts));

  // Final TLS 1.3 Certificate message
  return concatUint8Arrays([ctxVec, listVec]);
}

/// ----------------------------------------------------------------------------
/// Parse TLS 1.3 Certificate message
/// ----------------------------------------------------------------------------
/// Returns:
/// {
///   "version": TLSVersion.TLS1_3,
///   "request_context": Uint8List,
///   "entries": [
///      { "cert": Uint8List, "extensions": [...] }
///   ]
/// }
///
/// ----------------------------------------------------------------------------

Map<String, dynamic> parseCertificate(Uint8List body) {
  int off = 0;

  // request_context <1>
  final ctxRes = readVec(body, off, 1);
  final requestContext = ctxRes[0] as Uint8List;
  off = ctxRes[1];

  // certificate_list <3>
  final listRes = readVec(body, off, 3);
  final certListBytes = listRes[0] as Uint8List;
  off = listRes[1];

  int p = 0;
  final entries = <Map<String, dynamic>>[];

  while (p < certListBytes.length) {
    // cert_data <3>
    final r1 = r_u24(certListBytes, p);
    final certLen = r1[0];
    p = r1[1];

    final r2 = r_bytes(certListBytes, p, certLen);
    final Uint8List cert = r2[0];
    p = r2[1];

    // extensions <2>
    final r3 = r_u16(certListBytes, p);
    final extLen = r3[0];
    p = r3[1];

    final r4 = r_bytes(certListBytes, p, extLen);
    final Uint8List extRaw = r4[0];
    p = r4[1];

    final exts = (extLen > 0) ? parseExtensions(extRaw) : [];

    entries.add({"cert": cert, "extensions": exts});
  }

  return {
    "version": TLSVersion.TLS1_3,
    "request_context": requestContext,
    "entries": entries,
  };
}

/// ----------------------------------------------------------------------------
/// Helper: check vec<2>
/// ----------------------------------------------------------------------------

bool isVec2(Uint8List u8) {
  if (u8.length < 2) return false;
  final len = (u8[0] << 8) | u8[1];
  return (2 + len) == u8.length;
}

