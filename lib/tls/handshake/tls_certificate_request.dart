// // ============================================================================
// // tls_certificate_request.dart
// // TLS 1.3 + TLS 1.2 CertificateRequest builder & parser
// // Direct Dart translation of original JavaScript code
// // ============================================================================

// import 'dart:typed_data';

// import 'tls_constants.dart';
// import 'tls_utils.dart';
// import 'tls_read.dart';
// import 'tls_write.dart';
// import 'tls_vectors.dart';
// import 'tls_extensions.dart';

// /// ---------------------------------------------------------------------------
// /// buildCertificateRequest(params)
// /// TLS 1.3:
// ///   opaque certificate_request_context<0..2^8-1>
// ///   Extension extensions<0..2^16-1>
// /// TLS 1.2:
// ///   certificate_types<1>
// ///   signature_algorithms<2> (optional)
// ///   certificate_authorities<2>
// /// ---------------------------------------------------------------------------
// Uint8List buildCertificateRequest(Map<String, dynamic> params) {
//   final int version = params['version'] ?? TLSVersion.TLS1_3;

//   // -------------------------------------------------------------------------
//   // TLS 1.3 CertificateRequest
//   // -------------------------------------------------------------------------
//   if (version == TLSVersion.TLS1_3) {
//     final Uint8List ctx =
//         toU8(params['request_context'] ?? Uint8List(0));

//     final Uint8List extsBuf =
//         (params['extensions'] is List)
//             ? buildExtensions(params['extensions'])
//             : (params['extensions'] is Uint8List
//                 ? params['extensions']
//                 : buildExtensions([]));

//     final ctxVec = veclen(1, ctx);
//     return concatUint8Arrays([ctxVec, extsBuf]);
//   }

//   // -------------------------------------------------------------------------
//   // TLS 1.2 CertificateRequest
//   // -------------------------------------------------------------------------

//   // certificate_types (vec<1>)
//   final List ctList = params['certificate_types'] ?? [1]; // default rsa_sign
//   final ctBytes = Uint8List(ctList.length);
//   for (int i = 0; i < ctList.length; i++) {
//     ctBytes[i] = ctList[i] & 0xFF;
//   }
//   final ctVec = veclen(1, ctBytes);

//   // signature_algorithms (vec<2>, optional)
//   final List sigalgs = params['signature_algorithms'] ?? [];
//   Uint8List sigVec;
//   if (sigalgs.isNotEmpty) {
//     final tmp = Uint8List(sigalgs.length * 2);
//     int o = 0;
//     for (final a in sigalgs) {
//       o = w_u16(tmp, o, a);
//     }
//     sigVec = veclen(2, tmp);
//   } else {
//     sigVec = Uint8List(0);
//   }

//   // certificate_authorities (vec<2>)
//   final List cas = params['certificate_authorities'] ?? [];
//   final caParts = <Uint8List>[];
//   int caTotal = 0;

//   for (final dnRaw in cas) {
//     final dn = toU8(dnRaw);
//     final ent = Uint8List(2 + dn.length);
//     int off = 0;
//     off = w_u16(ent, off, dn.length);
//     off = w_bytes(ent, off, dn);
//     caParts.add(ent);
//     caTotal += ent.length;
//   }

//   final caVec = veclen(
//     2,
//     caParts.isNotEmpty ? concatUint8Arrays(caParts) : Uint8List(0),
//   );

//   return concatUint8Arrays([ctVec, sigVec, caVec]);
// }

// /// ---------------------------------------------------------------------------
// /// parseCertificateRequest(body)
// ///
// /// TLS 1.3:
// ///   ctx<1> + extensions<2>
// /// TLS 1.2:
// ///   certificate_types<1>
// ///   signature_algorithms<2>
// ///   certificate_authorities<2>
// /// ---------------------------------------------------------------------------
// Map<String, dynamic> parseCertificateRequest(Uint8List body) {
//   // -------------------------------------------------------------------------
//   // Try TLS 1.3 format:
//   // ctxLen + ctx + extLen + extensions
//   // -------------------------------------------------------------------------
//   if (body.length >= 3) {
//     final int ctxLen = body[0];
//     if (1 + ctxLen + 2 <= body.length) {
//       final extLen =
//           ((body[1 + ctxLen] << 8) | body[2 + ctxLen]) & 0xFFFF;

//       if (1 + ctxLen + 2 + extLen == body.length) {
//         final requestContext = body.sublist(1, 1 + ctxLen);
//         final extBuf = body.sublist(1 + ctxLen + 2);

//         return {
//           'version': TLSVersion.TLS1_3,
//           'request_context': requestContext,
//           'extensions': parseExtensions(extBuf),
//         };
//       }
//     }
//   }

//   // -------------------------------------------------------------------------
//   // TLS 1.2 / TLS 1.1 / TLS 1.0 parsing
//   // -------------------------------------------------------------------------
//   int off = 0;

//   // certificate_types<1>
//   final r1 = readVec(body, off, 1);
//   final Uint8List typesBytes = r1[0];
//   off = r1[1];

//   final certificateTypes = <int>[];
//   for (final b in typesBytes) {
//     certificateTypes.add(b & 0xFF);
//   }

//   // signature_algorithms<2> (optional)
//   final signatureAlgorithms = <int>[];
//   if (off + 2 <= body.length) {
//     final sigLen = ((body[off] << 8) | body[off + 1]) & 0xFFFF;
//     if (off + 2 + sigLen <= body.length) {
//       off += 2;
//       final end = off + sigLen;

//       while (off < end) {
//         final r = r_u16(body, off);
//         signatureAlgorithms.add(r[0]);
//         off = r[1];
//       }
//     }
//   }

//   // certificate_authorities<2>
//   final cas = <Uint8List>[];
//   if (off + 2 <= body.length) {
//     final r2 = r_u16(body, off);
//     final caLen = r2[0];
//     off = r2[1];

//     final end = off + caLen;
//     while (off < end) {
//       final r3 = r_u16(body, off);
//       final dnLen = r3[0];
//       off = r3[1];

//       final r4 = r_bytes(body, off, dnLen);
//       final dn = r4[0] as Uint8List;
//       off = r4[1];

//       cas.add(dn);
//     }
//   }

//   return {
//     'version': TLSVersion.TLS1_2,
//     'certificate_types': certificateTypes,
//     'signature_algorithms': signatureAlgorithms,
//     'certificate_authorities': cas,
//   };
// }
