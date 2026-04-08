// // ============================================================================
// // tls_certificate.dart
// // TLS 1.2 + TLS 1.3 Certificate builder & parser
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
// /// buildCertificate(params)
// /// Matches JS build_certificate()
// /// ---------------------------------------------------------------------------
// Uint8List buildCertificate(Map<String, dynamic> params) {
//   final int version = params['version'] ?? TLSVersion.TLS1_2;

//   // Normalize params.entries
//   List entries;
//   if (params['entries'] is List) {
//     entries = params['entries'];
//   } else if (params['certs'] is List) {
//     // backwards compatibility
//     entries = (params['certs'] as List).map((c) => {'cert': c}).toList();
//   } else {
//     entries = [];
//   }

//   // -------------------------------------------------------------------------
//   // TLS 1.3 Certificate
//   // -------------------------------------------------------------------------
//   if (version == TLSVersion.TLS1_3) {
//     final Uint8List ctx =
//         toU8(params['request_context'] ?? Uint8List(0));

//     final entryParts = <Uint8List>[];

//     for (final e in entries) {
//       final certBytes = toU8(e['cert'] ?? Uint8List(0));
//       final certVec = veclen(3, certBytes); // cert(vec<3>)

//       dynamic extRaw = e['extensions'];
//       Uint8List ex;

//       if (extRaw is List) {
//         ex = buildExtensions(extRaw);
//       } else if (extRaw is Uint8List) {
//         ex = isVec2(extRaw) ? extRaw : veclen(2, extRaw);
//       } else {
//         ex = veclen(2, Uint8List(0));
//       }

//       entryParts.add(certVec);
//       entryParts.add(ex);
//     }

//     final ctxVec = veclen(1, ctx);
//     final listVec = veclen(3, concatUint8Arrays(entryParts));

//     return concatUint8Arrays([ctxVec, listVec]);
//   }

//   // -------------------------------------------------------------------------
//   // TLS 1.2 Certificate
//   // -------------------------------------------------------------------------
//   final certListParts = <Uint8List>[];
//   for (final e in entries) {
//     final c = toU8(e['cert'] ?? Uint8List(0));
//     certListParts.add(veclen(3, c));
//   }

//   return veclen(3, concatUint8Arrays(certListParts));
// }

// /// ---------------------------------------------------------------------------
// /// parseCertificate(body)
// /// Matches JS parse_certificate()
// /// ---------------------------------------------------------------------------
// Map<String, dynamic> parseCertificate(Uint8List body) {
//   // Try TLS 1.3 format:
//   //   ctx(vec<1>) || list(vec<3>)
//   if (body.isNotEmpty && body.length >= 4) {
//     int off = 0;

//     final rcLen = body[off];
//     off += 1;

//     final afterCtx = off + rcLen;
//     if (afterCtx + 3 <= body.length) {
//       int off2 = afterCtx;

//       final rl = r_u24(body, off2);
//       final listLen = rl[0];
//       off2 = rl[1];

//       if (afterCtx + 3 + listLen == body.length) {
//         final requestContext = body.sublist(off, off + rcLen);

//         int off3 = off2;
//         final end = off2 + listLen;

//         final entries = <Map<String, dynamic>>[];

//         while (off3 < end) {
//           final r1 = r_u24(body, off3);
//           final certLen = r1[0];
//           off3 = r1[1];

//           final r2 = r_bytes(body, off3, certLen);
//           final cert = r2[0] as Uint8List;
//           off3 = r2[1];

//           final r3 = r_u16(body, off3);
//           final extLen = r3[0];
//           off3 = r3[1];

//           final r4 = r_bytes(body, off3, extLen);
//           final extRaw = r4[0] as Uint8List;
//           off3 = r4[1];

//           final exts = extLen > 0 ? parseExtensions(extRaw) : [];

//           entries.add({
//             'cert': cert,
//             'extensions': exts,
//           });
//         }

//         return {
//           'version': TLSVersion.TLS1_3,
//           'request_context': requestContext,
//           'entries': entries,
//         };
//       }
//     }
//   }

//   // -------------------------------------------------------------------------
//   // TLS 1.2 fallback parsing
//   // -------------------------------------------------------------------------
//   int off = 0;

//   final rList = r_u24(body, off);
//   final listLen = rList[0];
//   off = rList[1];

//   final end = off + listLen;
//   final entries12 = <Map<String, dynamic>>[];

//   while (off < body.length && off < end) {
//     final r1 = r_u24(body, off);
//     final certLen = r1[0];
//     off = r1[1];

//     final r2 = r_bytes(body, off, certLen);
//     final cert = r2[0] as Uint8List;
//     off = r2[1];

//     entries12.add({'cert': cert});
//   }

//   return {
//     'version': TLSVersion.TLS1_2,
//     'entries': entries12,
//   };
// }

// /// ---------------------------------------------------------------------------
// /// Helper used for isVec2() in tls_vectors.dart
// /// ---------------------------------------------------------------------------
// bool isVec2(Uint8List u8) {
//   if (u8.length < 2) return false;
//   final len = (u8[0] << 8) | u8[1];
//   return u8.length == 2 + len;
// }