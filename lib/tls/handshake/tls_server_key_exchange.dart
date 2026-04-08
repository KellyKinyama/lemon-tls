// // ============================================================================
// // tls_server_key_exchange.dart
// // TLS 1.2 ServerKeyExchange (ECDHE + DHE) builder & parser
// // Direct Dart translation of original JavaScript code
// // ============================================================================

// import 'dart:typed_data';

// import 'tls_utils.dart';
// import 'tls_write.dart';
// import 'tls_read.dart';
// import 'tls_vectors.dart';

// /// ---------------------------------------------------------------------------
// /// buildServerKeyExchangeECDHE(...)
// ///
// /// Parameters:
// /// {
// ///   group: int,
// ///   public: Uint8List | String,
// ///   sig_alg: int,
// ///   signature: Uint8List | String
// /// }
// ///
// /// Produces:
// ///   curve_type(1)=3,
// ///   named_group(2),
// ///   ec_point_length(1),
// ///   ec_point(bytes),
// ///   SignatureScheme(2),
// ///   signature_length(2),
// ///   signature(bytes)
// /// ---------------------------------------------------------------------------
// Uint8List buildServerKeyExchangeECDHE(Map<String, dynamic> p) {
//   final Uint8List pub = toU8(p['public'] ?? u8(0));

//   final head = Uint8List(1 + 2 + 1 + pub.length);
//   int off = 0;

//   off = w_u8(head, off, 3);                        // curve_type = named_curve
//   off = w_u16(head, off, (p['group'] as int));     // named_group
//   off = w_u8(head, off, pub.length);               // ec_point length
//   off = w_bytes(head, off, pub);

//   final Uint8List sig = toU8(p['signature'] ?? u8(0));

//   final sigPart = Uint8List(2 + 2 + sig.length);
//   int off2 = 0;

//   off2 = w_u16(sigPart, off2, (p['sig_alg'] as int));
//   off2 = w_u16(sigPart, off2, sig.length);
//   off2 = w_bytes(sigPart, off2, sig);

//   return concatUint8Arrays([head, sigPart]);
// }

// /// ---------------------------------------------------------------------------
// /// parseServerKeyExchange(...)
// ///
// /// Returns either:
// ///
// ///   {
// ///     'kex': 'ECDHE',
// ///     'group': int,
// ///     'public': Uint8List,
// ///     'sig_alg': int,
// ///     'signature': Uint8List
// ///   }
// ///
// /// OR for DHE:
// ///
// ///   {
// ///     'kex': 'DHE',
// ///     'dh_p': Uint8List,
// ///     'dh_g': Uint8List,
// ///     'dh_Ys': Uint8List,
// ///     'sig_alg': int,
// ///     'signature': Uint8List
// ///   }
// ///
// /// ---------------------------------------------------------------------------
// Map<String, dynamic> parseServerKeyExchange(Uint8List body) {
//   int off = 0;

//   final rCurve = r_u8(body, off);
//   final curveType = rCurve[0];
//   off = rCurve[1];

//   // -------------------------------------------------------------------------
//   // ECDHE form
//   // -------------------------------------------------------------------------
//   if (curveType == 3) {
//     final r1 = r_u16(body, off);
//     final group = r1[0];
//     off = r1[1];

//     final r2 = r_u8(body, off);
//     final plen = r2[0];
//     off = r2[1];

//     final r3 = r_bytes(body, off, plen);
//     final Uint8List pub = r3[0];
//     off = r3[1];

//     final r4 = r_u16(body, off);
//     final sigAlg = r4[0];
//     off = r4[1];

//     final r5 = r_u16(body, off);
//     final sigLen = r5[0];
//     off = r5[1];

//     final r6 = r_bytes(body, off, sigLen);
//     final Uint8List sig = r6[0];
//     off = r6[1];

//     return {
//       'kex': 'ECDHE',
//       'group': group,
//       'public': pub,
//       'sig_alg': sigAlg,
//       'signature': sig,
//     };
//   }

//   // -------------------------------------------------------------------------
//   // DHE fallback form
//   // -------------------------------------------------------------------------
//   final rP = r_u16(body, off);
//   final pLen = rP[0];
//   off = rP[1];

//   final rP2 = r_bytes(body, off, pLen);
//   final Uint8List dh_p = rP2[0];
//   off = rP2[1];

//   final rG = r_u16(body, off);
//   final gLen = rG[0];
//   off = rG[1];

//   final rG2 = r_bytes(body, off, gLen);
//   final Uint8List dh_g = rG2[0];
//   off = rG2[1];

//   final rYs = r_u16(body, off);
//   final yLen = rYs[0];
//   off = rYs[1];

//   final rYs2 = r_bytes(body, off, yLen);
//   final Uint8List dhYs = rYs2[0];
//   off = rYs2[1];

//   final rAlg = r_u16(body, off);
//   final sigAlg2 = rAlg[0];
//   off = rAlg[1];

//   final rSig = r_u16(body, off);
//   final s2len = rSig[0];
//   off = rSig[1];

//   final rSig2 = r_bytes(body, off, s2len);
//   final Uint8List sig2 = rSig2[0];
//   off = rSig2[1];

//   return {
//     'kex': 'DHE',
//     'dh_p': dh_p,
//     'dh_g': dh_g,
//     'dh_Ys': dhYs,
//     'sig_alg': sigAlg2,
//     'signature': sig2,
//   };
// }