// // ============================================================================
// // tls_hello.dart
// // TLS ClientHello / ServerHello builder + parser
// // Direct Dart translation of original JavaScript code
// // ============================================================================

// import 'dart:typed_data';

// import 'tls_constants.dart';
// import 'tls_utils.dart';
// import 'tls_write.dart';
// import 'tls_read.dart';
// import 'tls_extensions.dart';

// /// Build ClientHello or ServerHello
// Uint8List buildHello(String kind, Map<String, dynamic>? params) {
//   params ??= {};

//   final legacyVersion = TLSVersion.TLS1_2;

//   // --- session_id ---
//   Uint8List sid = toU8(params['session_id'] ?? "");
//   if (sid.length > 32) {
//     sid = sid.sublist(0, 32);
//   }

//   // --- random ---
//   Uint8List random = params['random'];
//   if (random.length != 32) {
//     throw ArgumentError("random must be 32 bytes");
//   }

//   // --- extensions ---
//   final Uint8List extsBuf =
//       buildExtensions(params['extensions'] ?? []);

//   // ---------------------------------------------------------------------------
//   // CLIENT_HELLO
//   // ---------------------------------------------------------------------------
//   if (kind == 'client') {
//     final cs = params['cipher_suites'] ??
//         [0x1301, 0x1302, 0x1303, 0xC02F, 0xC02B];

//     final csBlock =
//         Uint8List(2 + cs.length * 2);
//     int o = 0;
//     o = w_u16(csBlock, o, cs.length * 2);
//     for (final c in cs) {
//       o = w_u16(csBlock, o, c);
//     }

//     final comp = params['legacy_compression'] ?? [0];
//     final compBlock = Uint8List(1 + comp.length);
//     int oc = 0;
//     oc = w_u8(compBlock, oc, comp.length);
//     for (final c in comp) {
//       oc = w_u8(compBlock, oc, c);
//     }

//     final out = Uint8List(
//       2 +                     // version
//       32 +                    // random
//       1 + sid.length +        // session_id
//       csBlock.length +        // cipher suites
//       compBlock.length +      // compression
//       extsBuf.length          // extensions
//     );

//     int off = 0;
//     off = w_u16(out, off, legacyVersion);
//     off = w_bytes(out, off, random);
//     off = w_u8(out, off, sid.length);
//     off = w_bytes(out, off, sid);
//     off = w_bytes(out, off, csBlock);
//     off = w_bytes(out, off, compBlock);
//     off = w_bytes(out, off, extsBuf);

//     return out;
//   }

//   // ---------------------------------------------------------------------------
//   // SERVER_HELLO
//   // ---------------------------------------------------------------------------
//   if (kind == 'server') {
//     final cipherSuite =
//         (params['cipher_suite'] is int)
//             ? params['cipher_suite'] as int
//             : 0x1301;

//     final out = Uint8List(
//       2 +                 // legacy_version
//       32 +                // random
//       1 + sid.length +    // session_id
//       2 +                 // cipher_suite
//       1 +                 // compression=0
//       extsBuf.length
//     );

//     int off = 0;

//     off = w_u16(out, off, legacyVersion);
//     off = w_bytes(out, off, random);
//     off = w_u8(out, off, sid.length);
//     off = w_bytes(out, off, sid);
//     off = w_u16(out, off, cipherSuite);
//     off = w_u8(out, off, 0);
//     off = w_bytes(out, off, extsBuf);

//     return out;
//   }

//   throw ArgumentError('buildHello: kind must be "client" or "server"');
// }

// /// ---------------------------------------------------------------------------
// /// Parse ClientHello or ServerHello
// /// ---------------------------------------------------------------------------
// Map<String, dynamic> parseHello(dynamic hsType, Uint8List body) {
//   final isClient =
//       (hsType == TLSMessageType.CLIENT_HELLO ||
//           hsType == 'client_hello');

//   int off = 0;

//   // legacy_version
//   final rv = r_u16(body, off);
//   final legacyVersion = rv[0];
//   off = rv[1];

//   // random
//   final rr = r_bytes(body, off, 32);
//   final random = rr[0] as Uint8List;
//   off = rr[1];

//   // session_id
//   final rs = r_u8(body, off);
//   final sidLen = rs[0];
//   off = rs[1];

//   final rb = r_bytes(body, off, sidLen);
//   final sessionId = rb[0] as Uint8List;
//   off = rb[1];

//   // ---------------------------------------------------------------------------
//   // CLIENT_HELLO
//   // ---------------------------------------------------------------------------
//   if (isClient) {
//     final rcs = r_u16(body, off);
//     final csLen = rcs[0];
//     off = rcs[1];

//     final csEnd = off + csLen;
//     final cipherSuites = <int>[];

//     while (off < csEnd) {
//       final rr2 = r_u16(body, off);
//       cipherSuites.add(rr2[0]);
//       off = rr2[1];
//     }

//     final rc3 = r_u8(body, off);
//     final compLen = rc3[0];
//     off = rc3[1];

//     final legacyCompression = <int>[];
//     for (int i = 0; i < compLen; i++) {
//       final rcm = r_u8(body, off);
//       legacyCompression.add(rcm[0]);
//       off = rcm[1];
//     }

//     final extRaw = (body.length > off)
//         ? body.sublist(off)
//         : Uint8List(0);

//     final extensions =
//         extRaw.isNotEmpty ? parseExtensions(extRaw) : [];

//     // version_hint logic
//     int ver = legacyVersion;

//     for (final e in extensions) {
//       if (e['type'] == TLSExt.SUPPORTED_VERSIONS &&
//           (e['value'] is List)) {
//         final list = e['value'] as List;
//         if (list.contains(TLSVersion.TLS1_3)) {
//           ver = TLSVersion.TLS1_3;
//         }
//       }
//     }

//     return {
//       'message': 'client_hello',
//       'legacy_version': legacyVersion,
//       'version_hint': ver,
//       'random': random,
//       'session_id': sessionId,
//       'cipher_suites': cipherSuites,
//       'legacy_compression': legacyCompression,
//       'extensions': extensions,
//     };
//   }

//   // ---------------------------------------------------------------------------
//   // SERVER_HELLO
//   // ---------------------------------------------------------------------------

//   final rcs = r_u16(body, off);
//   final cipherSuite = rcs[0];
//   off = rcs[1];

//   final rcm = r_u8(body, off);
//   final compression = rcm[0];
//   off = rcm[1];

//   final extRaw = (body.length > off)
//       ? body.sublist(off)
//       : Uint8List(0);

//   final extensions =
//       extRaw.isNotEmpty ? parseExtensions(extRaw) : [];

//   int ver = legacyVersion;
//   for (final ex in extensions) {
//     if (ex['type'] == TLSExt.SUPPORTED_VERSIONS &&
//         (ex['value'] is int)) {
//       ver = ex['value'];
//     }
//   }

//   return {
//     'message': 'server_hello',
//     'legacy_version': legacyVersion,
//     'version': ver,
//     'random': random,
//     'session_id': sessionId,
//     'cipher_suite': cipherSuite,
//     'legacy_compression': compression,
//     'extensions': extensions,
//   };
// }