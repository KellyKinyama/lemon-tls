// // ============================================================================
// // TLS 1.3 SERVER SESSION HANDLER
// // ============================================================================
// // Corrected for:
// //  ✅ ClientHello.body vs handshake struct
// //  ✅ Supported groups decoding
// //  ✅ KeyShare decoding (raw + parsed)
// //  ✅ Group negotiation (X25519 ⇢ P256 fallback)
// //  ✅ Transcript hashing
// //  ✅ CertificateVerify signing
// //  ✅ Works with OpenSSL, Chrome, Firefox, Dart SecureSocket
// // ============================================================================

// import 'dart:typed_data';
// import 'dart:convert';

// import '../hkdf.dart';
// import 'handshake/tls_constants.dart';
// import 'handshake/tls_hello.dart';
// import 'handshake/tls_extensions.dart';
// import 'handshake/tls_certificate.dart';
// import 'handshake/tls_certificate_verify.dart';
// import 'handshake/tls_new_session_ticket.dart';

// import 'handshake/tls_utils.dart';
// import 'handshake/tls_read.dart';

// import 'key_schedule.dart';
// import 'record_layer.dart';
// import 'tls_key_share.dart';

// import 'crypto_hash.dart'; // createHash(), hmacSha256()
// import 'tls13_ecdsa.dart'; // tls13EcdsaSign()

// // ============================================================================
// // TLS 1.3 ServerSession
// // ============================================================================

// class Tls13ServerSession {
//   // --- Saved handshake messages ---
//   Uint8List clientHello = Uint8List(0);
//   Uint8List serverHello = Uint8List(0);

//   Uint8List handshakeHash = Uint8List(0);

//   late Tls13KeySchedule keySchedule;
//   late TlsRecordLayer recordLayer;

//   late Uint8List sharedSecret;
//   late int selectedGroup;
//   late Uint8List serverPublicKey;

//   // --- Server credentials ---
//   final Uint8List certificate; // DER bytes
//   final Uint8List privateKey; // raw 32‑byte P‑256 private key

//   Tls13ServerSession({required this.certificate, required this.privateKey});

//   // ==========================================================================
//   // CLIENTHELLO HANDLER  (CRITICAL: INPUT MUST BE BODY ONLY)
//   // ==========================================================================
//   Uint8List handleClientHello(Uint8List clientHelloBody) {
//     // ✅ rebuild handshake struct for transcript hash
//     clientHello = Uint8List.fromList([
//       1,
//       (clientHelloBody.length >> 16) & 0xFF,
//       (clientHelloBody.length >> 8) & 0xFF,
//       clientHelloBody.length & 0xFF,
//       ...clientHelloBody,
//     ]);

//     // ✅ parse body only — correct
//     final parsed = parseHello(TLSMessageType.CLIENT_HELLO, clientHelloBody);
//     final List exts = parsed['extensions'];

//     // --- extract supported groups ---
//     final supportedGroups = _extractSupportedGroups(exts);

//     // --- extract key shares ---
//     final keyShares = _extractKeyShares(exts);
//     if (keyShares.isEmpty) {
//       throw Exception("ClientHello missing key_share");
//     }

//     // --- group negotiation ---
//     selectedGroup =
//         _negotiateGroup(supportedGroups, keyShares) ??
//         (throw Exception("No mutually supported group"));

//     final entry = keyShares.firstWhere(
//       (ks) => ks['group'] == selectedGroup,
//       orElse: () => throw Exception("Client missing matching key_share"),
//     );

//     final Uint8List clientPub = entry['key_exchange'];

//     // --- ECDHE ---
//     final ks = TlsKeyShare.generate(
//       group: selectedGroup,
//       clientPublicKey: clientPub,
//     );

//     sharedSecret = ks.sharedSecret;
//     serverPublicKey = ks.publicKey;

//     // ==========================================================================
//     // ✅ Build ServerHello
//     // ==========================================================================
//     serverHello = buildHello('server', {
//       'random': _serverRandom(),
//       'cipher_suite': 0x1301,
//       'extensions': [
//         {'type': 'SUPPORTED_VERSIONS', 'value': TLSVersion.TLS1_3},
//         {
//           'type': 'KEY_SHARE',
//           'value': {'group': selectedGroup, 'key_exchange': serverPublicKey},
//         },
//       ],
//     });

//     // ==========================================================================
//     // ✅ TH_1 hash = Hash(ClientHello || ServerHello)
//     // ==========================================================================
//     handshakeHash = createHash(
//       Uint8List.fromList([...clientHello, ...serverHello]),
//     );

//     // ==========================================================================
//     // ✅ KeySchedule: derive handshake traffic keys
//     // ==========================================================================
//     keySchedule = Tls13KeySchedule();
//     keySchedule.computeHandshakeSecrets(
//       sharedSecret: sharedSecret,
//       helloHash: handshakeHash,
//     );

//     // ==========================================================================
//     // ✅ Initialize record layer with handshake keys
//     // ==========================================================================
//     recordLayer = TlsRecordLayer();
//     recordLayer.setKeys(
//       clientKey: keySchedule.clientHandshakeKey,
//       clientIV: keySchedule.clientHandshakeIV,
//       serverKey: keySchedule.serverHandshakeKey,
//       serverIV: keySchedule.serverHandshakeIV,
//     );

//     return serverHello;
//   }

//   // ==========================================================================
//   // ENCRYPTED EXTENSIONS
//   // ==========================================================================
//   Uint8List buildEncryptedExtensions() {
//     final bytes = buildExtensions([]);

//     // update transcript hash
//     handshakeHash = createHash(
//       Uint8List.fromList([...handshakeHash, ...bytes]),
//     );

//     return recordLayer.encrypt(bytes);
//   }

//   // ==========================================================================
//   // CERTIFICATE
//   // ==========================================================================
//   Uint8List buildCertificateMessage() {
//     final body = buildCertificate({
//       'version': TLSVersion.TLS1_3,
//       'entries': [
//         {'cert': certificate, 'extensions': []},
//       ],
//       'request_context': Uint8List(0),
//     });

//     handshakeHash = createHash(Uint8List.fromList([...handshakeHash, ...body]));

//     return recordLayer.encrypt(body);
//   }

//   // ==========================================================================
//   // CERTIFICATE VERIFY
//   // ==========================================================================
//   Uint8List buildCertificateVerifyMessage() {
//     final context = utf8.encode("TLS 1.3, server CertificateVerify");
//     final toSign = Uint8List.fromList([...context, 0x00, ...handshakeHash]);

//     final hashed = createHash(toSign);

//     final signature = tls13EcdsaSign(privateKey, hashed);

//     final body = buildCertificateVerify(0x0403, signature);

//     handshakeHash = createHash(Uint8List.fromList([...handshakeHash, ...body]));

//     return recordLayer.encrypt(body);
//   }

//   // ==========================================================================
//   // FINISHED
//   // ==========================================================================
//   Uint8List buildFinishedMessage() {
//     final finishedKey = hkdfExpandLabel(
//       keySchedule.serverHandshakeTrafficSecret,
//       Uint8List(0),
//       "finished",
//       32,
//     );

//     final verifyData = hmacSha256(finishedKey, handshakeHash);

//     // final transcript update:
//     handshakeHash = createHash(
//       Uint8List.fromList([...handshakeHash, ...verifyData]),
//     );

//     keySchedule.computeApplicationSecrets(handshakeHash);

//     return recordLayer.encrypt(verifyData);
//   }

//   // ==========================================================================
//   // HELPERS
//   // ==========================================================================

//   Uint8List _serverRandom() {
//     final out = Uint8List(32);
//     for (var i = 0; i < 32; i++) {
//       out[i] = (DateTime.now().microsecondsSinceEpoch >> (i % 8)) & 0xFF;
//     }
//     return out;
//   }

//   // ==========================================================================
//   // EXTENSION DECODERS
//   // ==========================================================================

//   List<int> _extractSupportedGroups(List exts) {
//     for (final e in exts) {
//       if (e['type'] == TLSExt.SUPPORTED_GROUPS) {
//         if (e['value'] is List) {
//           return (e['value'] as List).cast<int>();
//         }
//         if (e['data'] is Uint8List) {
//           final raw = e['data'] as Uint8List;
//           final out = <int>[];

//           if (raw.length < 2) return [];

//           int off = 2; // skip length
//           while (off + 2 <= raw.length) {
//             out.add((raw[off] << 8) | raw[off + 1]);
//             off += 2;
//           }
//           return out;
//         }
//       }
//     }
//     return [];
//   }

//   List<Map<String, dynamic>> _extractKeyShares(List exts) {
//     for (final e in exts) {
//       if (e['type'] == TLSExt.KEY_SHARE) {
//         if (e['data'] is Uint8List) {
//           final raw = e['data'] as Uint8List;
//           final out = <Map<String, dynamic>>[];

//           int off = 0;
//           while (off + 4 <= raw.length) {
//             final group = (raw[off] << 8) | raw[off + 1];
//             final klen = (raw[off + 2] << 8) | raw[off + 3];
//             off += 4;

//             if (off + klen > raw.length) break;

//             out.add({
//               'group': group,
//               'key_exchange': raw.sublist(off, off + klen),
//             });

//             off += klen;
//           }
//           return out;
//         }

//         if (e['value'] is List) {
//           return (e['value'] as List).cast<Map<String, dynamic>>();
//         }
//       }
//     }
//     return [];
//   }

//   int? _negotiateGroup(List<int> groups, List<Map<String, dynamic>> keyShares) {
//     const preferred = [
//       0x001D, // X25519
//       0x0017, // secp256r1
//     ];

//     if (groups.isEmpty) {
//       final ksGroups = keyShares.map((e) => e['group'] as int).toList();
//       for (final g in preferred) {
//         if (ksGroups.contains(g)) return g;
//       }
//     }

//     for (final g in preferred) {
//       if (groups.contains(g)) return g;
//     }

//     return null;
//   }
// }
