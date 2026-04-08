// // ============================================================================
// // TLS 1.3 Server-Side Handshake Handler
// // Requires:
// //   - tls_hello.dart
// //   - tls_extensions.dart
// //   - tls_certificate.dart
// //   - tls_certificate_verify.dart
// //   - tls_new_session_ticket.dart
// //   - hkdf.dart   (your HKDF implementation)
// //   - Tls13KeySchedule (from your earlier file)
// //   - TlsKeyShare (from your earlier file)
// // ============================================================================

// import 'dart:typed_data';
// import 'dart:convert';

// import '../key_schedule.dart';
// import '../tls_key_share.dart';
// import 'tls_hello.dart';
// import 'tls_extensions.dart';
// import 'tls_certificate.dart';
// import 'tls_certificate_verify.dart';
// import 'tls_new_session_ticket.dart';
// import 'tls_read.dart';
// import 'tls_utils.dart';
// import 'tls_constants.dart';


// class Tls13ServerHandshakeResult {
//   late Uint8List serverHello;
//   late Uint8List sharedSecret;

//   late Uint8List handshakeHash;
//   late Tls13KeySchedule keySchedule;

//   late Uint8List clientHandshakeKey;
//   late Uint8List serverHandshakeKey;

//   late Uint8List clientHandshakeIV;
//   late Uint8List serverHandshakeIV;

//   late int selectedGroup;
//   late Uint8List serverPublicKey;
// }

// class Tls13ServerHandshake {
//   /// The certificate + private key used by the server
//   final Uint8List serverCertificate;     // DER
//   final Uint8List serverPrivateKey;      // raw bytes (X25519 or P256)

//   Tls13ServerHandshake({
//     required this.serverCertificate,
//     required this.serverPrivateKey,
//   });

//   // ===========================================================
//   // Main entry point
//   // ===========================================================

//   Tls13ServerHandshakeResult handleClientHello(Uint8List clientHelloMsg) {
//     // ----------------------------------------------------------
//     // Step 1: Parse ClientHello
//     // ----------------------------------------------------------
//     final parsed = parseHello(TLSMessageType.CLIENT_HELLO, clientHelloMsg);

//     final extensions = parsed['extensions'] as List;

//     // Extract client supported groups
//     final clientSupportedGroups = _extractSupportedGroups(extensions);

//     // Extract client key_share (list of key shares)
//     final clientKeyShares = _extractKeyShares(extensions);

//     if (clientSupportedGroups.isEmpty || clientKeyShares.isEmpty) {
//       throw Exception("ClientHello missing supported_groups or key_share");
//     }

//     // ----------------------------------------------------------
//     // Step 2: Select the best mutual group
//     // ----------------------------------------------------------
//     final selectedGroup = _negotiateGroup(clientSupportedGroups);

//     if (selectedGroup == null) {
//       throw Exception("No compatible ECDHE group found");
//     }

//     // Find matching client key share entry
//     final Map<String, dynamic>? clientEntry = clientKeyShares
//         .cast<Map<String, dynamic>?>()
//         .firstWhere((e) => e?['group'] == selectedGroup, orElse: () => null);

//     if (clientEntry == null) {
//       throw Exception("Client did not include a key_share for selected group");
//     }

//     final Uint8List clientPub = clientEntry['key_exchange'];

//     // ----------------------------------------------------------
//     // Step 3: Generate Server key share + shared secret
//     // ----------------------------------------------------------
//     final keyShare = TlsKeyShare.generate(
//       group: selectedGroup,
//       clientPublicKey: clientPub,
//     );

//     // ----------------------------------------------------------
//     // Step 4: Build ServerHello
//     // ----------------------------------------------------------
//     final serverHello = _buildServerHello(
//       random: _serverRandom(),
//       selectedGroup: selectedGroup,
//       serverPublicKey: keyShare.publicKey,
//       clientHelloExtensions: extensions,
//     );

//     // ----------------------------------------------------------
//     // Step 5: Compute handshake secrets
//     // ----------------------------------------------------------
//     final keySchedule = Tls13KeySchedule();

//     // Compute Hash(ClientHello || ServerHello)
//     final helloHash = _hashHelloMessages(clientHelloMsg, serverHello);

//     keySchedule.computeHandshakeSecrets(
//       sharedSecret: keyShare.sharedSecret,
//       helloHash: helloHash,
//     );

//     // ----------------------------------------------------------
//     // Assemble final results
//     // ----------------------------------------------------------
//     final res = Tls13ServerHandshakeResult();
//     res.serverHello = serverHello;
//     res.sharedSecret = keyShare.sharedSecret;

//     res.handshakeHash = helloHash;
//     res.keySchedule = keySchedule;

//     res.clientHandshakeKey = keySchedule.clientHandshakeKey;
//     res.serverHandshakeKey = keySchedule.serverHandshakeKey;

//     res.clientHandshakeIV = keySchedule.clientHandshakeIV;
//     res.serverHandshakeIV = keySchedule.serverHandshakeIV;

//     res.selectedGroup = selectedGroup;
//     res.serverPublicKey = keyShare.publicKey;

//     return res;
//   }

//   // ===========================================================
//   // Helpers
//   // ===========================================================

//   Uint8List _serverRandom() {
//     final rnd = Uint8List(32);
//     for (var i = 0; i < 32; i++) rnd[i] = (DateTime.now().microsecondsSinceEpoch + i) & 0xFF;
//     return rnd;
//   }

//   List<int> _extractSupportedGroups(List exts) {
//     for (final e in exts) {
//       if (e['type'] == TLSExt.SUPPORTED_GROUPS) {
//         return (e['value'] as List).cast<int>();
//       }
//     }
//     return [];
//   }

//   List<Map<String, dynamic>> _extractKeyShares(List exts) {
//     for (final e in exts) {
//       if (e['type'] == TLSExt.KEY_SHARE) {
//         if (e['value'] is List) {
//           return (e['value'] as List).cast<Map<String, dynamic>>();
//         }
//       }
//     }
//     return [];
//   }

//   int? _negotiateGroup(List<int> clientGroups) {
//     const preferred = [0x001d, 0x0017]; // X25519, P‑256
//     for (final g in preferred) {
//       if (clientGroups.contains(g)) return g;
//     }
//     return null;
//   }

//   Uint8List _buildServerHello({
//     required Uint8List random,
//     required int selectedGroup,
//     required Uint8List serverPublicKey,
//     required List clientHelloExtensions,
//   }) {
//     return buildHello('server', {
//       'random': random,
//       'cipher_suite': 0x1301, // TLS_AES_128_GCM_SHA256
//       'extensions': [
//         {
//           'type': 'SUPPORTED_VERSIONS',
//           'value': TLSVersion.TLS1_3
//         },
//         {
//           'type': 'KEY_SHARE',
//           'value': {
//             'group': selectedGroup,
//             'key_exchange': serverPublicKey,
//           }
//         }
//       ]
//     });
//   }

//   /// Compute Hash(ClientHello || ServerHello)
//   Uint8List _hashHelloMessages(Uint8List ch, Uint8List sh) {
//     // You must replace this with your SHA256 implementation
//     throw UnimplementedError("hashing not implemented. Use sha256(CH || SH).");
//   }
// }