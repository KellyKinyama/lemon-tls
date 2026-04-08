// // ===========================================================
// // TLS 1.3 Handshake Message Builders (Server-Side)
// // ===========================================================

// import 'dart:typed_data';
// import 'dart:convert';
// import 'package:crypto/crypto.dart';
// // import '../crypto/hkdf.dart';
// // import '../crypto/crypto_utils.dart';
// // import '../model/message_types.dart';

// // ===========================================================
// // Utility: Write big-endian u16/u24
// // ===========================================================

// int wU16(Uint8List buf, int off, int v) {
//   buf[off] = (v >> 8) & 0xFF;
//   buf[off + 1] = v & 0xFF;
//   return off + 2;
// }

// int wU24(Uint8List buf, int off, int v) {
//   buf[off] = (v >> 16) & 0xFF;
//   buf[off + 1] = (v >> 8) & 0xFF;
//   buf[off + 2] = v & 0xFF;
//   return off + 3;
// }

// Uint8List u8(int v) => Uint8List.fromList([v]);

// // ===========================================================
// // TLS 1.3: ServerHello
// // ===========================================================
// //
// // Produces:
// //
// //   struct {
// //       ProtocolVersion legacy_version = 0x0303;
// //       Random random;
// //       opaque legacy_session_id_echo<0..32>;
// //       CipherSuite cipher_suite;
// //       uint8 legacy_compression_method = 0;
// //       Extension extensions<6..2^16-1>;
// //   } ServerHello;
// //
// // Wrapped in Handshake message type 2.
// // ===========================================================

// Uint8List buildServerHello({
//   required Uint8List random,
//   required Uint8List sessionId,
//   required int cipherSuite,
//   required int group,
//   required Uint8List serverPublicKey,
// }) {
//   final body = BytesBuilder();

//   // 1) legacy_version (always 0x0303 for TLS 1.3)
//   body.add([0x03, 0x03]);

//   // 2) random
//   body.add(random);

//   // 3) session id echo
//   body.add([sessionId.length]);
//   body.add(sessionId);

//   // 4) cipher suite
//   body.add([(cipherSuite >> 8) & 0xFF, cipherSuite & 0xFF]);

//   // 5) legacy_compression_method = 0
//   body.add([0x00]);

//   // 6) extensions
//   final ext = BytesBuilder();

//   // ---- supported_versions extension (0x002B) ----
//   ext.add([0x00, 0x2B]); // type
//   ext.add([0x00, 0x02]); // length = 2
//   ext.add([0x03, 0x04]); // TLS 1.3

//   // ---- key_share extension (0x0033) ----
//   final ks = BytesBuilder();
//   ks.add([(group >> 8) & 0xFF, group & 0xFF]); // group
//   ks.add([
//     (serverPublicKey.length >> 8) & 0xFF,
//     serverPublicKey.length & 0xFF,
//   ]); // key length
//   ks.add(serverPublicKey); // key

//   final ksBytes = ks.toBytes();
//   ext.add([0x00, 0x33]); // type
//   ext.add([(ksBytes.length >> 8) & 0xFF, ksBytes.length & 0xFF]); // length
//   ext.add(ksBytes);

//   final extBytes = ext.toBytes();

//   // write extension length
//   body.add([(extBytes.length >> 8) & 0xFF, extBytes.length & 0xFF]);
//   body.add(extBytes);

//   // Wrap into handshake header
//   final b = body.toBytes();
//   final out = BytesBuilder();

//   out.add([2]); // ServerHello
//   // print("server hello length: ${}")
//   out.add([(b.length >> 16) & 0xFF, (b.length >> 8) & 0xFF, b.length & 0xFF]);
//   out.add(b);

//   return out.toBytes();
// }

// // ===========================================================
// // TLS 1.3 EncryptedExtensions
// // ===========================================================
// //
// // struct {
// //     Extension extensions<0..2^16-1>;
// // } EncryptedExtensions;
// //
// // Handshake type = 8
// // ===========================================================

// Uint8List buildEncryptedExtensions({List<String>? alpn}) {
//   final body = BytesBuilder();
//   final ext = BytesBuilder();

//   // ALPN extension (optional)
//   if (alpn != null && alpn.isNotEmpty) {
//     final proto = utf8.encode(alpn.first);

//     final alpnList = BytesBuilder();
//     alpnList.add([proto.length]);
//     alpnList.add(proto);

//     // ALPN extension structure
//     final alpnExt = BytesBuilder();
//     alpnExt.add([0x00, 0x10]); // extension type ALPN
//     alpnExt.add([0x00, (alpnList.length + 2) & 0xFF]); // ALPN ext len
//     alpnExt.add([0x00, alpnList.length]);
//     alpnExt.add(alpnList.toBytes());

//     ext.add(alpnExt.toBytes());
//   }

//   final extBytes = ext.toBytes();
//   body.add([(extBytes.length >> 8) & 0xFF, extBytes.length & 0xFF]);
//   body.add(extBytes);

//   final b = body.toBytes();

//   final out = BytesBuilder();
//   out.add([8]); // EncryptedExtensions
//   out.add([(b.length >> 16) & 0xFF, (b.length >> 8) & 0xFF, b.length & 0xFF]);
//   out.add(b);

//   return out.toBytes();
// }

// // ===========================================================
// // TLS 1.3 Certificate (Server)
// // ===========================================================
// //
// // struct {
// //    opaque certificate_request_context<0..2^8-1>;
// //    CertificateEntry certificate_list<0..2^24-1>;
// // } Certificate;
// //
// // Handshake type = 11
// // ===========================================================

// Uint8List buildCertificateMessage({required Uint8List certificateDer}) {
//   final body = BytesBuilder();

//   // certificate_request_context = empty
//   body.add([0x00]);

//   // certificate_entry
//   final certEntry = BytesBuilder();
//   certEntry.add([
//     (certificateDer.length >> 16) & 0xFF,
//     (certificateDer.length >> 8) & 0xFF,
//     certificateDer.length & 0xFF,
//   ]);

//   certEntry.add(certificateDer);

//   // extensions = empty
//   certEntry.add([0x00, 0x00]);

//   final certEntryBytes = certEntry.toBytes();

//   // certificate_list<3 bytes>
//   body.add([
//     (certEntryBytes.length >> 16) & 0xFF,
//     (certEntryBytes.length >> 8) & 0xFF,
//     certEntryBytes.length & 0xFF,
//   ]);
//   body.add(certEntryBytes);

//   final b = body.toBytes();

//   final out = BytesBuilder();
//   out.add([11]); // Certificate
//   out.add([(b.length >> 16) & 0xFF, (b.length >> 8) & 0xFF, b.length & 0xFF]);
//   out.add(b);

//   return out.toBytes();
// }

// // ===========================================================
// // TLS 1.3 CertificateVerify
// // ===========================================================
// //
// // struct {
// //     SignatureScheme algorithm;
// //     opaque signature<0..2^16-1>;
// // }
// //
// // Handshake type = 15
// // ===========================================================

// Uint8List buildCertificateVerify({
//   required int algorithm,
//   required Uint8List signature,
// }) {
//   final body = BytesBuilder();

//   // algorithm
//   body.add([(algorithm >> 8) & 0xFF, algorithm & 0xFF]);

//   // signature
//   body.add([(signature.length >> 8) & 0xFF, signature.length & 0xFF]);
//   body.add(signature);

//   final b = body.toBytes();

//   final out = BytesBuilder();
//   out.add([15]); // CertificateVerify
//   out.add([(b.length >> 16) & 0xFF, (b.length >> 8) & 0xFF, b.length & 0xFF]);
//   out.add(b);

//   return out.toBytes();
// }

// // ===========================================================
// // TLS 1.3 Finished
// // ===========================================================
// //
// // struct {
// //    opaque verify_data[Hash.length];
// // }
// //
// // Handshake type = 20
// // ===========================================================

// Uint8List buildFinished({required Uint8List finishedMac}) {
//   final b = finishedMac;

//   final out = BytesBuilder();
//   out.add([20]); // Finished
//   out.add([(b.length >> 16) & 0xFF, (b.length >> 8) & 0xFF, b.length & 0xFF]);
//   out.add(b);

//   return out.toBytes();
// }
