// // ===============================================================
// // TLS 1.3 Server Main (integrates your ECDSA certificate generator)
// // ===============================================================

// import 'dart:io';
// import 'dart:typed_data';
// import 'dart:convert';

// import '../cert_utils.dart'; // ✅ your certificate generator
// import 'tls13_server.dart'; // ✅ your TLS engine (already built)
// // import 'record_layer.dart';
// // import 'key_schedule.dart';
// // import 'handshake_messages.dart';
// // import 'tls_key_share.dart';

// // ===============================================================
// // ✅ Correct TLS record reader (fixes "Stream has already been listened to")
// // ===============================================================

// class TlsSocketReader {
//   final Socket socket;
//   final BytesBuilder _buffer = BytesBuilder();
//   bool _listening = false;

//   TlsSocketReader(this.socket);

//   void ensureListening() {
//     if (_listening) return;
//     _listening = true;

//     socket.listen((data) {
//       _buffer.add(data);
//     });
//   }

//   Future<Uint8List?> readTlsRecord() async {
//     ensureListening();

//     // Wait for TLS header
//     while (_buffer.length < 5) {
//       await Future.delayed(Duration(milliseconds: 1));
//     }

//     final header = _buffer.toBytes().sublist(0, 5);
//     final length = (header[3] << 8) | header[4];

//     // Wait for full TLS record
//     while (_buffer.length < 5 + length) {
//       await Future.delayed(Duration(milliseconds: 1));
//     }

//     final fullBytes = _buffer.toBytes();
//     final record = Uint8List.fromList(fullBytes.sublist(0, 5 + length));

//     // Remove consumed bytes
//     final remaining = fullBytes.sublist(5 + length);
//     _buffer.clear();
//     _buffer.add(remaining);

//     return record;
//   }
// }

// // ===============================================================
// // ✅ Start TLS 1.3 Server
// // ===============================================================

// void main() async {
//   print("🔐 Starting TLS 1.3 server...");

//   // -----------------------------------------------------------
//   // ✅ Generate ECDSA certificate
//   // -----------------------------------------------------------
//   final cert = generateSelfSignedCertificate();

//   print("✅ Certificate generated.");
//   print("   - Private Key (raw) : ${cert.privateKey.length} bytes");
//   print("   - Public Key        : ${cert.publickKey.length} bytes");
//   print("   - Certificate (DER) : ${cert.cert.length} bytes");

//   // -----------------------------------------------------------
//   // ✅ Create TLS handshake engine with raw EC private key
//   // -----------------------------------------------------------
//   final tls = Tls13Server(
//     serverCertificateDer: cert.cert,
//     serverEcPrivateKey: cert.privateKey, // raw 32‑byte private key
//   );

//   // -----------------------------------------------------------
//   // ✅ Listen on TCP 443
//   // -----------------------------------------------------------
//   final server = await ServerSocket.bind(InternetAddress.anyIPv4, 443);
//   print("✅ Listening on 0.0.0.0:443 (TLS 1.3)");

//   await for (final socket in server) {
//     print("📥 Client connected: ${socket.remoteAddress.address}");
//     _handleClient(socket, tls);
//   }
// }

// // ===============================================================
// // ✅ Per-client TLS handshake handler
// // ===============================================================

// void _handleClient(Socket socket, Tls13Server tls) async {
//   final reader = TlsSocketReader(socket);

//   try {
//     // 1) Read ClientHello
//     final clientHello = await reader.readTlsRecord();
//     if (clientHello == null) {
//       print("❌ Client disconnected.");
//       return;
//     }
//     print("📥 Received ClientHello (${clientHello.length} bytes)");
//     tls.handleClientHello(clientHello);

//     // 2) Send ServerHello
//     final shRecords = tls.buildServerHelloFlight();
//     for (final rec in shRecords) {
//       socket.add(rec);
//       await socket.flush();
//     }
//     print("📤 Sent ServerHello");

//     // 3) Derive handshake keys
//     tls.computeHandshakeSecrets();

//     // 4) Send EncryptedExtensions, Certificate, CertVerify, Finished
//     final flight2 = tls.buildEncryptedFlight();
//     for (final rec in flight2) {
//       socket.add(rec);
//       await socket.flush();
//     }
//     print("📤 Sent encrypted handshake flight");
//     print("🔒 Encryption enabled");

//     // 5) Receive ClientFinished
//     final clientFinished = await reader.readTlsRecord();
//     if (clientFinished == null) {
//       print("❌ Client disconnected before Finished");
//       return;
//     }
//     tls.handleClientRecord(clientFinished);
//     print("✅ ClientFinished verified");
//     print("🎉 TLS 1.3 handshake complete — secure channel active");

//     // 6) Secure application data
//     while (true) {
//       final encrypted = await reader.readTlsRecord();
//       if (encrypted == null) {
//         print("🔌 Client disconnected");
//         break;
//       }

//       final plain = tls.recordLayer.decrypt(encrypted);
//       print("🔓 Received: ${utf8.decode(plain)}");

//       final reply = Uint8List.fromList("Hello from TLS 1.3 Server".codeUnits);
//       final encReply = tls.recordLayer.encrypt(reply);

//       socket.add(encReply);
//       await socket.flush();
//     }
//   } catch (e, st) {
//     print("❌ TLS error: $e");
//     print(st);
//     socket.destroy();
//   }
// }
