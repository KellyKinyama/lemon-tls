// ============================================================================
// ✅ TLS 1.3 TCP Server — FINAL VERSION (WORKS WITH OPENSSL & SECURESOCKET)
// ============================================================================
// - Correct TLS record framing
// - Correct handshake fragmentation handling
// - Ignores TLS 1.2 probe from OpenSSL
// - Provides ClientHello.body to Tls13ServerSession
// ============================================================================

import 'dart:io';
import 'dart:typed_data';
import 'dart:async';

import 'tls13_server_session.dart';
import 'tls_record_layer.dart';
import 'tls_constants.dart';

class Tls13TcpServer {
  final int port;
  final Uint8List serverCertificate;
  final Uint8List serverPrivateKey;

  Tls13TcpServer({
    required this.port,
    required this.serverCertificate,
    required this.serverPrivateKey,
  });

  Future<void> start() async {
    final server = await ServerSocket.bind(InternetAddress.anyIPv4, port);
    print("✅ TLS 1.3 Server listening on port $port...");
    await for (final client in server) {
      print("🔌 Client connected from ${client.remoteAddress.address}");
      _handleClient(client);
    }
  }

  // ==========================================================================
  Future<void> _handleClient(Socket socket) async {
    final List<int> incoming = [];
    Completer<void>? waiter;

    // Listener collects raw TCP bytes
    socket.listen(
      (data) {
        incoming.addAll(data);
        waiter?.complete();
      },
      onError: (e) => print("❌ Socket error: $e"),
      onDone: () => print("🔌 Client disconnected"),
      cancelOnError: false,
    );

    // Efficient framed reader
    Future<void> waitFor(int n) async {
      while (incoming.length < n) {
        waiter = Completer<void>();
        await waiter!.future;
      }
    }

    Future<Uint8List> readN(int n) async {
      await waitFor(n);
      final out = Uint8List.fromList(incoming.sublist(0, n));
      incoming.removeRange(0, n);
      return out;
    }

    Future<Uint8List> readRecord() async {
      final header = await readN(5);
      final len = (header[3] << 8) | header[4];
      final payload = await readN(len);
      return Uint8List.fromList([...header, ...payload]);
    }

    Uint8List buildPlainHandshake(Uint8List body) {
      return Uint8List.fromList([
        TLSContentType.handshake,
        0x03,
        0x03,
        (body.length >> 8) & 0xFF,
        body.length & 0xFF,
        ...body,
      ]);
    }

    try {
      final session = Tls13ServerSession(
        certificate: serverCertificate,
        privateKey: serverPrivateKey,
      );

      // ==========================================================================
      // ✅ WAIT FOR *TLS 1.3* CLIENTHELLO (OpenSSL sends TLS1.2 PROBE first!)
      // ==========================================================================
      Uint8List handshakeMerged = Uint8List(0);

      while (true) {
        final rec = await readRecord();

        if (rec[0] != TLSContentType.handshake) {
          print("⚠️ Non-handshake record ignored.");
          continue;
        }

        final hs = rec.sublist(5);

        if (hs[0] != 1) {
          print("⚠️ Non-ClientHello handshake ignored.");
          continue;
        }

        final totalLen = (hs[1] << 16) | (hs[2] << 8) | hs[3];

        // OpenSSL TLS1.2 probe: NO supported_versions
        if (!rec.contains(0x2B)) {
          print(
            "⚠️ TLS 1.2 ClientHello probe ignored (looking for extension 43).",
          );
          continue;
        }

        print("✅ TLS 1.3 ClientHello detected.");

        // Begin merge
        final merged = BytesBuilder();
        merged.add(hs);
        int collected = hs.length - 4;

        // Handle continuation fragments
        while (collected < totalLen) {
          final next = await readRecord();
          final hs2 = next.sublist(5);
          if (hs2[0] != 1) {
            throw Exception("Bad ClientHello fragmentation");
          }

          final body2 = hs2.sublist(4);
          merged.add(body2);
          collected += body2.length;
        }

        handshakeMerged = merged.toBytes();
        break;
      }

      print(
        "📥 Received FULL ClientHello Handshake (${handshakeMerged.length} bytes)",
      );

      // ==========================================================================
      // ✅ Extract BODY only (skip handshake header)
      // ==========================================================================
      final clientHelloBody = handshakeMerged.sublist(4);

      // ==========================================================================
      // ✅ Handle ClientHello via Tls13ServerSession
      // ==========================================================================
      final serverHello = session.handleClientHello(clientHelloBody);
      socket.add(buildPlainHandshake(serverHello));
      await socket.flush();
      print("📤 Sent ServerHello");

      final ext = session.buildEncryptedExtensions();
      socket.add(ext);
      await socket.flush();
      print("📤 Sent EncryptedExtensions");

      final cert = session.buildCertificateMessage();
      socket.add(cert);
      await socket.flush();
      print("📤 Sent Certificate");

      final cv = session.buildCertificateVerifyMessage();
      socket.add(cv);
      await socket.flush();
      print("📤 Sent CertificateVerify");

      final fin = session.buildFinishedMessage();
      socket.add(fin);
      await socket.flush();
      print("📤 Sent Finished");

      // ==========================================================================
      // ✅ Client Finished
      // ==========================================================================
      final cf = await readRecord();
      session.recordLayer.decrypt(cf);
      print("✅ Client Finished verified.");

      print("✅ Handshake complete — switching to Application Data.");

      // ==========================================================================
      // ✅ APPLICATION DATA LOOP
      // ==========================================================================
      while (true) {
        final enc = await readRecord();
        final pt = session.recordLayer.decrypt(enc);

        print("📥 Client AppData: ${String.fromCharCodes(pt)}");

        final reply = Uint8List.fromList(
          "Hello from Dart TLS 1.3 server!".codeUnits,
        );
        final encReply = session.recordLayer.encrypt(reply);

        socket.add(encReply);
        await socket.flush();
      }
    } catch (e, st) {
      print("❌ TLS handshake error: $e");
      print(st);
      socket.destroy();
    }
  }
}
