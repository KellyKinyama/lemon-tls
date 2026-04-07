// ===========================================================
// TCP TLS 1.3 Server Example
// ===========================================================
// This file shows how to use:
//   - Tls13Server
//   - Record Layer
//   - ClientHello parsing
//   - ServerHello flight
//   - Switching to encrypted traffic
//   - Handling ClientFinished
//
// Once handshake completes, you now have a secure channel.
//
// ===========================================================

import 'dart:io';
import 'dart:typed_data';
import '../tls/tls13_server.dart';
// import 'record_layer.dart';

class TlsTcpServer {
  final String host;
  final int port;
  final Tls13Server tls;

  TlsTcpServer({required this.host, required this.port, required this.tls});

  Future start() async {
    final server = await ServerSocket.bind(host, port);
    print("TLS 1.3 server listening on $host:$port");

    await for (final socket in server) {
      print("Client connected: ${socket.remoteAddress}:${socket.remotePort}");
      _handleClient(socket);
    }
  }

  // ===========================================================
  // Per‑client connection handler
  // ===========================================================
  void _handleClient(Socket socket) async {
    try {
      // -------------------------------------------------------------------
      // 1. Read ClientHello (plaintext TLS record)
      // -------------------------------------------------------------------
      final clientHelloRecord = await _readTlsRecord(socket);
      if (clientHelloRecord == null) {
        throw Exception("Client disconnected before ClientHello");
      }

      print("📥 Received ClientHello (${clientHelloRecord.length} bytes)");

      // Parse ClientHello inside the TLS server engine
      tls.handleClientHello(clientHelloRecord);

      // -------------------------------------------------------------------
      // 2. Generate ECDHE + ServerHello flight
      // -------------------------------------------------------------------
      print("🔐 Generating ServerHello flight...");

      final serverHelloRecords = tls.buildServerHelloFlight();

      for (final rec in serverHelloRecords) {
        socket.add(rec);
        await socket.flush();
      }

      print("📤 Sent ServerHello");

      // -------------------------------------------------------------------
      // 3. Derive handshake secrets
      // -------------------------------------------------------------------
      print("🔑 Computing TLS 1.3 handshake secrets...");
      tls.computeHandshakeSecrets();

      // -------------------------------------------------------------------
      // 4. Send EncryptedExtensions, Certificate, CertVerify, Finished
      // -------------------------------------------------------------------
      final encryptedFlight = tls.buildEncryptedFlight();

      for (final encryptedRecord in encryptedFlight) {
        socket.add(encryptedRecord);
        await socket.flush();
      }

      print(
        "📤 Sent EncryptedExtensions + Certificate + CertVerify + Finished",
      );
      print("🔒 Switching to encrypted mode...");

      // -------------------------------------------------------------------
      // 5. Receive ClientFinished (encrypted)
      // -------------------------------------------------------------------
      final clientFinishedRecord = await _readTlsRecord(socket);

      if (clientFinishedRecord == null) {
        throw Exception("Client disconnected before ClientFinished");
      }

      print("📥 Received encrypted ClientFinished");

      final ok = tls.handleClientRecord(clientFinishedRecord);

      if (ok) {
        print("✅ ClientFinished verified!");
      }

      print("🎉 TLS 1.3 Handshake COMPLETE — secure channel established.");

      // ===================================================================
      // 6. SECURE COMMUNICATION: receive encrypted data
      // ===================================================================

      while (true) {
        final encryptedRecord = await _readTlsRecord(socket);
        if (encryptedRecord == null) {
          print("Client disconnected.");
          break;
        }

        final plaintext = tls.recordLayer.decrypt(encryptedRecord);

        print(
          "🔓 Received encrypted app data: ${String.fromCharCodes(plaintext)}",
        );

        // Echo it back encrypted:
        final responsePlain = Uint8List.fromList(
          "Hello from TLS 1.3 server".codeUnits,
        );
        final responseRecord = tls.recordLayer.encrypt(responsePlain);

        socket.add(responseRecord);
        await socket.flush();
      }
    } catch (e, st) {
      print("❌ TLS Error: $e\n$st");
      socket.destroy();
    }
  }

  // ===========================================================
  // Helper: Read one full TLS record (5-byte header + payload)
  // ===========================================================
  Future<Uint8List?> _readTlsRecord(Socket socket) async {
    // Read the TLS record header
    final header = await _readBytes(socket, 5);
    if (header == null) return null;

    final length = (header[3] << 8) | header[4];

    final payload = await _readBytes(socket, length);
    if (payload == null) return null;

    return Uint8List.fromList([...header, ...payload]);
  }

  Future<Uint8List?> _readBytes(Socket socket, int len) async {
    final buffer = BytesBuilder();
    int remaining = len;

    while (remaining > 0) {
      final chunk = await socket.firstTimeout(const Duration(seconds: 15));
      if (chunk == null) return null;

      final bytes = Uint8List.fromList(chunk);

      final take = bytes.length > remaining ? remaining : bytes.length;

      buffer.add(bytes.sublist(0, take));
      remaining -= take;

      if (bytes.length > take) {
        // unread extra bytes (this is optional)
      }
    }

    return buffer.toBytes();
  }
}

extension _FirstTimeout on Socket {
  Future<List<int>?> firstTimeout(Duration d) {
    return this
        .timeout(d, onTimeout: (_) => null)
        .first
        .catchError((_) => null);
  }
}
