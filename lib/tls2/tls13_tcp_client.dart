// ============================================================================
// TLS 1.3 TCP CLIENT — interoperates with your custom TLS 1.3 server
// RFC 8446 (minimal, explicit, symmetric to server)
// ============================================================================

import 'dart:io';
import 'dart:typed_data';
import 'dart:async';

import 'package:hex/hex.dart';

import 'tls13_client_session.dart';
import 'tls_record_layer.dart';
import 'tls_constants.dart';

// ============================================================================
// DEBUG HELPERS
// ============================================================================

String hex(Uint8List b, [int max = 64]) {
  final cut = b.length > max ? b.sublist(0, max) : b;
  final s = cut.map((x) => x.toRadixString(16).padLeft(2, '0')).join(' ');
  return b.length > max
      ? "$s ... (${b.length} bytes)"
      : "$s (${b.length} bytes)";
}

void dumpRecord(String label, Uint8List rec) {
  final len = (rec[3] << 8) | rec[4];
  print("");
  print("🔎 $label TLS RECORD");
  print("  type   = ${rec[0]}");
  print("  ver    = ${rec[1].toRadixString(16)} ${rec[2].toRadixString(16)}");
  print("  length = $len");
  print("  data   = ${hex(rec.sublist(5))}");
}

void dumpHandshake(String label, Uint8List hs) {
  final len = (hs[1] << 16) | (hs[2] << 8) | hs[3];
  print("");
  print("🔎 $label HANDSHAKE");
  print("  hsType = ${hs[0]}");
  print("  hsLen  = $len");
  print("  body   = ${hex(hs.sublist(4))}");
}

// ============================================================================
// TCP CLIENT
// ============================================================================

class Tls13TcpClient {
  final String host;
  final int port;

  /// Raw ClientHello bytes (TLSPlaintext record)
  final Uint8List clientHello;

  Tls13TcpClient({
    required this.host,
    required this.port,
    required this.clientHello,
  });

  Future<void> connect() async {
    final socket = await Socket.connect(host, port);
    print("✅ Connected to $host:$port");

    final incoming = <int>[];
    Completer<void>? waiter;

    socket.listen(
      (data) {
        incoming.addAll(data);
        if (waiter != null && !waiter!.isCompleted) {
          waiter!.complete();
        }
      },
      onDone: () => print("🔌 Server closed connection"),
      onError: (e) => print("❌ Socket error: $e"),
      cancelOnError: false,
    );

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
      final rec = Uint8List.fromList([...header, ...payload]);
      dumpRecord("RX", rec);
      return rec;
    }

    try {
      // ------------------------------------------------------------------
      // Send ClientHello
      // ------------------------------------------------------------------
      print("📤 Sending ClientHello (${clientHello.length} bytes)");
      socket.add(clientHello);
      await socket.flush();

      // ------------------------------------------------------------------
      // Create client TLS session
      // ------------------------------------------------------------------
      final session = Tls13ClientSession(
        certificate: Uint8List(0),
        privateKey: Uint8List(0),
      );

      // ------------------------------------------------------------------
      // ServerHello
      // ------------------------------------------------------------------
      final shRec = await readRecord();
      if (shRec[0] != TLSContentType.handshake) {
        throw Exception("Expected ServerHello handshake record");
      }

      final sh = shRec.sublist(5);
      dumpHandshake("RX ServerHello", sh);
      session.handleServerHello(sh);

      // ------------------------------------------------------------------
      // Encrypted handshake messages
      // ------------------------------------------------------------------
      session.decryptHandshake(await readRecord()); // EncryptedExtensions
      session.decryptHandshake(await readRecord()); // Certificate
      session.decryptHandshake(await readRecord()); // CertificateVerify
      session.decryptHandshake(await readRecord()); // Finished (server)

      // ------------------------------------------------------------------
      // Send Client Finished
      // ------------------------------------------------------------------
      final clientFinished = session.buildClientFinished();
      dumpRecord("TX Client Finished", clientFinished);
      socket.add(clientFinished);
      await socket.flush();

      print("✅ TLS 1.3 handshake complete");

      // ------------------------------------------------------------------
      // Application data example
      // ------------------------------------------------------------------
      final appData = Uint8List.fromList(
        "HELLO FROM DART TLS CLIENT".codeUnits,
      );
      final enc = session.recordLayer.encrypt(appData);

      print("📤 Sending Application Data");
      socket.add(enc);
      await socket.flush();

      // Echo loop
      while (true) {
        final rec = await readRecord();
        final pt = session.recordLayer.decrypt(rec);
        print("📥 AppData: ${String.fromCharCodes(pt)}");
      }
    } catch (e, st) {
      print("❌ TLS handshake error: $e");
      print(st);
      socket.destroy();
    }
  }
}
