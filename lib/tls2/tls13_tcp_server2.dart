// ============================================================================
// ✅ TLS 1.3 TCP Server — CORRECTED FOR 2‑PARAM ClientHello API
// RFC 8446 compatible
// ============================================================================

import 'dart:io';
import 'dart:typed_data';
import 'dart:async';

import 'tls13_server_session2.dart';
import 'tls_record_layer.dart';

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
// TCP SERVER
// ============================================================================

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

  Future<void> _handleClient(Socket socket) async {
    final List<int> incoming = [];
    Completer<void>? waiter;

    socket.listen(
      (data) {
        incoming.addAll(data);
        if (waiter != null && !waiter!.isCompleted) {
          waiter!.complete();
        }
      },
      onError: (e) => print("❌ Socket error: $e"),
      onDone: () => print("🔌 Client disconnected"),
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

    Uint8List buildPlainHandshake(Uint8List handshake) {
      final rec = Uint8List.fromList([
        TLSContentType.handshake,
        0x03,
        0x03,
        (handshake.length >> 8) & 0xFF,
        handshake.length & 0xFF,
        ...handshake,
      ]);
      dumpHandshake("TX ServerHello", handshake);
      dumpRecord("TX ServerHello", rec);
      return rec;
    }

    try {
      final session = Tls13ServerSession(
        certificate: serverCertificate,
        privateKey: serverPrivateKey,
      );

      Uint8List handshakeMerged;

      // ----------------------------------------------------------------------
      // Read full ClientHello (may be fragmented)
      // ----------------------------------------------------------------------
      while (true) {
        final rec = await readRecord();
        if (rec[0] != TLSContentType.handshake) continue;

        final hs = rec.sublist(5);
        if (hs[0] != 1) continue; // NOT ClientHello

        final totalLen = (hs[1] << 16) | (hs[2] << 8) | hs[3];

        if (!rec.contains(0x2B)) {
          print("⚠️ TLS 1.2 probe ignored.");
          continue;
        }

        print("✅ TLS 1.3 ClientHello detected.");

        final merged = BytesBuilder();
        merged.add(hs);

        int collected = hs.length - 4;

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
        dumpHandshake("RX ClientHello (full)", handshakeMerged);
        break;
      }

      // ----------------------------------------------------------------------
      // ✅ PASS BOTH FORMS TO SESSION
      // ----------------------------------------------------------------------
      final clientHelloBody = handshakeMerged.sublist(4);

      final serverHello = session.handleClientHello(
        handshakeMerged, // FULL handshake bytes (transcript)
        clientHelloBody, // BODY ONLY (parsing)
      );

      socket.add(buildPlainHandshake(serverHello));
      await socket.flush();
      print("📤 Sent ServerHello");

      final ee = session.buildEncryptedExtensions();
      dumpRecord("TX EncryptedExtensions", ee);
      socket.add(ee);
      await socket.flush();

      final cert = session.buildCertificateMessage();
      dumpRecord("TX Certificate", cert);
      socket.add(cert);
      await socket.flush();

      final cv = session.buildCertificateVerifyMessage();
      dumpRecord("TX CertificateVerify", cv);
      socket.add(cv);
      await socket.flush();

      final fin = session.buildFinishedMessage();
      dumpRecord("TX Finished", fin);
      socket.add(fin);
      await socket.flush();

      // ----------------------------------------------------------------------
      // Client Finished
      // ----------------------------------------------------------------------
      final cf = await readRecord();
      final pt = session.recordLayer.decrypt(cf);
      dumpHandshake("RX Client Finished", pt);

      print("✅ TLS 1.3 handshake complete.");
    } catch (e, st) {
      print("❌ TLS handshake error: $e");
      print(st);
      socket.destroy();
    }
  }
}
