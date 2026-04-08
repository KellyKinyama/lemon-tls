import 'dart:io';
import 'dart:typed_data';
import 'dart:async';

import 'package:hex/hex.dart';

import 'tls13_client_session.dart';
import 'tls_record_layer.dart';
import 'tls_constants.dart';
// import 'package:lemon_tls/tls1_3.dart';

Future<void> main() async {
  final socket = await Socket.connect('127.0.0.1', 4433);

  socket.listen(
    (data) {
      print("📥 Received from server:");
      print(HEX.encode(data));
    },
    onDone: () {
      print("✅ Connection closed by server.");
    },
    onError: (err) {
      print("❌ Socket error: $err");
    },
  );

  print("📤 Sending ClientHello (${clientHello.length} bytes)...");
  socket.add(clientHello); // ✅ CORRECT — binary safe
  await socket.flush();

  // final log = File('keylog.txt');

  // SecureSocket.connect(
  //   '127.0.0.1',
  //   4433,
  //   // onBadCertificate: (certificate) => false,
  //   keyLog: (line) => log.writeAsStringSync(line, mode: FileMode.append),
  // ).then((socket) {
  //   socket.listen((onData) {
  //     print("received: ${onData}");
  //   });
  //   // print("Data to send: $client_to_server");
  //   // socket.write(client_to_server);
  // });
}

// ============================================================================
// ✅ TLS 1.3 TCP Server — FIXED (minimal changes)
// ============================================================================

class Tls13TcpClient {
  final int port;
  final Uint8List clientCertificate;
  final Uint8List clientPrivateKey;

  Tls13TcpClient({
    required this.port,
    required this.clientCertificate,
    required this.clientPrivateKey,
  });

  Future<void> connect() async {
    final client = await Socket.connect("127.0.0.1", 4433);
    print("✅ TLS 1.3 Server listening on port $port...");

    client.listen(
      (onData) {
        print("🔌 Client connected to ${client.remoteAddress.address}:$port");
        _handleClient(onData, client);
      },
      onError: (e) => print("❌ Socket error: $e"),
      onDone: () => print("🔌 Client disconnected"),
      cancelOnError: false,
    );
  }

  Future<void> _handleClient(Uint8List onData, Socket socket) async {
    final List<int> incoming = [];
    Completer<void>? waiter;

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
      final session = Tls13ClientSession(
        certificate: clientCertificate,
        privateKey: clientPrivateKey,
      );

      Uint8List handshakeMerged = Uint8List(0);

      while (true) {
        final rec = await readRecord();

        if (rec[0] != TLSContentType.handshake) continue;

        final hs = rec.sublist(5);

        if (hs[0] != 1) continue;

        final totalLen = (hs[1] << 16) | (hs[2] << 8) | hs[3];

        // naive detection, fix later if needed
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
          if (hs2[0] != 1) throw Exception("Bad fragmentation");

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

      final clientHelloBody = handshakeMerged.sublist(4);

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

      final cf = await readRecord();
      session.recordLayer.decrypt(cf);
      print("✅ Client Finished verified.");

      print("✅ Handshake complete — switching to Application Data.");

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

final clientHello = Uint8List.fromList(
  HEX.decode(
    "16 03 01 00 f8 01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 08 13 02 13 03 13 01 00 ff 01 00 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0b 00 04 03 00 01 02 00 0a 00 16 00 14 00 1d 00 17 00 1e 00 19 00 18 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 16 00 00 00 17 00 00 00 0d 00 1e 00 1c 04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08 05 08 06 04 01 05 01 06 01 00 2b 00 03 02 03 04 00 2d 00 02 01 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54",
  ),
);
