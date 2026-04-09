import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'tls13_session_server.dart';

// import 'tls_server_session.dart';

Future<void> main() async {
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 8443);
  stdout.writeln('Listening on https://127.0.0.1:8443');

  await for (final sock in server) {
    () async {
      final session = TLS13ServerSession(sock);
      try {
        await session.handshake();

        final req = await session.recv();
        final reqStr = utf8.decode(req, allowMalformed: true);
        stdout.writeln('Got request:\n$reqStr');

        final body = 'hello from toy tls server\n';
        final resp =
            'HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n$body';
        await session.send(Uint8List.fromList(utf8.encode(resp)));
      } catch (e) {
        stderr.writeln('session error: $e');
      } finally {
        await session.close();
      }
    }();
  }
}
