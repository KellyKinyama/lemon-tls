import 'dart:convert';
import 'dart:typed_data';

// import 'tls13_session6.dart';
import 'tls_session7.dart';
// import 'tls_session.dart';

void main() async {
  final session = TLS13Session(
    host: Uint8List.fromList(utf8.encode('example.com')),
    // host: utf8.encode("localhost"),
    // port: 8443,
    port: 443,
  );

  // final session = TLS13Session(
  //   // host: Uint8List.fromList(utf8.encode('example.com')),
  //   host: utf8.encode("localhost"),
  //   port: 8443,
  //   // port: 443,
  // );

  await session.connect();

  /// Send HTTP request
  final request = '''
GET / HTTP/1.1
Host: example.com
User-Agent: dart-tls
Accept: */*

''';

  await session.send(Uint8List.fromList(utf8.encode(request)));

  // await session.send(
  //   utf8.encode(
  //     "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
  //   ),
  // );

  // Read until we get some application data (or EOF/timeout depending on implementation).
  final out = BytesBuilder(copy: false);
  while (true) {
    final chunk = await session.recv();
    if (chunk.isEmpty) break;
    out.add(chunk);

    // stop early once we have headers
    final s = utf8.decode(out.toBytes(), allowMalformed: true);
    if (s.contains('\r\n\r\n')) break;
  }

  print(utf8.decode(out.toBytes(), allowMalformed: true));

  await session.close();
}
