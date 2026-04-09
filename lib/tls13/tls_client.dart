import 'dart:convert';
import 'dart:typed_data';

// import 'tls13_session6.dart';
import 'tls_session7.dart';
// import 'tls_session.dart';

void main() async {
  final session = TLS13Session(
    host: Uint8List.fromList(utf8.encode('example.com')),
    port: 443,
  );

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

  final resp = await session.recv();
  print(utf8.decode(resp));

  /// Receive response
  final response = await session.recv();

  print(utf8.decode(response));

  await session.close();
}
