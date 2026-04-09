import 'dart:convert';
import 'dart:typed_data';

import 'tls13_session5.dart';
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

  /// Receive response
  final response = await session.recv();

  print(utf8.decode(response));

  await session.close();
}
