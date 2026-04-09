import 'dart:io';

import 'package:lemon_tls/tls1_3.dart';

void main() {
  // Socket.connect('127.0.0.1', 4433).then((socket) {
  //   socket.listen((onData) {
  //     print("received: ${onData}");
  //   });
  //   // print("Data to send: $client_to_server");
  //   socket.write(client_to_server3);
  //   // socket.flush();
  // });
  final log = File('keylog.txt');

  SecureSocket.connect(
    '127.0.0.1',
    8443,
    onBadCertificate: (certificate) => true,
    keyLog: (line) => log.writeAsStringSync(line, mode: FileMode.append),
  ).then((socket) {
    socket.listen((onData) {
      print("received: ${onData}");
    });
    // print("Data to send: $client_to_server");
    // socket.write(client_to_server);
  });
}
