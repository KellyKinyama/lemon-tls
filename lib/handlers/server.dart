import 'dart:io';

import '../tcp_client.dart';

class ServerHandler {
  Map<String, TcpClient> clients = {};

  ServerHandler();

  void handle(
    List<int> request,
    Socket transport,
    Null Function(List<int> data) msgToClient,
  ) {
    if (clients["${transport.address.address}:${transport.port}"] == null) {
      clients["${transport.address.address}:${transport.port}"] = TcpClient(
        transport,
      );

      clients["${transport.address.address}:${transport.port}"]!.handle(
        request,
        msgToClient,
      );
    } else {
      clients["${transport.address.address}:${transport.port}"]!.handle(
        request,
        msgToClient,
      );
    }
  }
}
