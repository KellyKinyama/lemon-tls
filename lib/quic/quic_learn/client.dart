import 'dart:async';
import 'dart:convert';
import 'dart:io';

Future<void> main() async {
  final socket = await RawDatagramSocket.bind("127.0.0.1", 0);
  print("listening ip:${socket.address.address}:${socket.port}");
  socket.listen((ev) {
    if (ev == RawSocketEvent.read) {
      final dg = socket.receive();
      if (dg != null) {
        // _onPacket(dg);
        print("Data datagram received: ${utf8.decode(dg.data)}");
      }
    }
  });

  Timer.periodic(Duration(seconds: 2), (_) {
    socket.send(utf8.encode("hello"), InternetAddress("127.0.0.1"), 4433);
  });
}
