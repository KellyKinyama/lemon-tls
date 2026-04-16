import 'dart:convert';
import 'dart:io';

Future<void> main() async {
  final socket = await RawDatagramSocket.bind("127.0.0.1", 0);

  socket.listen((ev) {
    if (ev == RawSocketEvent.read) {
      final dg = socket.receive();
      if (dg != null) {
        // _onPacket(dg);
        print("Data datagram received: ${dg.data}");
      }
    }
  });

  socket.send(utf8.encode("hello"), InternetAddress("127.0.0.1"), 4433);
}
