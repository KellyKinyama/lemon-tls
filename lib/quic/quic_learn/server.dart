import 'dart:convert';
import 'dart:io';

Future<void> main() async {
  final socket = await RawDatagramSocket.bind(
    "127.0.0.1",
    // int.parse(arguments[0]),
    4433,
  );
  print("listening ip:${socket.address.address}:${socket.port}");

  socket.listen((ev) {
    if (ev == RawSocketEvent.read) {
      final dg = socket.receive();
      if (dg != null) {
        // _onPacket(dg);
        print("Data datagram received: ${utf8.decode(dg.data)}");
        socket.send(dg.data, InternetAddress("127.0.0.1"), dg.port);
      }
    }
  });

  await Future.delayed(Duration(minutes: 10));
  socket.close();
}
