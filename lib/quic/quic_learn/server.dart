import 'dart:io';

Future<void> main(List<String> arguments) async {
  print("args: $arguments");
  int port;
  try {
    port = int.parse(arguments[0]);
  } catch (e, st) {
    print(e);
    print(st);
    port = 0;
  }

  final socket = await RawDatagramSocket.bind(
    "127.0.0.1",
    // int.parse(arguments[0]),
    port,
  );
  print("listening ip:${socket.address.address}:${socket.port}");

  socket.listen((ev) {
    if (ev == RawSocketEvent.read) {
      final dg = socket.receive();
      if (dg != null) {
        // _onPacket(dg);
        print("Data datagram received: ${dg.data}");
        socket.send(dg.data, InternetAddress("127.0.0.1"), dg.port);
      }
    }
  });
}
