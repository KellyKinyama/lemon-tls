import 'dart:io';

import 'package:lemon_tls/handlers/server.dart';

import '../handlers/extensions/extension2.dart';

ServerHandler handler = ServerHandler();

void serve() {
  final tcpIp = InternetAddress.loopbackIPv4;
  int port = 443;
  ServerSocket.bind(tcpIp, port)
      .then((serverSocket) {
        print(
          'Server listening on tcp:${serverSocket.address.address}:${serverSocket.port}',
        );

        serverSocket.listen((Socket clientSocket) async {
          print(
            'Client connected from ${clientSocket.remoteAddress}:${clientSocket.remotePort}',
          );

          //SecureServerSocket.secureServer();
          msgToClient(List<int> data) {
            print("Sending to client");
            clientSocket.write(data);
          }

          msgFromClient(List<int> data) {
            // var tx = SipTransport(
            //   sockaddr_in(
            //     clientSocket.remoteAddress.address,
            //     clientSocket.remotePort,
            //     'tcp',
            //   ),
            //   sockaddr_in(tcpIp, tcpPort, 'tcp'),
            //   msgToClient,
            // );
            handler.handle(data, clientSocket, msgToClient);
          }

          // Handle data from the client
          clientSocket.listen(
            (List<int> data) {
              // final receivedData = String.fromCharCodes(data).trim();
              // print('Received data: $receivedData');

              msgFromClient(data);

              // Send a response back to the client
              //clientSocket.write('Hello from server!\n');
            },
            onError: (error, stack) {
              print("{error: $error, stack: $stack}");
            },
          );

          // Handle client disconnection
          clientSocket.done.then((_) {
            print('Client disconnected.');
          });
        });
      })
      .catchError((error) {
        print('Error creating server: $error');
      });
}

void main() {
  initParsing();
  serve();
}
