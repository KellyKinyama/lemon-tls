import 'dart:io';

void main() {
  final log = File('keylog.txt');

  SecureSocket.connect(
        "127.0.0.1",
        4433,
        onBadCertificate: (cert) => true,
        keyLog: (line) => log.writeAsStringSync(line, mode: FileMode.append),
      )
      .then((s) {
        print("Connected to server");
        s.listen(
          (data) {
            print("Received from server: ${String.fromCharCodes(data)}");
          },
          onDone: () {
            print("Connection closed by server");
          },
          onError: (err) {
            print("Socket error: $err");
          },
        );

        // Send a simple message to the server
        final message = "Hello, TLS Server!";
        print("Sending to server: $message");
        s.write(message);
      })
      .catchError((err) {
        print("Failed to connect: $err");
      });
}
