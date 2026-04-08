import 'dart:typed_data';
import 'dart:io';

import '../tls13_tcp_server.dart';

void main() async {
  // Load your certificate (DER)
  final cert = await File("cert.der").readAsBytes();

  // Load your raw P‑256 private key bytes
  final priv = await File("privkey.bin").readAsBytes();

  final server = Tls13TcpServer(
    port: 4433,
    serverCertificate: Uint8List.fromList(cert),
    serverPrivateKey: Uint8List.fromList(priv),
  );

  await server.start();
}
