import 'dart:typed_data';
import 'dart:io';

import '../tls13_tcp_client.dart';

void main() async {
  // Load your certificate (DER)
  final cert = await File("cert.der").readAsBytes();

  // Load your raw P‑256 private key bytes
  final priv = await File("privkey.bin").readAsBytes();

  final client = Tls13TcpClient(
    port: 4433,
    clientCertificate: Uint8List.fromList(cert),
    clientPrivateKey: Uint8List.fromList(priv),
  );

  await client.connect();
}
