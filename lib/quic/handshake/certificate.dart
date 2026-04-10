import 'dart:typed_data';

Uint8List buildCertificateMessage(List<Uint8List> certChain) {
  final builder = BytesBuilder();

  // Context length = 0 for QUIC/TLS 1.3
  builder.addByte(0x00);

  // Build certificate list
  final certListBuilder = BytesBuilder();

  for (final cert in certChain) {
    // Cert length (3 bytes)
    certListBuilder.add([
      (cert.length >> 16) & 0xff,
      (cert.length >> 8) & 0xff,
      cert.length & 0xff,
    ]);

    // Certificate data
    certListBuilder.add(cert);

    // Extensions length = 0 (no per‑certificate extensions)
    certListBuilder.add([0x00, 0x00]);
  }

  final certList = certListBuilder.toBytes();

  // Certificate_list length (3 bytes)
  builder.add([
    (certList.length >> 16) & 0xff,
    (certList.length >> 8) & 0xff,
    certList.length & 0xff,
  ]);

  builder.add(certList);

  final body = builder.toBytes();

  // Handshake header (type=0x0B)
  final header = Uint8List.fromList([
    0x0B,
    (body.length >> 16) & 0xff,
    (body.length >> 8) & 0xff,
    body.length & 0xff,
  ]);

  return Uint8List.fromList([...header, ...body]);
}
