import 'dart:typed_data';

import 'tls_messages.dart';

Uint8List _u8(int v) => Uint8List.fromList([v & 0xff]);
Uint8List _u16be(int v) {
  final x = Uint8List(2);
  x[0] = (v >> 8) & 0xff;
  x[1] = v & 0xff;
  return x;
}

Uint8List buildEncryptedExtensions(List<TlsExtension> extensions) {
  // final builder = BytesBuilder();

  // Build extension block
  final extBytes = BytesBuilder();
  for (final ext in extensions) {
    extBytes.add(_u16be(ext.type));
    extBytes.add(_u16be(ext.data.length));
    extBytes.add(ext.data);
  }

  final extList = extBytes.toBytes();

  // Prepend extension list length
  final body = BytesBuilder();
  body.add(_u16be(extList.length));
  body.add(extList);

  final bodyBytes = body.toBytes();

  // TLS Handshake Header: type=0x08, length=3 bytes
  final header = Uint8List.fromList([
    0x08,
    (bodyBytes.length >> 16) & 0xff,
    (bodyBytes.length >> 8) & 0xff,
    bodyBytes.length & 0xff,
  ]);

  return Uint8List.fromList([...header, ...bodyBytes]);
}
