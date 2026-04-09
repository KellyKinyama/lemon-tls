import 'dart:typed_data';

import 'package:lemon_tls/tls13/server_hello.dart';

import 'record_header.dart' show RecordHeader;

/// Minimal reader interface (compatible with the ByteReader used elsewhere).
// abstract class ReadableBytes {
//   Uint8List readBytes(int n);
// }

Uint8List _concat(List<Uint8List> parts) {
  final total = parts.fold<int>(0, (n, p) => n + p.length);
  final out = Uint8List(total);
  var off = 0;
  for (final p in parts) {
    out.setRange(off, off + p.length, p);
    off += p.length;
  }
  return out;
}

class ChangeCipherSuite {
  final RecordHeader recordHeader;
  final Uint8List payload;

  ChangeCipherSuite({required this.recordHeader, required this.payload});

  static ChangeCipherSuite deserialize(ByteReader byteStream) {
    final rh = RecordHeader.deserialize(byteStream.readBytes(5));
    final payload = byteStream.readBytes(rh.size);
    return ChangeCipherSuite(recordHeader: rh, payload: payload);
  }

  Uint8List serialize() {
    return _concat([recordHeader.serialize(), payload]);
  }
}
