import 'dart:typed_data';
// import '../byte_reader.dart';

Uint8List _u8(int v) => Uint8List.fromList([v & 0xff]);
Uint8List _u16(int v) {
  final x = Uint8List(2);
  x[0] = (v >> 8) & 0xff;
  x[1] = v & 0xff;
  return x;
}

Uint8List _concat(List<Uint8List> xs) {
  final total = xs.fold(0, (a, b) => a + b.length);
  final out = Uint8List(total);
  int o = 0;
  for (final b in xs) {
    out.setRange(o, o + b.length, b);
    o += b.length;
  }
  return out;
}

/// QUIC‑toy EncryptedExtensions:
/// No ALPN, no QUIC transport params, no SNI response.
class EncryptedExtensions {
  static Uint8List build() {
    final extensions = Uint8List(0); // no extensions

    final body = _concat([_u16(extensions.length), extensions]);

    final header = [
      0x08,
      (body.length >> 16) & 0xff,
      (body.length >> 8) & 0xff,
      body.length & 0xff,
    ];

    return Uint8List.fromList([...header, ...body]);
  }
}
