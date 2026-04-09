// lib/handshake/certificate.dart
import 'dart:typed_data';

Uint8List _u8(int v) => Uint8List.fromList([v & 0xff]);
Uint8List _u16(int v) => Uint8List.fromList([(v >> 8) & 0xff, v & 0xff]);

Uint8List _u24(int v) =>
    Uint8List.fromList([(v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff]);

Uint8List _concat(List<Uint8List> xs) {
  final total = xs.fold(0, (s, b) => s + b.length);
  final out = Uint8List(total);
  int o = 0;
  for (final x in xs) {
    out.setRange(o, o + x.length, x);
    o += x.length;
  }
  return out;
}

/// TLS 1.3 Certificate message (QUIC-compatible)
Uint8List buildCertificateMessage(Uint8List certDer) {
  final certLen = _u24(certDer.length);

  final entry = _concat([
    certLen,
    certDer,
    _u16(0x0000), // extensions length = 0
  ]);

  final body = _concat([
    _u8(0x00), // certificate_request_context length = 0
    _u24(entry.length),
    entry,
  ]);

  final hdr = Uint8List.fromList([
    0x0B, // handshake type = certificate
    (body.length >> 16) & 0xff,
    (body.length >> 8) & 0xff,
    body.length & 0xff,
  ]);

  return Uint8List.fromList([...hdr, ...body]);
}
