import 'dart:typed_data';
import '../hkdf.dart';
import '../hash.dart';

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

class FinishedMessage {
  /// per TLS 1.3: verify_data = HMAC(finished_key, transcript_hash)
  static Uint8List build({
    required Uint8List finishedKey,
    required Uint8List transcriptHash,
  }) {
    final verify = hmacSha256(key: finishedKey, data: transcriptHash);

    final hdr = [0x14, 0x00, 0x00, verify.length];

    return Uint8List.fromList([...hdr, ...verify]);
  }
}
