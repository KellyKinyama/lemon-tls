import 'dart:typed_data';

import 'byte_reader.dart';
import 'record_header.dart' show RecordHeader;
import 'server_hello.dart';

/// Minimal reader interface (compatible with the ByteReader used elsewhere).
abstract class ReadableBytes {
  Uint8List readBytes(int n);
}

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

class Wrapper {
  final RecordHeader recordHeader;

  /// Contains: encrypted_data || auth_tag (last 16 bytes).
  ///
  /// Use [Uint8List] (fixed) like Python `bytes`/`bytearray` content.
  /// If you need mutability, wrap with `Uint8List.fromList(...)`.
  Uint8List payload;

  Wrapper({required this.recordHeader, required this.payload});

  static Wrapper deserialize(ByteReader byteStream) {
    final rh = RecordHeader.deserialize(byteStream.readBytes(5));
    final payload = Uint8List.fromList(byteStream.readBytes(rh.size));
    return Wrapper(recordHeader: rh, payload: payload);
  }

  Uint8List serialize() {
    return _concat([recordHeader.serialize(), payload]);
  }

  /// Last 16 bytes of [payload].
  Uint8List get authTag {
    if (payload.length < 16) {
      throw StateError('Payload too short for auth_tag (need >= 16).');
    }
    return payload.sublist(payload.length - 16);
  }

  /// Everything except the last 16 bytes of [payload].
  Uint8List get encryptedData {
    if (payload.length < 16) {
      throw StateError('Payload too short for encrypted_data (need >= 16).');
    }
    return payload.sublist(0, payload.length - 16);
  }
}
