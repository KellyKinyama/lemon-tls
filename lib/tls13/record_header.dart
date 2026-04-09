import 'dart:typed_data';

class RecordHeader {
  final int rtype;
  int size;
  final int legacyProtoVersion;

  RecordHeader({
    required this.rtype,
    required this.size,
    this.legacyProtoVersion = 0x0303,
  });

  /// TLS record header is 5 bytes:
  ///  - type: 1 byte
  ///  - legacy_version: 2 bytes (big-endian)
  ///  - length: 2 bytes (big-endian)
  factory RecordHeader.deserialize(Uint8List data) {
    if (data.length < 5) {
      throw ArgumentError(
        'RecordHeader requires at least 5 bytes, got ${data.length}.',
      );
    }

    final recordType = data[0];
    final bd = ByteData.sublistView(data, 1, 5);
    final legacyProtoVersion = bd.getUint16(0, Endian.big);
    final size = bd.getUint16(2, Endian.big);

    return RecordHeader(
      rtype: recordType,
      legacyProtoVersion: legacyProtoVersion,
      size: size,
    );
  }

  Uint8List serialize() {
    final out = Uint8List(5);
    final bd = ByteData.sublistView(out);
    bd.setUint8(0, rtype & 0xFF);
    bd.setUint16(1, legacyProtoVersion & 0xFFFF, Endian.big);
    bd.setUint16(3, size & 0xFFFF, Endian.big);
    return out;
  }
}
