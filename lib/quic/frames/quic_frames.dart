import 'dart:typed_data';

/// Represents a QUIC CRYPTO frame (type 0x06).
class CryptoFrame {
  final int offset;
  final Uint8List data;

  CryptoFrame({required this.offset, required this.data});

  @override
  String toString() => "CryptoFrame(offset=$offset, len=${data.length})";
}
