// wrapper_quic.dart
import 'dart:typed_data';

import 'byte_reader.dart';

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

/// QUIC Wrapper
///
/// QUIC does **not** use TLS RecordHeader.
/// Instead, each QUIC packet has:
///
///   QUIC_HEADER (variable length)
///   ENCRYPTED_PAYLOAD (ciphertext + auth tag)
///
/// This wrapper lets you store a fully formed QUIC packet split as:
///   - headerBytes    (unencrypted QUIC header / protected header)
///   - payload        (ciphertext || auth tag)
///
/// You can use this to serialize / deserialize QUIC packets.
class QuicPacketWrapper {
  /// QUIC packet header *before* payload protection.
  final Uint8List headerBytes;

  /// AEAD Encrypted content:
  ///   ciphertext || auth_tag (last 16 bytes)
  Uint8List payload;

  QuicPacketWrapper({required this.headerBytes, required this.payload});

  /// Deserialize from raw bytes when reading from a Datagram
  static QuicPacketWrapper deserialize(Uint8List data) {
    final r = ByteReader(data);

    // NOTE:
    // QUIC packet headers are variable length.
    //
    // For INITIAL/HANDSHAKE packets:
    //   - first byte indicates long header and PN length
    //   - DCID length + DCID
    //   - SCID length + SCID
    //   - Token length + token
    //   - Length field
    //   - Packet number (1-4 bytes)
    //
    // Because each QUIC implementation determines header length AFTER
    // reading header fields, the wrapper **cannot guess header length**.
    //
    // QUIC callers must parse header first, then call this with:
    //   QuicPacketWrapper(header, payload)
    //
    // So deserialize() is not suitable for QUIC without context.
    throw StateError(
      "QuicPacketWrapper.deserialize() requires header length. "
      "QUIC headers are variable-length. "
      "Call new QuicPacketWrapper(headerBytes, payload) manually.",
    );
  }

  /// Serialize back to full QUIC packet
  Uint8List serialize() => _concat([headerBytes, payload]);

  /// Last 16 bytes = AEAD authentication tag
  Uint8List get authTag {
    if (payload.length < 16) {
      throw StateError("Payload too short for auth tag");
    }
    return payload.sublist(payload.length - 16);
  }

  /// Ciphertext (everything except auth tag)
  Uint8List get encryptedData {
    if (payload.length < 16) {
      throw StateError("Payload too short for ciphertext");
    }
    return payload.sublist(0, payload.length - 16);
  }
}
