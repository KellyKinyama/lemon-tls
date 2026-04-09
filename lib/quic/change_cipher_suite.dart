import 'dart:typed_data';

import 'byte_reader.dart';

/// QUIC DOES NOT USE ChangeCipherSpec.
/// Some TLS implementations send it for middlebox compatibility.
/// QUIC endpoints MUST ignore it.
///
/// This class simply wraps the raw bytes so your QUIC server can skip them.
class ChangeCipherSuite {
  /// Raw CCS payload (normally: [0x01])
  final Uint8List payload;

  ChangeCipherSuite({required this.payload});

  /// QUIC CCS format inside a CRYPTO frame:
  /// It's NOT a TLSPlaintext. It is just handshake bytes.
  ///
  /// If you're reading raw CRYPTO stream data, CCS */
  static ChangeCipherSuite deserialize(ByteReader r) {
    // RFC 8446 CCS format:
    //   struct {
    //       ContentType type = change_cipher_spec(20);
    //       ProtocolVersion legacy_version = 0x0303;
    //       opaque fragment[1] = { 0x01 };
    //   } ChangeCipherSpec;
    //
    // But QUIC SHOULD NOT receive full CCS records, only:
    //   message_type = 20 (0x14)
    //   body = [0x01]
    //
    // Your parser should simply read the message_type byte and ignore the rest.

    if (r.remaining < 2) {
      throw StateError("Not enough bytes for ChangeCipherSpec");
    }

    final msgType = r.readUint8(); // expect 0x14
    if (msgType != 0x14) {
      throw StateError(
        "Expected CCS (0x14), got 0x${msgType.toRadixString(16)}",
      );
    }

    // The CCS "payload" is always one byte: 0x01
    final value = r.readUint8();
    return ChangeCipherSuite(payload: Uint8List.fromList([value]));
  }

  /// Serialize QUIC-lightweight CCS form:
  /// Only the handshake message type + the single byte 0x01
  Uint8List serialize() {
    return Uint8List.fromList([
      0x14, // CCS handshake type
      ...payload,
    ]);
  }
}
