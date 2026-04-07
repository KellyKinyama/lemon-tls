// ===========================================================
// TLS 1.3 Record Layer (Complete Consolidated Version)
// ===========================================================

import 'dart:typed_data';
import 'package:hex/hex.dart';

import '../cipher/aes_gcm.dart'; // ← your AES‑GCM encrypt/decrypt
import '../tls1_3.dart'; // ← HKDF, crypto utils, ContentType, etc.
import 'message_types.dart';

// ===========================================================
// Uint24 Utility
// ===========================================================

class Uint24 {
  final int value;

  Uint24(this.value);

  factory Uint24.fromBytes(Uint8List bytes) {
    return Uint24((bytes[0] << 16) | (bytes[1] << 8) | bytes[2]);
  }

  Uint8List toBytes() {
    return Uint8List(3)
      ..[0] = (value >> 16) & 0xFF
      ..[1] = (value >> 8) & 0xFF
      ..[2] = value & 0xFF;
  }

  @override
  String toString() => "Uint24($value)";
}

// ===========================================================
// ProtocolVersion
// ===========================================================

class ProtocolVersion {
  final int major;
  final int minor;

  ProtocolVersion(this.major, this.minor);

  @override
  String toString() => '$major.$minor';
}

// ===========================================================
// TLSPlaintext (Unencrypted Record, used only before handshake keys)
// ===========================================================

class TLSPlaintext {
  ContentType type;
  ProtocolVersion legacy_record_version;
  int length;
  Uint8List fragment;

  TLSPlaintext(
    this.type,
    this.legacy_record_version,
    this.length,
    this.fragment,
  );

  factory TLSPlaintext.fromBytes(Uint8List bytes) {
    int offset = 0;

    ContentType type = ContentType.fromBytes(bytes[offset++]);

    ProtocolVersion version = ProtocolVersion(bytes[offset], bytes[offset + 1]);
    offset += 2;

    int length = ByteData.sublistView(bytes).getUint16(offset);
    offset += 2;

    Uint8List fragment = bytes.sublist(offset, offset + length);

    return TLSPlaintext(type, version, length, fragment);
  }

  @override
  String toString() {
    final frag = fragment.length > 10
        ? HEX.encode(fragment.sublist(0, 10)) + "..."
        : HEX.encode(fragment);

    return """
Record Layer {
  type: $type,
  version: $legacy_record_version,
  length: $length,
  fragment: $frag
}""";
  }
}

// ===========================================================
// TLS 1.3 Nonce (IV XOR sequence_number) — RFC 8446 §5.3
// ===========================================================

Uint8List tls13Nonce(Uint8List iv, int sequence) {
  final out = Uint8List.fromList(iv);
  for (int i = 0; i < 8; i++) {
    out[out.length - 1 - i] ^= (sequence >> (8 * i)) & 0xFF;
  }
  return out;
}

// ===========================================================
// Encrypt TLS 1.3 Record
// ===========================================================

Uint8List buildTlsCiphertextRecord({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List plaintext,
  required int sequence,
}) {
  // TLS 1.3 always appends inner content type to plaintext
  final pt = Uint8List.fromList([
    ...plaintext,
    ContentType.handshake.value, // inner content type
  ]);

  // TLS record header (AEAD associated data)
  final header = Uint8List(5)
    ..[0] = ContentType.application_data.value
    ..[1] = 0x03
    ..[2] = 0x03; // legacy version (TLS 1.2 in header)

  // Build nonce = IV XOR sequence_number
  final nonce = tls13Nonce(iv, sequence);

  // AES‑GCM
  final ciphertext = encrypt(key, pt, nonce, header);

  // Fill length
  final len = ciphertext.length;
  header[3] = (len >> 8) & 0xFF;
  header[4] = len & 0xFF;

  return Uint8List.fromList([...header, ...ciphertext]);
}

// ===========================================================
// Decrypt TLS 1.3 Record
// ===========================================================

Uint8List parseAndDecryptRecord({
  required Uint8List recordBytes,
  required Uint8List key,
  required Uint8List iv,
  required int sequence,
}) {
  int offset = 0;

  ContentType outerType = ContentType.fromBytes(recordBytes[offset++]);
  offset += 2; // skip legacy version
  final len = (recordBytes[offset++] << 8) | recordBytes[offset++];

  final ciphertext = recordBytes.sublist(offset, offset + len);

  // Associated data = header
  final header = recordBytes.sublist(0, 5);

  final nonce = tls13Nonce(iv, sequence);

  final decrypted = decrypt(key, ciphertext, nonce, header);

  // Last byte = real inner content type
  final innerType = decrypted.last;
  return decrypted.sublist(0, decrypted.length - 1);
}

// ===========================================================
// Record Layer Manager (handles sequence numbers + keys)
// ===========================================================

class TlsRecordLayer {
  int writeSeq = 0;
  int readSeq = 0;

  late Uint8List clientKey;
  late Uint8List clientIV;
  late Uint8List serverKey;
  late Uint8List serverIV;

  void setKeys({
    required Uint8List clientKey,
    required Uint8List clientIV,
    required Uint8List serverKey,
    required Uint8List serverIV,
  }) {
    this.clientKey = clientKey;
    this.clientIV = clientIV;
    this.serverKey = serverKey;
    this.serverIV = serverIV;
  }

  // Decrypt record from CLIENT → SERVER
  Uint8List decrypt(Uint8List recordBytes) {
    final pt = parseAndDecryptRecord(
      recordBytes: recordBytes,
      key: clientKey,
      iv: clientIV,
      sequence: readSeq,
    );
    readSeq++;
    return pt;
  }

  // Encrypt record from SERVER → CLIENT
  Uint8List encrypt(Uint8List plaintext) {
    final ct = buildTlsCiphertextRecord(
      key: serverKey,
      iv: serverIV,
      plaintext: plaintext,
      sequence: writeSeq,
    );
    writeSeq++;
    return ct;
  }
}
