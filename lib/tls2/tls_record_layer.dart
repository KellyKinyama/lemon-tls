// ============================================================================
// TLS 1.3 Record Layer (AES‑128‑GCM) — FINAL FIXED VERSION (MINIMAL CHANGES)
// RFC 8446 §§5.2, 5.3
// ============================================================================

import 'dart:typed_data';

import 'cipher/aes_gcm.dart' as aes_gcm;

// ============================================================================
// TLS ContentType constants
// ============================================================================

class TLSContentType {
  static const int invalid = 0x00;
  static const int alert = 0x15;
  static const int handshake = 0x16; // inner content type
  static const int applicationData = 0x17; // outer record type
}

// ============================================================================
// TLS 1.3 NONCE = IV XOR sequence_number
// ============================================================================

Uint8List tls13Nonce(Uint8List iv, int sequence) {
  final out = Uint8List.fromList(iv);
  for (int i = 0; i < 8; i++) {
    out[out.length - 1 - i] ^= (sequence >> (8 * i)) & 0xFF;
  }
  return out;
}

// ============================================================================
// TLS 1.3 RECORD ENCRYPT
// ============================================================================

Uint8List tls13EncryptRecord({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List plaintext,
  required int sequence,
}) {
  // ---------------------------------------------------------
  // TLSInnerPlaintext = content || inner_content_type
  // (padding omitted — allowed by RFC 8446)
  // ---------------------------------------------------------
  final innerPlaintext = Uint8List.fromList([
    ...plaintext,
    TLSContentType.handshake,
  ]);

  // ---------------------------------------------------------
  // Build record header (used as AEAD AAD)
  // ---------------------------------------------------------
  final header = Uint8List(5);
  header[0] = TLSContentType.applicationData;
  header[1] = 0x03;
  header[2] = 0x03;

  // ciphertext_len = innerPlaintext + GCM tag (16 bytes)
  final int ciphertextLen = innerPlaintext.length + 16;
  header[3] = (ciphertextLen >> 8) & 0xFF;
  header[4] = ciphertextLen & 0xFF;

  // ---------------------------------------------------------
  // Nonce
  // ---------------------------------------------------------
  final nonce = tls13Nonce(iv, sequence);

  // ---------------------------------------------------------
  // Encrypt (ciphertext || tag)
  // ---------------------------------------------------------
  final encrypted = aes_gcm.encrypt(
    key,
    innerPlaintext,
    nonce,
    header, // AAD
  );

  return Uint8List.fromList([...header, ...encrypted]);
}

// ============================================================================
// TLS 1.3 RECORD DECRYPT (FIXED)
// ============================================================================

Uint8List tls13DecryptRecord({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List record,
  required int sequence,
}) {
  int offset = 0;

  final outerType = record[offset++];
  if (outerType != TLSContentType.applicationData) {
    throw Exception("Unexpected TLS record type: $outerType");
  }

  // legacy record version
  offset += 2;

  final int length = (record[offset++] << 8) | record[offset++];
  final ciphertext = record.sublist(offset, offset + length);

  final nonce = tls13Nonce(iv, sequence);

  // AAD = full 5‑byte header
  final aad = record.sublist(0, 5);

  final decrypted = aes_gcm.decrypt(key, ciphertext, nonce, aad);

  if (decrypted.isEmpty) {
    throw Exception("TLSInnerPlaintext empty");
  }

  // ---------------------------------------------------------
  // ✅ FIX: Strip TLS 1.3 padding BEFORE reading inner type
  // ---------------------------------------------------------
  int i = decrypted.length - 1;
  while (i >= 0 && decrypted[i] == 0x00) {
    i--;
  }

  if (i < 0) {
    throw Exception("Invalid TLSInnerPlaintext (all padding)");
  }

  final int innerType = decrypted[i];
  if (innerType != TLSContentType.handshake &&
      innerType != TLSContentType.applicationData) {
    throw Exception(
      "Invalid inner TLS content type: 0x${innerType.toRadixString(16)}",
    );
  }

  return decrypted.sublist(0, i);
}

// ============================================================================
// RECORD LAYER STATE MACHINE (UNCHANGED API)
// ============================================================================

class TlsRecordLayer {
  int writeSeq = 0;
  int readSeq = 0;

  late Uint8List clientKey;
  late Uint8List clientIV;
  late Uint8List serverKey;
  late Uint8List serverIV;

  void setHandshakeKeys({
    required Uint8List clientKey,
    required Uint8List clientIV,
    required Uint8List serverKey,
    required Uint8List serverIV,
  }) {
    this.clientKey = clientKey;
    this.clientIV = clientIV;
    this.serverKey = serverKey;
    this.serverIV = serverIV;
    resetHandshakeSequence();
  }

  void resetHandshakeSequence() {
    writeSeq = 0;
    readSeq = 0;
  }

  // SERVER → CLIENT
  Uint8List encrypt(Uint8List plaintext) {
    final record = tls13EncryptRecord(
      key: serverKey,
      iv: serverIV,
      plaintext: plaintext,
      sequence: writeSeq,
    );
    writeSeq++;
    return record;
  }

  // CLIENT → SERVER
  Uint8List decrypt(Uint8List recordBytes) {
    final pt = tls13DecryptRecord(
      key: clientKey,
      iv: clientIV,
      record: recordBytes,
      sequence: readSeq,
    );
    readSeq++;
    return pt;
  }
}

// ============================================================================

void main() {
  print("TLS 1.3 Record Layer loaded (final, correct, non-breaking).");
}
