// ============================================================================
// TLS 1.3 Record Layer (FastCrypt AES-GCM version)
// RFC 8446 Sections 5.2, 5.3
// ============================================================================

import 'dart:typed_data';
import 'package:hex/hex.dart';

import 'cipher/aes_gcm.dart' as aes_gcm;

// import '../../fast_crypt/fastcrypt.dart';

// ============================================================================
// TLS 1.3 Nonce = IV XOR sequence_number   (RFC 8446 §5.3)
// ============================================================================

Uint8List tls13Nonce(Uint8List iv, int sequence) {
  final out = Uint8List.fromList(iv);
  for (int i = 0; i < 8; i++) {
    out[out.length - 1 - i] ^= (sequence >> (8 * i)) & 0xFF;
  }
  return out;
}

// ============================================================================
// TLS 1.3 Encrypt Record
// ============================================================================
//
// struct {
//   ContentType type = application_data (0x17)
//   ProtocolVersion legacy_record_version = 0x0303
//   uint16 length
//   opaque encrypted_record[length]
// } TLSCiphertext;
//
// The *inner* plaintext is:
//
//   plaintext || ContentType(inner_type)
//
// and the AEAD associated data is the 5-byte header.
//
// ============================================================================

Uint8List tls13EncryptRecord({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List plaintext,
  required int sequence,
}) {
  // final crypt = FastCrypt();

  // Append inner content type = handshake or application_data
  final Uint8List pt = Uint8List.fromList([
    ...plaintext,
    TLSContentType.handshake, // For handshake records
  ]);

  // Build TLS 1.3 header (AEAD AAD)
  final header = Uint8List(5);
  header[0] = TLSContentType.applicationData; // always 0x17
  header[1] = 0x03; // legacy version
  header[2] = 0x03;
  // length will be set *after* AEAD encryption

  // Compute AEAD Nonce
  final nonce = tls13Nonce(iv, sequence);

  // Perform AES-GCM encryption via FastCrypt

  final encrypted = aes_gcm.encrypt(key, pt, nonce, header);
  // final encrypted = crypt.encryptBytes(pt, key: key, nonce: nonce, aad: header);

  // TLS 1.3 ciphertext = ciphertext || tag (16 bytes)
  final combined = encrypted;
  // final combined = Uint8List.fromList([
  //   ...encrypted.ciphertext,
  //   ...encrypted.tag,
  // ]);

  // Patch header length
  final len = combined.length;
  header[3] = (len >> 8) & 0xFF;
  header[4] = len & 0xFF;

  return Uint8List.fromList([...header, ...combined]);
}

// ============================================================================
// TLS 1.3 Decrypt Record
// ============================================================================
//
// Extracts header, tag, decrypts inner data, returns plaintext
// without the trailing content_type byte.
// ============================================================================

Uint8List tls13DecryptRecord({
  required Uint8List key,
  required Uint8List iv,
  required Uint8List record,
  required int sequence,
}) {
  // final crypt = FastCrypt();

  int offset = 0;

  int outerType = record[offset++];
  if (outerType != TLSContentType.applicationData) {
    throw Exception("Unexpected TLS record type: $outerType");
  }

  // Skip legacy version
  offset += 2;

  final length = (record[offset++] << 8) | record[offset++];
  final ciphertext = record.sublist(offset, offset + length);

  // Extract ciphertext + tag
  final Uint8List ct = ciphertext.sublist(0, ciphertext.length - 16);
  final Uint8List tag = ciphertext.sublist(ciphertext.length - 16);

  // Build AAD
  final aeadHeader = record.sublist(0, 5);

  final nonce = tls13Nonce(iv, sequence);

  // Decrypt
  final decrypted = aes_gcm.decrypt(
    key,
    Uint8List.fromList([...ct, ...tag]),
    nonce,
    aeadHeader,
  );

  // Last byte = inner content type
  final innerType = decrypted.last;
  if (innerType != TLSContentType.handshake &&
      innerType != TLSContentType.applicationData) {
    throw Exception("Invalid inner TLS content type: $innerType");
  }

  return Uint8List.fromList(decrypted.sublist(0, decrypted.length - 1));
}

// ============================================================================
// Record Layer Manager
// - Maintains sequence numbers
// - Applies encryption/decryption keys
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

    writeSeq = 0;
    readSeq = 0;
  }

  // Encrypt SERVER → CLIENT
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

  // Decrypt CLIENT → SERVER
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
// TLS ContentType constants (RFC 8446 §5)
// ============================================================================

class TLSContentType {
  static const int invalid = 0x00;
  static const int alert = 0x15;
  static const int handshake = 0x16;
  static const int applicationData = 0x17;
}

void main() {
  print("=== TLS 1.3 Record Layer Test ===");

  //---------------------------------------------------------------------------
  // 1. Show TLS Record Header (from your test clientHello)
  //---------------------------------------------------------------------------

  final record = clientHello;

  if (record.length < 5) {
    print("❌ Not enough bytes");
    return;
  }

  final contentType = record[0];
  final version = (record[1] << 8) | record[2];
  final length = (record[3] << 8) | record[4];

  print("Record Header:");
  print("- ContentType = 0x${contentType.toRadixString(16)}");
  print("- Version     = 0x${version.toRadixString(16)}");
  print("- Length      = $length bytes\n");

  if (contentType != TLSContentType.handshake) {
    print("❌ This is not a handshake record.");
    return;
  }

  //---------------------------------------------------------------------------
  // 2. Extract Handshake struct (NOT encrypted in TLS 1.3 ClientHello)
  //---------------------------------------------------------------------------

  if (record.length < 5 + length) {
    print("❌ Record is truncated.");
    return;
  }

  final handshake = record.sublist(5, 5 + length);

  print("Handshake struct (${handshake.length} bytes):");
  print(HEX.encode(handshake));
  print("");

  //-------------------------------------------------------------------------
  // IMPORTANT:
  // ClientHello is UNENCRYPTED — you cannot decrypt it with the record layer.
  //
  // To test the record layer, we must perform an artificial:
  //    plaintext → encrypt → ciphertext → decrypt → plaintext
  //
  // using dummy handshake traffic keys.
  //-------------------------------------------------------------------------

  //---------------------------------------------------------------------------
  // 3. Dummy handshake traffic keys (for testing encryption/decryption)
  //---------------------------------------------------------------------------
  // AES‑128‑GCM requires:
  // - key = 16 bytes
  // - IV  = 12 bytes
  // final fakeServerKey = Uint8List.fromList(
  //   List<int>.generate(16, (i) => i + 1),
  // );
  // final fakeServerIV = Uint8List.fromList(
  //   List<int>.generate(12, (i) => 0xA0 + i),
  // );

  // final fakeClientKey = Uint8List.fromList(
  //   List<int>.generate(16, (i) => 50 + i),
  // );
  // final fakeClientIV = Uint8List.fromList(
  //   List<int>.generate(12, (i) => 0xB0 + i),
  // );

  // final layer = TlsRecordLayer();
  // layer.setHandshakeKeys(
  //   clientKey: fakeClientKey,
  //   clientIV: fakeClientIV,
  //   serverKey: fakeServerKey,
  //   serverIV: fakeServerIV,
  // );

  // //---------------------------------------------------------------------------
  // // 4. Let's encrypt a fake handshake message using the record layer
  // //---------------------------------------------------------------------------
  // final plaintext = Uint8List.fromList("hello-record-layer".codeUnits);

  // print("Plaintext to encrypt:");
  // print(String.fromCharCodes(plaintext));
  // print("");

  // final encryptedRecord = layer.encrypt(plaintext);

  // print("Encrypted TLS 1.3 record:");
  // print(HEX.encode(encryptedRecord));
  // print("");

  // //---------------------------------------------------------------------------
  // // 5. Now decrypt it back (server → client direction)
  // //---------------------------------------------------------------------------
  // final decrypted = layer.decrypt(encryptedRecord);

  // print("Decrypted plaintext:");
  // print(String.fromCharCodes(decrypted));
  // print("");

  // if (HEX.encode(decrypted) == HEX.encode(plaintext)) {
  //   print("✅ Record layer AES‑GCM round‑trip successful!");
  // } else {
  //   print("❌ Decrypted output mismatch!");
  // }
}

final clientHello = Uint8List.fromList(
  HEX.decode(
    "16 03 01 00 f8 01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 08 13 02 13 03 13 01 00 ff 01 00 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0b 00 04 03 00 01 02 00 0a 00 16 00 14 00 1d 00 17 00 1e 00 19 00 18 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 16 00 00 00 17 00 00 00 0d 00 1e 00 1c 04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08 05 08 06 04 01 05 01 06 01 00 2b 00 03 02 03 04 00 2d 00 02 01 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54",
  ),
);
