// lib/quic_aead.dart
import 'dart:typed_data';
import 'package:pointycastle/export.dart';

Uint8List quicNonce(Uint8List iv, int packetNumber) {
  final out = Uint8List.fromList(iv);
  var n = packetNumber;

  for (int i = iv.length - 1; i >= 0 && n > 0; i--) {
    out[i] ^= (n & 0xff);
    n >>= 8;
  }
  return out;
}

/// QUIC AES-GCM decrypt returning plaintext or null
Uint8List? quicAeadDecrypt({
  required Uint8List key,
  required Uint8List iv,
  required int packetNumber,
  required Uint8List ciphertextWithTag,
  required Uint8List aad,
}) {
  try {
    final nonce = quicNonce(iv, packetNumber);

    final ciphertext = ciphertextWithTag.sublist(
      0,
      ciphertextWithTag.length - 16,
    );
    final tag = ciphertextWithTag.sublist(ciphertextWithTag.length - 16);

    final cipher = GCMBlockCipher(AESFastEngine());
    cipher.init(false, AEADParameters(KeyParameter(key), 128, nonce, aad));

    final plaintext = cipher.process(ciphertext);
    cipher.process(tag); // authentication check

    return Uint8List.fromList(plaintext);
  } catch (_) {
    return null;
  }
}

/// QUIC AES-GCM encrypt
Uint8List? quicAeadEncrypt({
  required Uint8List key,
  required Uint8List iv,
  required int packetNumber,
  required Uint8List plaintext,
  required Uint8List aad,
}) {
  try {
    final nonce = quicNonce(iv, packetNumber);

    final cipher = GCMBlockCipher(AESFastEngine());
    cipher.init(true, AEADParameters(KeyParameter(key), 128, nonce, aad));

    final out = cipher.process(plaintext);
    return Uint8List.fromList(out);
  } catch (_) {
    return null;
  }
}
