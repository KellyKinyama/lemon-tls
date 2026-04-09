import 'dart:typed_data';

import 'cipher/aes_gcm.dart' as aes;
import 'cipher/chacha.dart' as chacha;

/// TLS 1.3 Cipher Suites
enum CipherSuite { aes128gcm, chacha20poly1305 }

class Aead {
  final CipherSuite suite;

  Aead(this.suite);

  Uint8List encrypt({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List aad,
    required Uint8List plaintext,
  }) {
    switch (suite) {
      case CipherSuite.aes128gcm:
        return aes.encrypt(key, plaintext, nonce, aad);

      case CipherSuite.chacha20poly1305:
        return chacha.encrypt(key, plaintext, nonce, aad);
    }
  }

  Uint8List decrypt({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List aad,
    required Uint8List ciphertext,
  }) {
    switch (suite) {
      case CipherSuite.aes128gcm:
        return aes.decrypt(key, ciphertext, nonce, aad);

      case CipherSuite.chacha20poly1305:
        return chacha.decrypt(key, ciphertext, nonce, aad);
    }
  }
}
