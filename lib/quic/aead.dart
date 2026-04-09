// import 'dart:typed_data';

// import 'cipher/aes_gcm.dart' as aes;
// import 'cipher/chacha.dart' as chacha;

// /// TLS 1.3 Cipher Suites
// enum CipherSuite { aes128gcm, chacha20poly1305 }

// class Aead {
//   final CipherSuite suite;

//   Aead(this.suite);

//   Uint8List encrypt({
//     required Uint8List key,
//     required Uint8List nonce,
//     required Uint8List aad,
//     required Uint8List plaintext,
//   }) {
//     switch (suite) {
//       case CipherSuite.aes128gcm:
//         return aes.encrypt(key, plaintext, nonce, aad);

//       case CipherSuite.chacha20poly1305:
//         return chacha.encrypt(key, plaintext, nonce, aad);
//     }
//   }

//   Uint8List decrypt({
//     required Uint8List key,
//     required Uint8List nonce,
//     required Uint8List aad,
//     required Uint8List ciphertext,
//   }) {
//     switch (suite) {
//       case CipherSuite.aes128gcm:
//         return aes.decrypt(key, ciphertext, nonce, aad);

//       case CipherSuite.chacha20poly1305:
//         return chacha.decrypt(key, ciphertext, nonce, aad);
//     }
//   }
// }

import 'dart:typed_data';

import 'cipher/aes_gcm.dart' as aes;
import 'cipher/chacha.dart' as chacha;

/// TLS 1.3 Cipher Suites
enum CipherSuite { aes128gcm, chacha20poly1305 }

class Aead {
  final CipherSuite suite;

  /// Flip to `true` when debugging nonce/AAD/tag mismatches.
  static bool debug = true;

  /// If true, prints full buffers (can be large).
  static bool debugVerbose = false;

  Aead(this.suite);

  static String _hex(Uint8List b, {int max = 64}) {
    final take = b.length <= max ? b.length : max;
    final sb = StringBuffer();
    for (var i = 0; i < take; i++) {
      if (i > 0) sb.write(i % 16 == 0 ? '\n' : ' ');
      sb.write(b[i].toRadixString(16).padLeft(2, '0'));
    }
    if (take != b.length) sb.write('\n... (${b.length} bytes total)');
    return sb.toString();
  }

  static void _logBytes(String label, Uint8List bytes) {
    final max = debugVerbose ? bytes.length : 64;
    // ignore: avoid_print
    print('--- AEAD $label (${bytes.length} bytes) ---');
    // ignore: avoid_print
    print(_hex(bytes, max: max));
    // ignore: avoid_print
    print('--- end AEAD $label ---');
  }

  Uint8List encrypt({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List aad,
    required Uint8List plaintext,
  }) {
    if (debug) {
      // ignore: avoid_print
      print('AEAD.encrypt suite=$suite');
      _logBytes('key', key);
      _logBytes('nonce', nonce);
      _logBytes('aad', aad);
      _logBytes('plaintext', plaintext);
    }

    final out = switch (suite) {
      CipherSuite.aes128gcm => aes.encrypt(key, plaintext, nonce, aad),
      CipherSuite.chacha20poly1305 => chacha.encrypt(
        key,
        plaintext,
        nonce,
        aad,
      ),
    };

    if (debug) {
      _logBytes('ciphertext', out);
    }
    return out;
  }

  Uint8List decrypt({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List aad,
    required Uint8List ciphertext,
  }) {
    if (debug) {
      // ignore: avoid_print
      print('AEAD.decrypt suite=$suite');
      _logBytes('key', key);
      _logBytes('nonce', nonce);
      _logBytes('aad', aad);
      _logBytes('ciphertext', ciphertext);
    }

    final out = switch (suite) {
      CipherSuite.aes128gcm => aes.decrypt(key, ciphertext, nonce, aad),
      CipherSuite.chacha20poly1305 => chacha.decrypt(
        key,
        ciphertext,
        nonce,
        aad,
      ),
    };

    if (debug) {
      _logBytes('plaintext', out);
    }
    return out;
  }
}
