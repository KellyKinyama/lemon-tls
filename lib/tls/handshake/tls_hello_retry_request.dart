// ============================================================================
// tls_hello_retry_request.dart
// TLS 1.3 HelloRetryRequest builder
// Direct Dart translation of original JavaScript code
// ============================================================================

import 'dart:typed_data';

import 'tls_constants.dart';
import 'tls_utils.dart';
import 'tls_write.dart';
import 'tls_extensions.dart';

/// The special TLS 1.3 HelloRetryRequest random value:
/// 44 bytes defined in RFC 8446, Section 4.1.3
final Uint8List TLS13_HRR_RANDOM = Uint8List.fromList([
  0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
  0xBE, 0x1A, 0x8A, 0x6E, 0x7F, 0xCC, 0x7F, 0x0E,
  0xC8, 0x2A, 0xF2, 0x7E, 0xB0, 0x1D, 0xB8, 0x82,
  0xCD, 0x1B, 0xE2, 0x7B, 0x0E, 0x2F, 0x00, 0x00,
]);

/// ---------------------------------------------------------------------------
/// buildHelloRetryRequest(params)
///
/// Params:
/// {
///   cipher_suite: int,
///   selected_version: int,
///   selected_group: int,
///   cookie?: Uint8List | String,
///   other_exts?: List<Map>
/// }
///
/// Produces a ServerHello‑shaped payload with HRR random.
/// ---------------------------------------------------------------------------
Uint8List buildHelloRetryRequest(Map<String, dynamic> params) {
  final Uint8List rnd = TLS13_HRR_RANDOM;
  final Uint8List sid = Uint8List(0);
  final int legacyVersion = TLSVersion.TLS1_2;

  final List<Map<String, dynamic>> extList = [];

  // supported_versions (selected)
  extList.add({
    'type': 'SUPPORTED_VERSIONS',
    'value': params['selected_version'] ?? TLSVersion.TLS1_3,
  });

  // key_share : only selected_group, empty key
  if (params.containsKey('selected_group')) {
    extList.add({
      'type': 'KEY_SHARE',
      'value': {
        'group': params['selected_group'],
        'key_exchange': Uint8List(0),
      }
    });
  }

  // cookie
  if (params.containsKey('cookie')) {
    // ensure COOKIE extension handler exists
    if (!exts.containsKey('COOKIE')) {
      exts['COOKIE'] = ExtensionHandler(
        encode: (v) => veclen(2, toU8(v ?? "")),
        decode: (Uint8List d) {
          final r = readVec(d, 0, 2);
          return r[0];
        },
      );
    }
    extList.add({
      'type': 'COOKIE',
      'value': params['cookie'],
    });
  }

  // other extensions passed through
  if (params['other_exts'] is List) {
    for (final e in params['other_exts']) {
      extList.add(e);
    }
  }

  final Uint8List extsBuf = buildExtensions(extList);
  final int cipherSuite =
      (params['cipher_suite'] is int)
          ? params['cipher_suite']
          : 0x1301;

  // Wire format:
  // legacy_version (2)
  // random (32)
  // session_id length (1) + session_id
  // cipher_suite (2)
  // compression (1 = 0)
  // extensions (...)
  final Uint8List out = Uint8List(
    2 +          // legacy_version
    32 +         // random
    1 +          // sid length
    0 +          // sid data
    2 +          // cipher_suite
    1 +          // compression
    extsBuf.length
  );

  int off = 0;
  off = w_u16(out, off, legacyVersion);
  off = w_bytes(out, off, rnd);
  off = w_u8(out, off, 0); // sid length
  off = w_u16(out, off, cipherSuite);
  off = w_u8(out, off, 0); // compression method
  off = w_bytes(out, off, extsBuf);

  return out;
}