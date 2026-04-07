// ============================================================================
// TLS 1.3 Hello Messages
// - ClientHello builder (if needed for future client support)
// - ServerHello builder (used by server handshake)
// - Hello parsers (compatible with TLS 1.2 layout, as required by RFC 8446)
// ============================================================================

import 'dart:typed_data';

import 'package:hex/hex.dart';

import 'tls_extensions.dart';
import 'tls_constants.dart';
import 'tls_record_layer.dart';
import 'utils.dart';

/// ============================================================================
/// BUILD SERVERHELLO (TLS 1.3)
/// ============================================================================
///
/// ServerHello structure (RFC 8446 §4.1.3):
///
///   legacy_version        = 0x0303
///   random[32]
///   legacy_session_id_echo
///   cipher_suite
///   legacy_compression_method = 0x00
///   extensions (MUST include supported_versions + key_share)
///
/// ============================================================================

Uint8List buildHello(String kind, Map<String, dynamic> params) {
  params = params ?? {};

  // TLS 1.3 uses legacy_version = TLS 1.2 in ServerHello
  const legacyVersion = TLSVersion.TLS1_2;

  // -------------------------------------------------------------
  // session_id (echoed from ClientHello)
  // -------------------------------------------------------------
  Uint8List sid = toU8(params['session_id'] ?? "");
  if (sid.length > 32) {
    sid = sid.sublist(0, 32);
  }

  Uint8List random = params['random'];
  if (random.length != 32) {
    throw Exception("ServerHello random must be 32 bytes");
  }

  final Uint8List extsBuf = buildExtensions(
    (params['extensions'] ?? []) as List<Map<String, dynamic>>,
  );

  // ServerHello builder (TLS 1.3)
  if (kind == 'server') {
    final cipherSuite = params['cipher_suite'] ?? 0x1301; // AES_128_GCM_SHA256

    final out = Uint8List(
      2 + // legacy_version
          32 + // random
          1 +
          sid.length +
          2 + // cipher_suite
          1 + // compression_method
          extsBuf.length,
    );

    int off = 0;

    off = w_u16(out, off, legacyVersion);
    off = w_bytes(out, off, random);

    off = w_u8(out, off, sid.length);
    off = w_bytes(out, off, sid);

    off = w_u16(out, off, cipherSuite);
    off = w_u8(out, off, 0x00); // legacy compression = 0

    off = w_bytes(out, off, extsBuf);

    return out;
  }

  // If needed in the future: ClientHello builder
  if (kind == 'client') {
    throw UnimplementedError("ClientHello builder not implemented yet.");
  }

  throw Exception('buildHello: kind must be either "server" or "client"');
}

/// ============================================================================
/// PARSE HELLO (ClientHello or ServerHello)
/// ============================================================================
///
/// This parser keeps compatibility with both:
///   - TLS 1.3 ClientHello
///   - TLS 1.2 ClientHello
///   - TLS 1.3 ServerHello
///   - TLS 1.2 ServerHello
///
/// The server side only needs ClientHello parsing.
/// The client side would use ServerHello parsing.
///
/// ============================================================================

Map<String, dynamic> parseHello(dynamic type, Uint8List body) {
  bool isClientHello =
      (type == TLSMessageType.CLIENT_HELLO || type == "client_hello");

  int off = 0;

  // legacy_version
  final rv = r_u16(body, off);
  final legacyVersion = rv[0];
  off = rv[1];

  // random
  final rr = r_bytes(body, off, 32);
  final random = rr[0] as Uint8List;
  off = rr[1];

  // session_id
  final rs = r_u8(body, off);
  final sidLen = rs[0];
  off = rs[1];

  final sidRes = r_bytes(body, off, sidLen);
  final sessionId = sidRes[0] as Uint8List;
  off = sidRes[1];

  // ---------------------------------------------------------------------------
  // CLIENT_HELLO
  // ---------------------------------------------------------------------------
  if (isClientHello) {
    // cipher_suites vector<2>
    final csLenRes = r_u16(body, off);
    int csLen = csLenRes[0];
    off = csLenRes[1];

    final csEnd = off + csLen;
    final cipherSuites = <int>[];

    while (off < csEnd) {
      final rcs = r_u16(body, off);
      cipherSuites.add(rcs[0]);
      off = rcs[1];
    }

    // compression methods vector<1>
    final compLenRes = r_u8(body, off);
    int compLen = compLenRes[0];
    off = compLenRes[1];

    final legacyCompression = <int>[];
    for (int i = 0; i < compLen; i++) {
      final rc = r_u8(body, off);
      legacyCompression.add(rc[0]);
      off = rc[1];
    }

    // Extensions
    final Uint8List extBuf = (off < body.length)
        ? body.sublist(off)
        : Uint8List(0);

    final exts = (extBuf.isEmpty) ? [] : parseExtensions(extBuf);

    // infer hinted TLS version
    int hintedVersion = legacyVersion;
    for (final e in exts) {
      if (e['type'] == TLSExt.SUPPORTED_VERSIONS && (e['value'] is List)) {
        final versions = e['value'] as List;
        if (versions.contains(TLSVersion.TLS1_3)) {
          hintedVersion = TLSVersion.TLS1_3;
        }
      }
    }
    print("extensions: $exts");

    return {
      'message': 'client_hello',
      'legacy_version': legacyVersion,
      'version_hint': hintedVersion,
      'random': random,
      'session_id': sessionId,
      'cipher_suites': cipherSuites,
      'legacy_compression': legacyCompression,
      'extensions': exts,
    };
  }

  // ---------------------------------------------------------------------------
  // SERVER_HELLO
  // ---------------------------------------------------------------------------

  final scs = r_u16(body, off);
  final cipherSuite = scs[0];
  off = scs[1];

  final compR = r_u8(body, off);
  final compressionMethod = compR[0];
  off = compR[1];

  final Uint8List extBuf = (off < body.length)
      ? body.sublist(off)
      : Uint8List(0);

  final exts = (extBuf.isEmpty) ? [] : parseExtensions(extBuf);

  int selectedVersion = legacyVersion;

  for (final ex in exts) {
    if (ex['type'] == TLSExt.SUPPORTED_VERSIONS && ex['value'] is int) {
      selectedVersion = ex['value'];
    }
  }

  return {
    'message': 'server_hello',
    'legacy_version': legacyVersion,
    'version': selectedVersion,
    'random': random,
    'session_id': sessionId,
    'cipher_suite': cipherSuite,
    'legacy_compression': compressionMethod,
    'extensions': exts,
  };
}

void main() {
  print("=== TLS Hello Parser Test ===");

  // Full TLS record from your test vector
  final record = client_to_server;

  // -------------------------------------------------------------
  // 1. Validate TLSPlaintext header
  // -------------------------------------------------------------
  if (record.length < 5) {
    print("Record too small.");
    return;
  }

  final contentType = record[0];
  if (contentType != TLSContentType.handshake) {
    print(
      "❌ Not a handshake record. contentType=0x${contentType.toRadixString(16)}",
    );
    return;
  }

  final recordLen = (record[3] << 8) | record[4];
  print("TLS Record length = $recordLen bytes");

  // -------------------------------------------------------------
  // 2. Extract Handshake struct (starts after 5‑byte record header)
  // -------------------------------------------------------------
  if (record.length < 5 + recordLen) {
    print("❌ Record truncated");
    return;
  }

  final handshakeStruct = record.sublist(5, 5 + recordLen);

  if (handshakeStruct.length < 4) {
    print("❌ Handshake struct too short");
    return;
  }

  // -------------------------------------------------------------
  // 3. Parse handshake header
  // -------------------------------------------------------------
  final hsType = handshakeStruct[0];
  final hsLen =
      (handshakeStruct[1] << 16) |
      (handshakeStruct[2] << 8) |
      handshakeStruct[3];

  print("Handshake type = $hsType  (1 = ClientHello)");
  print("Handshake body length = $hsLen");

  if (handshakeStruct.length != hsLen + 4) {
    print(
      "❌ Handshake length mismatch. Expected ${hsLen + 4}, got ${handshakeStruct.length}",
    );
    return;
  }

  // -------------------------------------------------------------
  // 4. Extract ONLY ClientHello body (this is what parseHello() needs!)
  // -------------------------------------------------------------
  final clientHelloBody = handshakeStruct.sublist(4);

  // -------------------------------------------------------------
  // 5. Parse ClientHello
  // -------------------------------------------------------------
  final parsed = parseHello(TLSMessageType.CLIENT_HELLO, clientHelloBody);

  print("✅ Parsed ClientHello:");
  print(parsed);
}

final client_to_server = Uint8List.fromList(
  HEX.decode(
    [
      "16 03 01 00 fe 01 00 00  fa 03 03 00 00 00 00 00", //|................|
      "00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00", //|................|
      "00 00 00 00 00 00 00 00  00 00 00 20 00 00 00 00", //|........... ....|
      "00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00", //|................|
      "00 00 00 00 00 00 00 00  00 00 00 00 00 32 cc a9", //|.............2..|
      "cc a8 c0 2b c0 2f c0 2c  c0 30 c0 09 c0 13 c0 0a", //|...+./.,.0......|
      "c0 14 00 9c 00 9d 00 2f  00 35 c0 12 00 0a c0 23", //|......./.5.....#|
      "c0 27 00 3c c0 07 c0 11  00 05 13 03 13 01 13 02", //|.'.<............|
      "01 00 00 7f 00 0b 00 02  01 00 ff 01 00 01 00 00", //|................|
      "17 00 00 00 12 00 00 00  05 00 05 01 00 00 00 00", //|................|
      "00 0a 00 0a 00 08 00 1d  00 17 00 18 00 19 00 0d", //|................|
      "00 1a 00 18 08 04 04 03  08 07 08 05 08 06 04 01", //|................|
      "05 01 06 01 05 03 06 03  02 01 02 03 00 2b 00 09", //|.............+..|
      "08 03 04 03 03 03 02 03  01 00 33 00 26 00 24 00", //|..........3.&.$.|
      "1d 00 20 2f e5 7d a3 47  cd 62 43 15 28 da ac 5f", //|.. /.}.G.bC.(.._|
      "bb 29 07 30 ff f6 84 af  c4 cf c2 ed 90 99 5f 58", //|.).0.........._X|
      "cb 3b 74                                        ",
    ].join(' ').replaceAll(" ", ""),
  ),
); //|.;t|
