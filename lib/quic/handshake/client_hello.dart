import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:collection/equality.dart';
import 'package:hex/hex.dart';
import 'package:lemon_tls/quic/quic_session.dart';
import 'package:lemon_tls/tls13/server_hello.dart';

import '../buffer.dart';
// import '../packet/payload_parser.dart';
import 'keyshare.dart';
import 'tls_messages.dart';

class ClientHello extends TlsHandshakeMessage {
  int legacyVersion;
  final Uint8List random;
  Uint8List sessionId;
  final List<int> cipherSuites;
  Uint8List compressionMethods;
  final List<TlsExtension> extensions;

  // Parsed Extension Variables
  String? sni;
  List<ParsedKeyShare>? keyShares = [];
  List<int>? supportedVersions = [];
  List<int>? supportedGroups = [];
  List<int>? signatureAlgorithms = [];
  List<String>? alpn = [];
  int? maxFragmentLength;
  Uint8List? padding;
  Uint8List? cookie;
  List<int>? pskKeyExchangeModes = [];
  Uint8List? preSharedKey;
  Uint8List? renegotiationInfo;
  Uint8List? quicTransportParametersRaw;

  Uint8List rawData;
  ClientHello({
    required this.legacyVersion,
    required this.sessionId,
    required this.random,
    required this.cipherSuites,
    required this.compressionMethods,
    required this.extensions,
    required String type,
    this.sni,
    this.keyShares,
    this.supportedVersions,
    this.supportedGroups,
    this.signatureAlgorithms,
    this.alpn,
    this.maxFragmentLength,
    this.padding,
    this.cookie,
    this.pskKeyExchangeModes,
    this.preSharedKey,
    this.renegotiationInfo,
    this.quicTransportParametersRaw,
    required this.rawData,
  }) : super(0x01);

  @override
  String toString() {
    final suites = cipherSuites
        .map((s) => cipherSuitesMap[s] ?? 'Unknown (0x${s.toRadixString(16)})')
        .join(',\n    ');
    return '''
✅ Parsed ClientHello (Type 0x01):
- Random: ${HEX.encode(random.sublist(0, 8))}...
- Cipher Suites:
    $suites
- Key share: $keyShares
- Extensions Count: ${extensions.map((extension) {
      return extensionTypesMap[extension.type] != null ? (extensionTypesMap[extension.type], HEX.encode(extension.data)) : (extension.type, HEX.encode(extension.data));
    })}''';
  }

  Uint8List serialize() {
    final body = QuicBuffer();

    // 1. legacy_version: Always 0x0303 (TLS 1.2) for compatibility
    body.pushUint16(0x0303);

    // 2. random: 32 bytes
    body.pushBytes(random);

    // 3. legacy_session_id: Encoded as a vector (Length byte + data)
    // For QUIC, this is typically empty (0 length)
    body.pushUint8(0);

    // 4. cipher_suites: Encoded as a vector (2-byte length + suite IDs)
    body.pushUint16(cipherSuites.length * 2);
    for (var suite in cipherSuites) {
      body.pushUint16(suite);
    }

    // 5. legacy_compression_methods: Encoded as a vector (1-byte length + data)
    // Standard is 1 method: null (0x00)
    body.pushUint8(1);
    body.pushUint8(0);

    // 6. extensions: Encoded as a vector (2-byte length + extensions)
    final extBuffer = QuicBuffer();
    for (var ext in extensions) {
      extBuffer.pushUint16(ext.type);
      extBuffer.pushUint16(ext.data.length);
      extBuffer.pushBytes(ext.data);
    }

    final extBytes = extBuffer.toBytes();
    body.pushUint16(extBytes.length);
    body.pushBytes(extBytes);

    // 7. Handshake Header: Type (1 byte) + Length (3 bytes)
    final bodyBytes = body.toBytes();
    final header = Uint8List(4);
    header[0] = 0x01; // ClientHello Type

    // Set 24-bit length (Big Endian)
    header[1] = (bodyBytes.length >> 16) & 0xFF;
    header[2] = (bodyBytes.length >> 8) & 0xFF;
    header[3] = bodyBytes.length & 0xFF;

    return Uint8List.fromList([...header, ...bodyBytes]);
  }

  static ClientHello parse_tls_client_hello(Uint8List body) {
    final view = body;
    int ptr = 0;

    int legacy_version = (view[ptr++] << 8) | view[ptr++];
    Uint8List random = view.sublist(ptr, ptr + 32);
    ptr += 32;
    int session_id_len = view[ptr++];
    Uint8List session_id = view.sublist(ptr, ptr + session_id_len);
    ptr += session_id_len;

    int cipher_suites_len = (view[ptr++] << 8) | view[ptr++];
    List<int> cipher_suites = [];
    for (var i = 0; i < cipher_suites_len; i += 2) {
      int code = (view[ptr++] << 8) | view[ptr++];
      cipher_suites.add(code);
    }
    print("parsed length: $ptr");

    int compression_methods_len = view[ptr++];
    Uint8List compression_methods = view.sublist(
      ptr,
      ptr + compression_methods_len,
    );
    ptr += compression_methods_len;

    var extensions_len = (view[ptr++] << 8) | view[ptr++];
    List<TlsExtension> extensions = [];
    var ext_end = ptr + extensions_len;
    while (ptr < ext_end) {
      int ext_type = (view[ptr++] << 8) | view[ptr++];
      int ext_len = (view[ptr++] << 8) | view[ptr++];
      Uint8List ext_data = view.sublist(ptr, ptr + ext_len);
      ptr += ext_len;
      extensions.add(
        TlsExtension(type: ext_type, length: ext_len, data: ext_data),
      );
    }

    // --------------------------------------------------
    // Decode extensions (NO byte re-parsing)
    // --------------------------------------------------

    // --------------------------------------------------
    // ✅ Semantic decode (iterate over TlsExtension)
    // --------------------------------------------------
    final keyShares = <ParsedKeyShare>[];
    final supportedGroups = <int>[];
    final supportedVersions = <int>[];

    for (final ext in extensions) {
      final buf = QuicBuffer(data: ext.data);

      switch (ext.type) {
        // --------------------------------------------
        // supported_groups (0x000a)
        // --------------------------------------------
        case 0x000a:
          final len = buf.pullUint16();
          for (int i = 0; i < len; i += 2) {
            supportedGroups.add(buf.pullUint16());
          }
          break;

        // --------------------------------------------
        // supported_versions (0x002b)
        // --------------------------------------------
        case 0x002b:
          final len = buf.pullUint8();
          for (int i = 0; i < len; i += 2) {
            supportedVersions.add(buf.pullUint16());
          }
          break;

        // --------------------------------------------
        // key_share (0x0033)
        // --------------------------------------------
        case 0x0033:
          final listLen = buf.pullUint16();
          final end = buf.readOffset + listLen;

          while (buf.readOffset < end) {
            final group = buf.pullUint16();
            final keyLen = buf.pullUint16();
            final key = buf.pullBytes(keyLen);
            keyShares.add(ParsedKeyShare(group, key));
          }
          break;

        default:
          break;
      }
    }

    return ClientHello(
      type: 'client_hello',
      legacyVersion: legacy_version,
      random: random,
      sessionId: session_id,
      cipherSuites: cipher_suites,
      compressionMethods: compression_methods,
      extensions: extensions,
      rawData: body,

      // ✅ populated from extension decoding
      keyShares: keyShares,
      supportedGroups: supportedGroups,
      supportedVersions: supportedVersions,
    );
  }

  Uint8List build_tls_client_hello() {
    final buffer = QuicBuffer();

    // Legacy Version (usually 0x0303 for TLS 1.2 compatibility)
    buffer.pushUint16(legacyVersion);

    // Random (32 bytes)
    buffer.pushBytes(random);

    // Session ID
    buffer.pushUint8(sessionId.length);
    buffer.pushBytes(sessionId);

    // Cipher Suites
    buffer.pushUint16(cipherSuites.length);
    for (int cipherSuite in cipherSuites) {
      buffer.pushUint16(cipherSuite);
    }

    // Compression Methods
    buffer.pushUint8(compressionMethods.length);

    buffer.pushBytes(compressionMethods);

    // Extensions
    buffer.pushUint16(extensions.length);

    for (var extension in extensions) {
      buffer.pushUint16(extension.type);
      buffer.pushUint16(extension.length);
      buffer.pushBytes(extension.data);
    }

    final bodyBytes = buffer.data.sublist(0, buffer.writeIndex);
    return bodyBytes;

    // final header = Uint8List(4);
    // header[0] = 0x01; // ClientHello Type

    // // Set 24-bit length (Big Endian)
    // header[1] = (bodyBytes.length >> 16) & 0xFF;
    // header[2] = (bodyBytes.length >> 8) & 0xFF;
    // header[3] = bodyBytes.length & 0xFF;

    // return Uint8List.fromList([...header, ...bodyBytes]);
  }

  Uint8List build_tls_client_hello2() {
    var view = BytesBuilder();

    // Legacy Version
    view.add([(legacyVersion >> 8) & 0xFF, legacyVersion & 0xFF]);

    // Random
    view.add(random);

    // Session ID
    view.addByte(sessionId.length);
    view.add(sessionId);

    // ✅ Cipher suites length (bytes)
    int cipherBytes = cipherSuites.length * 2;
    view.add([(cipherBytes >> 8) & 0xFF, cipherBytes & 0xFF]);

    for (int suite in cipherSuites) {
      view.add([(suite >> 8) & 0xFF, suite & 0xFF]);
    }

    // Compression Methods
    view.addByte(compressionMethods.length);
    view.add(compressionMethods);

    // ✅ Extensions length in bytes
    int extLen = extensions.fold(0, (sum, e) => sum + 4 + e.length);
    view.add([(extLen >> 8) & 0xFF, extLen & 0xFF]);

    for (final ext in extensions) {
      view.add([(ext.type >> 8) & 0xFF, ext.type & 0xFF]);
      view.add([(ext.length >> 8) & 0xFF, ext.length & 0xFF]);
      view.add(ext.data);
    }

    final bodyBytes = view.toBytes();

    final header = Uint8List(4);
    header[0] = 0x01; // ClientHello Type

    // Set 24-bit length (Big Endian)
    header[1] = (bodyBytes.length >> 16) & 0xFF;
    header[2] = (bodyBytes.length >> 8) & 0xFF;
    header[3] = bodyBytes.length & 0xFF;

    return Uint8List.fromList([...header, ...bodyBytes]);
  }

  // #############################################################################
  // ## SECTION 3: PARSER LOGIC
  // #############################################################################

  List<TlsExtension> parseExtensions(QuicBuffer buffer) {
    if (buffer.remaining < 2) return [];
    final totalExtLen = buffer.pullUint16();
    final extensions = <TlsExtension>[];
    int extensionsRead = 0;
    while (extensionsRead < totalExtLen && buffer.remaining > 0) {
      final extType = buffer.pullUint16();
      final extLen = buffer.pullUint16();
      final extData = buffer.pullBytes(extLen);
      extensions.add(
        TlsExtension(type: extType, length: extLen, data: extData),
      );
      extensionsRead += 4 + extLen;
    }
    return extensions;
  }
}

ClientHello parseClientHelloBody(QuicBuffer buffer) {
  int legacyVersion = buffer.pullUint16(); // Skip legacy_version
  final random = buffer.pullBytes(32);
  Uint8List sessionId = buffer.pullVector(1); // Skip legacy_session_id

  final cipherSuitesBytes = buffer.pullVector(2);
  final cipherSuites = <int>[];
  final csBuffer = QuicBuffer(data: cipherSuitesBytes);
  while (!csBuffer.eof) {
    cipherSuites.add(csBuffer.pullUint16());
  }

  Uint8List compressionMethods = buffer.pullVector(
    1,
  ); // Skip legacy_compression_methods
  final extensions = parseExtensions(buffer);

  // throw UnimplementedError("ClientHello");

  return ClientHello(
    type: 'client_hello',
    legacyVersion: legacyVersion,
    random: random,
    sessionId: sessionId,
    cipherSuites: cipherSuites,
    compressionMethods: compressionMethods,
    extensions: extensions,
    rawData: buffer.data.sublist(buffer.readOffset),
  );
}

List<TlsExtension> parseExtensions(QuicBuffer buffer) {
  if (buffer.remaining < 2) return [];
  final totalExtLen = buffer.pullUint16();
  final extensions = <TlsExtension>[];
  int extensionsRead = 0;
  while (extensionsRead < totalExtLen && buffer.remaining > 0) {
    final extType = buffer.pullUint16();
    final extLen = buffer.pullUint16();
    final extData = buffer.pullBytes(extLen);
    extensions.add(TlsExtension(type: extType, length: extLen, data: extData));
    extensionsRead += 4 + extLen;
  }
  return extensions;
}

final clientHello = Uint8List.fromList(
  HEX.decode(
    "01 00 00 ea 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 00 06 13 01 13 02 13 03 01 00 00 bb 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 08 00 06 00 1d 00 17 00 18 00 10 00 0b 00 09 08 70 69 6e 67 2f 31 2e 30 00 0d 00 14 00 12 04 03 08 04 04 01 05 03 08 05 05 01 08 06 06 01 02 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54 00 2d 00 02 01 01 00 2b 00 03 02 03 04 00 39 00 31 03 04 80 00 ff f7 04 04 80 a0 00 00 05 04 80 10 00 00 06 04 80 10 00 00 07 04 80 10 00 00 08 01 0a 09 01 0a 0a 01 03 0b 01 19 0f 05 63 5f 63 69 64"
        .replaceAll(" ", ""),
  ),
);

// void main() {
//   // ==========================================================
//   // 1️⃣ Raw TLS ClientHello (handshake header + body)
//   // ==========================================================
//   final clientHelloWire = Uint8List.fromList(
//     HEX.decode(
//       "01 00 00 ea 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 00 06 13 01 13 02 13 03 01 00 00 bb 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 08 00 06 00 1d 00 17 00 18 00 10 00 0b 00 09 08 70 69 6e 67 2f 31 2e 30 00 0d 00 14 00 12 04 03 08 04 04 01 05 03 08 05 05 01 08 06 06 01 02 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54 00 2d 00 02 01 01 00 2b 00 03 02 03 04 00 39 00 31 03 04 80 00 ff f7 04 04 80 a0 00 00 05 04 80 10 00 00 06 04 80 10 00 00 07 04 80 10 00 00 08 01 0a 09 01 0a 0a 01 03 0b 01 19 0f 05 63 5f 63 69 64"
//           .replaceAll(" ", ""),
//     ),
//   );

//   print("✅ ClientHello wire length = ${clientHelloWire.length}");
//   print("Handshake type = 0x${clientHelloWire[0].toRadixString(16)}");

//   // ==========================================================
//   // 2️⃣ Parse ClientHello (strip handshake header)
//   // ==========================================================
//   final parsed = ClientHello.parse_tls_client_hello(clientHelloWire.sublist(4));

//   print(parsed);

//   // ✅ sanity checks
//   if (parsed.legacyVersion != 0x0303) {
//     throw StateError(
//       "Invalid legacy_version: expected 0x0303, "
//       "got 0x${parsed.legacyVersion.toRadixString(16)}",
//     );
//   }

//   if (!parsed.cipherSuites.contains(0x1301)) {
//     throw StateError(
//       "ClientHello does not advertise TLS_AES_128_GCM_SHA256 (0x1301)",
//     );
//   }

//   if (parsed.keyShares == null || parsed.keyShares!.isEmpty) {
//     throw StateError("ClientHello contains no key_share extension");
//   }

//   final x25519Share = parsed.keyShares!.firstWhere(
//     (ks) => ks.group == 0x001d,
//     orElse: () => throw StateError(
//       "ClientHello does not contain an X25519 (0x001d) key_share",
//     ),
//   );

//   // ==========================================================
//   // 3️⃣ Re‑serialize ClientHello
//   // ==========================================================
//   final rebuilt = parsed.serialize();

//   print("✅ Rebuilt ClientHello length = ${rebuilt.length}");

//   // ==========================================================
//   // 4️⃣ Byte‑for‑byte equality check
//   // ==========================================================
//   final eq = const ListEquality<int>().equals(clientHelloWire, rebuilt);

//   if (!eq) {
//     print("❌ MISMATCH!");
//     print("Original:");
//     print(HEX.encode(clientHelloWire));
//     print("Rebuilt:");
//     print(HEX.encode(rebuilt));
//     throw StateError("ClientHello round‑trip mismatch");
//   }

//   print("✅ ClientHello parse ⇄ build round‑trip OK");
// }

void main() {
  final originalWire = Uint8List.fromList(
    HEX.decode(
      "01 00 00 ea 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 00 06 13 01 13 02 13 03 01 00 00 bb 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 08 00 06 00 1d 00 17 00 18 00 10 00 0b 00 09 08 70 69 6e 67 2f 31 2e 30 00 0d 00 14 00 12 04 03 08 04 04 01 05 03 08 05 05 01 08 06 06 01 02 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54 00 2d 00 02 01 01 00 2b 00 03 02 03 04 00 39 00 31 03 04 80 00 ff f7 04 04 80 a0 00 00 05 04 80 10 00 00 06 04 80 10 00 00 07 04 80 10 00 00 08 01 0a 09 01 0a 0a 01 03 0b 01 19 0f 05 63 5f 63 69 64"
          .replaceAll(" ", ""),
    ),
  );

  Uint8List current = originalWire;

  const iterations = 10;

  for (int i = 0; i < iterations; i++) {
    // --------------------------------------------------
    // 1. Parse (strip handshake header)
    // --------------------------------------------------
    if (current.length < 4 || current[0] != 0x01) {
      throw StateError("Iteration $i: not a ClientHello handshake");
    }

    final parsed = ClientHello.parse_tls_client_hello(current.sublist(4));

    // --------------------------------------------------
    // 2. Validate parsed structure explicitly
    // --------------------------------------------------
    if (parsed.legacyVersion != 0x0303) {
      throw StateError("Iteration $i: legacy_version mismatch");
    }

    if (!parsed.cipherSuites.contains(0x1301)) {
      throw StateError("Iteration $i: missing TLS_AES_128_GCM_SHA256");
    }

    if (parsed.keyShares == null || parsed.keyShares!.isEmpty) {
      throw StateError("Iteration $i: key_share missing");
    }

    final hasX25519 = parsed.keyShares!.any((ks) => ks.group == 0x001d);

    if (!hasX25519) {
      throw StateError("Iteration $i: X25519 key_share missing");
    }

    // --------------------------------------------------
    // 3. Rebuild
    // --------------------------------------------------
    final rebuilt = parsed.serialize();

    // --------------------------------------------------
    // 4. Byte‑for‑byte compare
    // --------------------------------------------------
    if (rebuilt.length != current.length) {
      throw StateError(
        "Iteration $i: length mismatch "
        "${rebuilt.length} != ${current.length}",
      );
    }

    for (int j = 0; j < rebuilt.length; j++) {
      if (rebuilt[j] != current[j]) {
        throw StateError(
          "Iteration $i: byte mismatch at offset $j "
          "(0x${current[j].toRadixString(16)} != "
          "0x${rebuilt[j].toRadixString(16)})",
        );
      }
    }

    print("✅ Iteration $i OK");

    // Feed rebuilt bytes into next round
    current = rebuilt;
  }

  print("✅ ClientHello stable after $iterations parse ⇄ build cycles");
}
