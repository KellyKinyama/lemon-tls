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

  // static ClientHello parse_tls_client_hello(Uint8List body) {
  //   int ptr = 0;

  //   // Legacy Version (usually 0x0303 for TLS 1.2 compatibility)
  //   int legacyVersion = (body[ptr++] << 8) | body[ptr++];

  //   // Random (32 bytes)
  //   Uint8List random = body.sublist(ptr, ptr + 32);
  //   ptr += 32;

  //   // Session ID
  //   int sessionIdLen = body[ptr++];
  //   Uint8List sessionId = body.sublist(ptr, ptr + sessionIdLen);
  //   ptr += sessionIdLen;

  //   // Cipher Suites
  //   int cipherSuitesLen = (body[ptr++] << 8) | body[ptr++];
  //   List<int> cipherSuites = [];
  //   for (int i = 0; i < cipherSuitesLen; i += 2) {
  //     cipherSuites.add((body[ptr++] << 8) | body[ptr++]);
  //   }

  //   // Compression Methods
  //   int compressionMethodsLen = body[ptr++];
  //   Uint8List compressionMethods = body.sublist(
  //     ptr,
  //     ptr + compressionMethodsLen,
  //   );
  //   ptr += compressionMethodsLen;

  //   // Extensions
  //   int extensionsLen = (body[ptr++] << 8) | body[ptr++];
  //   List<TlsExtension> extensions = [];
  //   int extEnd = ptr + extensionsLen;

  //   while (ptr < extEnd) {
  //     int extType = (body[ptr++] << 8) | body[ptr++];
  //     int extLen = (body[ptr++] << 8) | body[ptr++];
  //     Uint8List extData = body.sublist(ptr, ptr + extLen);
  //     ptr += extLen;
  //     extensions.add(
  //       TlsExtension(type: extType, length: extLen, data: extData),
  //     );
  //   }

  //   // Parsed Extension Variables
  //   String? sni;
  //   List<ParsedKeyShare> keyShares = [];
  //   List<int> supportedVersions = [];
  //   List<int> supportedGroups = [];
  //   List<int> signatureAlgorithms = [];
  //   List<String>? alpn = [];
  //   int? maxFragmentLength;
  //   Uint8List? padding;
  //   Uint8List? cookie;
  //   List<int> pskKeyExchangeModes = [];
  //   Uint8List? preSharedKey;
  //   Uint8List? renegotiationInfo;
  //   Uint8List? quicTransportParametersRaw;

  //   for (var ext in extensions) {
  //     Uint8List extView = ext.data;
  //     int type = ext.type;
  //     if (ext.type == 0x39) {
  //       // quic_transport_parameters
  //       quicTransportParametersRaw = ext.data;
  //     }

  //     if (type == 0x0000) {
  //       // Server Name Indication (SNI)
  //       // list_len(2) + name_type(1) + name_len(2) + name(n)
  //       int nameLen = (extView[3] << 8) | extView[4];
  //       sni = utf8.decode(extView.sublist(5, 5 + nameLen));
  //     } else if (type == 0x0033) {
  //       // Key Share
  //       int ptr2 = 2; // skip list length
  //       int end = extView.length;
  //       while (ptr2 < end) {
  //         int group = (extView[ptr2++] << 8) | extView[ptr2++];
  //         int keyLen = (extView[ptr2++] << 8) | extView[ptr2++];
  //         Uint8List pubkey = extView.sublist(ptr2, ptr2 + keyLen);
  //         ptr2 += keyLen;
  //         keyShares.add(ParsedKeyShare(group, pubkey));
  //       }
  //     } else if (type == 0x002b) {
  //       // Supported Versions
  //       int len = extView[0];
  //       for (int i = 1; i < 1 + len; i += 2) {
  //         supportedVersions.add((extView[i] << 8) | extView[i + 1]);
  //       }
  //     } else if (type == 0x000a) {
  //       // Supported Groups
  //       int len = (extView[0] << 8) | extView[1];
  //       for (int i = 2; i < 2 + len; i += 2) {
  //         supportedGroups.add((extView[i] << 8) | extView[i + 1]);
  //       }
  //     } else if (type == 0x000d) {
  //       // Signature Algorithms
  //       int len = (extView[0] << 8) | extView[1];
  //       for (int i = 2; i < 2 + len; i += 2) {
  //         signatureAlgorithms.add((extView[i] << 8) | extView[i + 1]);
  //       }
  //     } else if (type == 0x0010) {
  //       // ALPN
  //       int listLen = (extView[0] << 8) | extView[1];
  //       int i = 2;
  //       while (i < 2 + listLen) {
  //         int nameLen = extView[i++];
  //         alpn.add(utf8.decode(extView.sublist(i, i + nameLen)));
  //         i += nameLen;
  //       }
  //     } else if (type == 0x0039) {
  //       // QUIC Transport Parameters
  //       quicTransportParametersRaw = extView;
  //     } else if (type == 0x0001) {
  //       // Max Fragment Length
  //       maxFragmentLength = extView[0];
  //     } else if (type == 0x0015) {
  //       // Padding
  //       padding = extView;
  //     } else if (type == 0x002a) {
  //       // Cookie
  //       int len = (extView[0] << 8) | extView[1];
  //       cookie = extView.sublist(2, 2 + len);
  //     } else if (type == 0x002d) {
  //       // PSK Key Exchange Modes
  //       int len = extView[0];
  //       for (int i = 1; i <= len; i++) {
  //         pskKeyExchangeModes.add(extView[i]);
  //       }
  //     } else if (type == 0x0029) {
  //       // Pre-Shared Key
  //       preSharedKey = extView;
  //     } else if (type == 0xff01) {
  //       // Renegotiation Info
  //       renegotiationInfo = extView;
  //     }
  //   }

  //   return ClientHello(
  //     type: 'client_hello',
  //     legacyVersion: legacyVersion,
  //     random: random,
  //     sessionId: sessionId,
  //     cipherSuites: cipherSuites,
  //     compressionMethods: compressionMethods,
  //     extensions: extensions,
  //     sni: sni,
  //     keyShares: keyShares,
  //     supportedVersions: supportedVersions,
  //     supportedGroups: supportedGroups,
  //     signatureAlgorithms: signatureAlgorithms,
  //     alpn: alpn,
  //     maxFragmentLength: maxFragmentLength,
  //     padding: padding,
  //     cookie: cookie,
  //     pskKeyExchangeModes: pskKeyExchangeModes,
  //     preSharedKey: preSharedKey,
  //     renegotiationInfo: renegotiationInfo,
  //     quicTransportParametersRaw: quicTransportParametersRaw,
  //   );
  // }

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

    return ClientHello(
      type: 'client_hello',
      legacyVersion: legacy_version,
      random: random,
      sessionId: session_id,
      cipherSuites: cipher_suites,
      compressionMethods: compression_methods,
      extensions: extensions,
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

  // Uint8List build_tls_client_hello() {
  //   final bb = BytesBuilder();

  //   // Legacy Version (usually 0x0303 for TLS 1.2 compatibility)
  //   buffer.pushUint16(legacyVersion);

  //   // Random (32 bytes)
  //   buffer.pushBytes(random);

  //   // Session ID
  //   buffer.pushUint8(sessionId.length);
  //   buffer.pushBytes(sessionId);

  //   // Cipher Suites
  //   buffer.pushUint16(cipherSuites.length);
  //   for (int cipherSuite in cipherSuites) {
  //     buffer.pushUint16(cipherSuite);
  //   }

  //   // Compression Methods
  //   buffer.pushUint8(compressionMethods.length);

  //   buffer.pushBytes(compressionMethods);

  //   // Extensions
  //   buffer.pushUint16(extensions.length);

  //   for (var extension in extensions) {
  //     buffer.pushUint16(extension.type);
  //     buffer.pushUint16(extension.data.length);
  //     buffer.pushBytes(extension.data);
  //   }

  //   final bodyBytes = buffer.data;

  //   var ptr = 0;

  //   // var legacy_version = (view[ptr++] << 8) | view[ptr++];
  //   bb.add([legacyVersion >> 8 & 0xff, legacyVersion & 0xff]);
  //   // var random = view.slice(ptr, ptr + 32);
  //   bb.add(random);
  //   // ptr += 32;
  //   var session_id_len = view[ptr++];
  //   var session_id = view.slice(ptr, ptr + session_id_len);
  //   ptr += session_id_len;

  //   var cipher_suites_len = (view[ptr++] << 8) | view[ptr++];
  //   var cipher_suites = [];
  //   for (var i = 0; i < cipher_suites_len; i += 2) {
  //     var code = (view[ptr++] << 8) | view[ptr++];
  //     cipher_suites.push(code);
  //   }

  //   var compression_methods_len = view[ptr++];
  //   var compression_methods = view.slice(ptr, ptr + compression_methods_len);
  //   ptr += compression_methods_len;

  //   var extensions_len = (view[ptr++] << 8) | view[ptr++];
  //   var extensions = [];
  //   var ext_end = ptr + extensions_len;
  //   while (ptr < ext_end) {
  //     var ext_type = (view[ptr++] << 8) | view[ptr++];
  //     var ext_len = (view[ptr++] << 8) | view[ptr++];
  //     var ext_data = view.slice(ptr, ptr + ext_len);
  //     ptr += ext_len;
  //     extensions.push({type: ext_type, data: ext_data});
  //   }
  //   return bodyBytes;

  //   // final header = Uint8List(4);
  //   // header[0] = 0x01; // ClientHello Type

  //   // // Set 24-bit length (Big Endian)
  //   // header[1] = (bodyBytes.length >> 16) & 0xFF;
  //   // header[2] = (bodyBytes.length >> 8) & 0xFF;
  //   // header[3] = bodyBytes.length & 0xFF;

  //   // return Uint8List.fromList([...header, ...bodyBytes]);
  // }

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

  // ClientHello parseClientHelloBody(QuicBuffer buffer) {
  //   buffer.pullUint16(); // Skip legacy_version
  //   final random = buffer.pullBytes(32);
  //   buffer.pullVector(1); // Skip legacy_session_id

  //   final cipherSuitesBytes = buffer.pullVector(2);
  //   final cipherSuites = <int>[];
  //   final csBuffer = QuicBuffer(data: cipherSuitesBytes);
  //   while (!csBuffer.eof) {
  //     cipherSuites.add(csBuffer.pullUint16());
  //   }

  //   buffer.pullVector(1); // Skip legacy_compression_methods
  //   final extensions = parseExtensions(buffer);

  //   return ClientHello(
  //     random: random,
  //     cipherSuites: cipherSuites,
  //     extensions: extensions,
  //   );
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

void main() {
  // The ClientHello payload from RFC 9001, Appendix A.2
  // final rfcClientHelloPayload =
  //     (BytesBuilder()
  //           ..add(
  //             HEX.decode(
  //               '060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868'
  //               '04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578'
  //               '616d706c652e636f6dff01000100000a00080006001d00170018001000070005'
  //               '04616c706e000500050100000000003300260024001d00209370b2c9caa47fba'
  //               'baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400'
  //               '0d0010000e0403050306030203080408050806002d00020101001c0002400100'
  //               '3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000'
  //               '75300901100f088394c8f03e51570806048000ffff',
  //             ),
  //           )
  //           ..add(Uint8List(920)) // Padding to simulate a real initial packet
  //           )
  //         .toBytes();

  // print("--- Running with RFC 9001 ClientHello Payload ---");
  // parsePayload(
  //   rfcClientHelloPayload,
  //   QUICSession(dcid: Uint8List(0), address: "127.0.0.1", port: 443),
  // );
  ClientHello ch = ClientHello.parse_tls_client_hello(clientHello);

  print("parsed client hello: $ch");
  final encoded = ch.build_tls_client_hello2();
  print("encoded:  ${HEX.encode(encoded)}");
  print("expected: ${HEX.encode(clientHello)}");
  int compareConst = clientHello.length;

  if (!encoded
      .sublist(0, compareConst)
      .equals(clientHello.sublist(0, compareConst))) {
    throw Exception("list mismatch");
  }
  // print("encoded:  ${HEX.encode(encoded)}");
  ch = ClientHello.parse_tls_client_hello(encoded);
  final re_encoded = ch.build_tls_client_hello2();
  print("Re-encoded:  ${HEX.encode(re_encoded)}");
  print("expected: ${HEX.encode(clientHello)}");

  if (!re_encoded
      .sublist(0, compareConst)
      .equals(clientHello.sublist(0, compareConst))) {
    throw Exception("list mismatch");
  }
}

final clientHello = Uint8List.fromList([
  0x03,
  0x03,
  0x00,
  0x01,
  0x02,
  0x03,
  0x04,
  0x05,
  0x06,
  0x07,
  0x08,
  0x09,
  0x0a,
  0x0b,
  0x0c,
  0x0d,
  0x0e,
  0x0f,
  0x10,
  0x11,
  0x12,
  0x13,
  0x14,
  0x15,
  0x16,
  0x17,
  0x18,
  0x19,
  0x1a,
  0x1b,
  0x1c,
  0x1d,
  0x1e,
  0x1f,
  0x00,
  0x00,
  0x06,
  0x13,
  0x01,
  0x13,
  0x02,
  0x13,
  0x03,
  0x01,
  0x00,
  0x00,
  0xbb,
  0x00,
  0x00,
  0x00,
  0x18,
  0x00,
  0x16,
  0x00,
  0x00,
  0x13,
  0x65,
  0x78,
  0x61,
  0x6d,
  0x70,
  0x6c,
  0x65,
  0x2e,
  0x75,
  0x6c,
  0x66,
  0x68,
  0x65,
  0x69,
  0x6d,
  0x2e,
  0x6e,
  0x65,
  0x74,
  0x00,
  0x0a,
  0x00,
  0x08,
  0x00,
  0x06,
  0x00,
  0x1d,
  0x00,
  0x17,
  0x00,
  0x18,
  0x00,
  0x10,
  0x00,
  0x0b,
  0x00,
  0x09,
  0x08,
  0x70,
  0x69,
  0x6e,
  0x67,
  0x2f,
  0x31,
  0x2e,
  0x30,
  0x00,
  0x0d,
  0x00,
  0x14,
  0x00,
  0x12,
  0x04,
  0x03,
  0x08,
  0x04,
  0x04,
  0x01,
  0x05,
  0x03,
  0x08,
  0x05,
  0x05,
  0x01,
  0x08,
  0x06,
  0x06,
  0x01,
  0x02,
  0x01,
  0x00,
  0x33,
  0x00,
  0x26,
  0x00,
  0x24,
  0x00,
  0x1d,
  0x00,
  0x20,
  0x35,
  0x80,
  0x72,
  0xd6,
  0x36,
  0x58,
  0x80,
  0xd1,
  0xae,
  0xea,
  0x32,
  0x9a,
  0xdf,
  0x91,
  0x21,
  0x38,
  0x38,
  0x51,
  0xed,
  0x21,
  0xa2,
  0x8e,
  0x3b,
  0x75,
  0xe9,
  0x65,
  0xd0,
  0xd2,
  0xcd,
  0x16,
  0x62,
  0x54,
  0x00,
  0x2d,
  0x00,
  0x02,
  0x01,
  0x01,
  0x00,
  0x2b,
  0x00,
  0x03,
  0x02,
  0x03,
  0x04,
  0x00,
  0x39,
  0x00,
  0x31,
  0x03,
  0x04,
  0x80,
  0x00,
  0xff,
  0xf7,
  0x04,
  0x04,
  0x80,
  0xa0,
  0x00,
  0x00,
  0x05,
  0x04,
  0x80,
  0x10,
  0x00,
  0x00,
  0x06,
  0x04,
  0x80,
  0x10,
  0x00,
  0x00,
  0x07,
  0x04,
  0x80,
  0x10,
  0x00,
  0x00,
  0x08,
  0x01,
  0x0a,
  0x09,
  0x01,
  0x0a,
  0x0a,
  0x01,
  0x03,
  0x0b,
  0x01,
  0x19,
  0x0f,
  0x05,
  0x63,
  0x5f,
  0x63,
  0x69,
  0x64,
]);
