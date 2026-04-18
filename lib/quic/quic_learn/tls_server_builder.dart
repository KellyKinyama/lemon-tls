import 'dart:convert';
import 'dart:typed_data';

import 'package:hex/hex.dart';

import '../cipher/x25519.dart';

/// =============================================================
/// Constants
/// =============================================================

const int tlsAes128GcmSha256 = 0x1301; // 4865
const int x25519Group = 0x001d; // 29

/// =============================================================
/// Small helper types
/// =============================================================

class BuiltExtension {
  final int type;
  final Uint8List data;

  const BuiltExtension({required this.type, required this.data});
}

class CertificateEntry {
  final Uint8List cert;
  final Uint8List extensions;

  CertificateEntry({required this.cert, Uint8List? extensions})
    : extensions = extensions ?? Uint8List(0);
}

class ParsedKeyShare {
  final int group;
  final Uint8List pubkey;

  const ParsedKeyShare({required this.group, required this.pubkey});
}

class HandleClientHelloResult {
  final int? selectedCipher;
  final int? selectedGroup;
  final Uint8List? clientPublicKey;
  final Uint8List? serverPrivateKey;
  final Uint8List? serverPublicKey;
  final Uint8List? sharedSecret;

  const HandleClientHelloResult({
    required this.selectedCipher,
    required this.selectedGroup,
    required this.clientPublicKey,
    required this.serverPrivateKey,
    required this.serverPublicKey,
    required this.sharedSecret,
  });
}

class ServerHandshakeArtifacts {
  final Uint8List serverHello;
  final Uint8List encryptedExtensions;
  final Uint8List certificate;
  final Uint8List certificateVerify;

  const ServerHandshakeArtifacts({
    required this.serverHello,
    required this.encryptedExtensions,
    required this.certificate,
    required this.certificateVerify,
  });
}

/// =============================================================
/// Helpers
/// =============================================================

Uint8List hexToBytes(String hex) {
  return Uint8List.fromList(HEX.decode(hex.replaceAll(" ", "")));
}

/// =============================================================
/// buildServerHello(...)
/// Dart equivalent of your JS build_server_hello(...)
/// =============================================================
///
/// NOTE:
/// - This does NOT include QUIC transport parameters (same as your JS)
/// - It includes only:
///   - supported_versions
///   - key_share
///
Uint8List buildServerHello({
  required Uint8List serverRandom,
  required Uint8List publicKey,
  required Uint8List sessionId,
  required int cipherSuite,
  required int group,
}) {
  final body = BytesBuilder();

  // legacy_version = 0x0303
  body.add([0x03, 0x03]);

  // random
  body.add(serverRandom);

  // legacy_session_id_echo
  body.addByte(sessionId.length & 0xff);
  body.add(sessionId);

  // cipher_suite
  body.add([(cipherSuite >> 8) & 0xff, cipherSuite & 0xff]);

  // legacy_compression_method = 0x00
  body.addByte(0x00);

  // -------------------------
  // Extensions
  // -------------------------
  final extensions = BytesBuilder();

  // supported_versions extension
  // type = 0x002b
  // len  = 0x0002
  // val  = 0x0304
  extensions.add([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);

  // key_share extension
  final keyShareBody = BytesBuilder()
    ..add([(group >> 8) & 0xff, group & 0xff])
    ..add([(publicKey.length >> 8) & 0xff, publicKey.length & 0xff])
    ..add(publicKey);

  final keyShareBytes = keyShareBody.toBytes();

  extensions.add([
    0x00, 0x33, // extension type
    (keyShareBytes.length >> 8) & 0xff,
    keyShareBytes.length & 0xff,
    ...keyShareBytes,
  ]);

  final extBytes = extensions.toBytes();

  // extensions length
  body.add([(extBytes.length >> 8) & 0xff, extBytes.length & 0xff]);
  body.add(extBytes);

  final bodyBytes = body.toBytes();

  // Handshake header
  return Uint8List.fromList([
    0x02, // HandshakeType.server_hello
    (bodyBytes.length >> 16) & 0xff,
    (bodyBytes.length >> 8) & 0xff,
    bodyBytes.length & 0xff,
    ...bodyBytes,
  ]);
}

/// =============================================================
/// Hardcoded ServerHello using the exact values from your Node log
/// =============================================================
///
/// From your log:
/// - selected_cipher = 4865 = 0x1301
/// - selected_group  = 29   = 0x001d
/// - server_random   = aaa7ef...
/// - server_pubkey   = c7ee1a...
///
/// NOTE:
/// These bytes reproduce the logged ServerHello exactly.
/// But for a *working* live server, the public key in ServerHello MUST match
/// the private key the server uses for X25519 shared-secret computation.
/// The log does NOT contain the private key.
///
Uint8List buildServerHelloFromNodeLog() {
  return buildServerHello(
    serverRandom: hexToBytes(
      "aaa7efb20bbd35dcb6dee81d97b0fbd8db2268b7867f8d323a6c6a85b185dce7",
    ),
    publicKey: hexToBytes(
      "c7ee1a76a9165c3b1a9e808bbaae1e45d1f972c69d9e9ffbf4ab81b1e2ad996b",
    ),
    sessionId: Uint8List(0),
    cipherSuite: tlsAes128GcmSha256,
    group: x25519Group,
  );
}

/// =============================================================
/// buildAlpnExt(...)
/// Dart equivalent of your JS build_alpn_ext(...)
/// Returns extension DATA only (not type/length wrapper)
/// =============================================================
Uint8List buildAlpnExt(String protocol) {
  final protoBytes = Uint8List.fromList(utf8.encode(protocol));

  return Uint8List.fromList([
    0x00,
    protoBytes.length + 1,
    protoBytes.length,
    ...protoBytes,
  ]);
}

/// =============================================================
/// buildEncryptedExtensions(...)
/// Dart equivalent of your JS build_encrypted_extensions(...)
/// =============================================================
Uint8List buildEncryptedExtensions(List<BuiltExtension> extensions) {
  final extBytes = BytesBuilder();

  for (final ext in extensions) {
    extBytes.add([
      (ext.type >> 8) & 0xff,
      ext.type & 0xff,
      (ext.data.length >> 8) & 0xff,
      ext.data.length & 0xff,
      ...ext.data,
    ]);
  }

  final extBytesList = extBytes.toBytes();

  final body = BytesBuilder()
    ..add([(extBytesList.length >> 8) & 0xff, extBytesList.length & 0xff])
    ..add(extBytesList);

  final bodyBytes = body.toBytes();

  return Uint8List.fromList([
    0x08, // HandshakeType.encrypted_extensions
    (bodyBytes.length >> 16) & 0xff,
    (bodyBytes.length >> 8) & 0xff,
    bodyBytes.length & 0xff,
    ...bodyBytes,
  ]);
}

/// =============================================================
/// buildCertificate(...)
/// Dart equivalent of your JS build_certificate(...)
/// =============================================================
Uint8List buildCertificate(List<CertificateEntry> certificates) {
  final certList = BytesBuilder();

  for (final cert in certificates) {
    certList.add([
      (cert.cert.length >> 16) & 0xff,
      (cert.cert.length >> 8) & 0xff,
      cert.cert.length & 0xff,
      ...cert.cert,
      (cert.extensions.length >> 8) & 0xff,
      cert.extensions.length & 0xff,
      ...cert.extensions,
    ]);
  }

  final certListBytes = certList.toBytes();

  final body = BytesBuilder()
    ..addByte(0x00) // certificate_request_context length = 0
    ..add([
      (certListBytes.length >> 16) & 0xff,
      (certListBytes.length >> 8) & 0xff,
      certListBytes.length & 0xff,
    ])
    ..add(certListBytes);

  final bodyBytes = body.toBytes();

  return Uint8List.fromList([
    0x0b, // HandshakeType.certificate
    (bodyBytes.length >> 16) & 0xff,
    (bodyBytes.length >> 8) & 0xff,
    bodyBytes.length & 0xff,
    ...bodyBytes,
  ]);
}

/// =============================================================
/// buildCertificateVerify(...)
/// Dart equivalent of your JS build_certificate_verify(...)
/// =============================================================
Uint8List buildCertificateVerify({
  required int algorithm,
  required Uint8List signature,
}) {
  final totalLen = 4 + signature.length;

  return Uint8List.fromList([
    0x0f, // HandshakeType.certificate_verify
    (totalLen >> 16) & 0xff,
    (totalLen >> 8) & 0xff,
    totalLen & 0xff,
    (algorithm >> 8) & 0xff,
    algorithm & 0xff,
    (signature.length >> 8) & 0xff,
    signature.length & 0xff,
    ...signature,
  ]);
}

/// =============================================================
/// buildFinished(...)
/// Dart equivalent of your JS build_finished(...)
/// =============================================================
Uint8List buildFinished(Uint8List verifyData) {
  return Uint8List.fromList([
    0x14, // HandshakeType.finished
    (verifyData.length >> 16) & 0xff,
    (verifyData.length >> 8) & 0xff,
    verifyData.length & 0xff,
    ...verifyData,
  ]);
}

/// =============================================================
/// Minimal handleClientHelloX25519(...)
/// Dart equivalent of the X25519 branch of your JS handle_client_hello(...)
/// =============================================================
///
/// This version intentionally focuses on X25519, which is what your current
/// Dart client actually uses.
///
/// For a live server, make sure:
/// - serverPublicKey corresponds to serverPrivateKey
///
HandleClientHelloResult handleClientHelloX25519({
  required List<int> clientCipherSuites,
  required List<ParsedKeyShare> clientKeyShares,
  required Uint8List serverPrivateKey,
  required Uint8List serverPublicKey,
}) {
  const supportedCipherSuites = <int>[
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
  ];

  const supportedGroups = <int>[
    0x001d, // X25519
  ];

  int? selectedCipher;
  int? selectedGroup;
  Uint8List? clientPublicKey;
  Uint8List? sharedSecret;

  // Select cipher suite
  for (final cs in supportedCipherSuites) {
    if (clientCipherSuites.contains(cs)) {
      selectedCipher = cs;
      break;
    }
  }

  // Select group + key share
  for (final grp in supportedGroups) {
    final match = clientKeyShares.where((ks) => ks.group == grp).toList();
    if (match.isNotEmpty) {
      selectedGroup = grp;
      clientPublicKey = match.first.pubkey;
      break;
    }
  }

  if (selectedGroup == x25519Group && clientPublicKey != null) {
    sharedSecret = x25519ShareSecret(
      privateKey: serverPrivateKey,
      publicKey: clientPublicKey,
    );
  }

  return HandleClientHelloResult(
    selectedCipher: selectedCipher,
    selectedGroup: selectedGroup,
    clientPublicKey: clientPublicKey,
    serverPrivateKey: serverPrivateKey,
    serverPublicKey: serverPublicKey,
    sharedSecret: sharedSecret,
  );
}

/// =============================================================
/// Convenience helper to build the 4 server-side handshake messages
/// that your QuicServerSession can assign directly:
///
///   serverHelloBytes
///   encryptedExtensionsBytes
///   certificateBytes
///   certificateVerifyBytes
///
/// NOTE:
/// - `quicTransportParameters` must be the raw extension DATA for type 0x0039
/// - `certificateDer` must be DER bytes of the leaf certificate
/// - `certificateVerifySignature` must be the actual signature bytes
/// - `certificateVerifyAlgorithm` defaults to 0x0804 (rsa_pss_rsae_sha256)
///   but change it to match your certificate/signature code if needed.
/// =============================================================
ServerHandshakeArtifacts buildServerHandshakeArtifacts({
  required Uint8List serverRandom,
  required Uint8List serverPublicKey,
  required Uint8List quicTransportParameters,
  required Uint8List certificateDer,
  required Uint8List certificateVerifySignature,
  Uint8List? sessionId,
  int cipherSuite = tlsAes128GcmSha256,
  int group = x25519Group,
  String alpnProtocol = "ping/1.0",
  int certificateVerifyAlgorithm = 0x0804,
}) {
  final sh = buildServerHello(
    serverRandom: serverRandom,
    publicKey: serverPublicKey,
    sessionId: sessionId ?? Uint8List(0),
    cipherSuite: cipherSuite,
    group: group,
  );

  final ee = buildEncryptedExtensions([
    BuiltExtension(
      type: 0x0010, // ALPN
      data: buildAlpnExt(alpnProtocol),
    ),
    BuiltExtension(
      type: 0x0039, // QUIC transport parameters
      data: quicTransportParameters,
    ),
  ]);

  final cert = buildCertificate([
    CertificateEntry(cert: certificateDer, extensions: Uint8List(0)),
  ]);

  final cv = buildCertificateVerify(
    algorithm: certificateVerifyAlgorithm,
    signature: certificateVerifySignature,
  );

  return ServerHandshakeArtifacts(
    serverHello: sh,
    encryptedExtensions: ee,
    certificate: cert,
    certificateVerify: cv,
  );
}

/// =============================================================
/// Example helper: exact ServerHello from the Node log you pasted
/// =============================================================
void demoBuildServerHelloFromLog() {
  final sh = buildServerHelloFromNodeLog();
  print("ServerHello(hex) = ${HEX.encode(sh)}");
}
