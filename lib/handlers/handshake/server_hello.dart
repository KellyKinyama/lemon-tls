import 'dart:convert';
import 'dart:typed_data';

import '../extensions/extensions.dart';
import '../message_types.dart';

class ServerHello extends HandShakeMessageType {
  @override
  // Uint8List body;
  TLS_MESSAGE_TYPE message;
  int legacy_version;
  // TLS_VERSION version_hint;
  Uint8List random;
  Uint8List session_id;
  Uint8List body;
  int cipher_suite;
  List<int> legacy_compression;
  List<TlsExtension> extensions;
  TLS_VERSION version;
  ServerHello({
    required this.message,
    required this.legacy_version,
    // required this.version_hint,
    required this.random,
    required this.session_id,
    required this.cipher_suite,
    required this.legacy_compression,
    required this.extensions,
    required this.body,
    required this.version,
    // required cipher_suite,
  }) : super(message, body);
}

Uint8List buildServerHello(Map<String, dynamic> params) {
  final int version = params['version'] as int;
  final Uint8List serverRandom = params['server_random'] as Uint8List;

  final Uint8List sessionId =
      (params['legacy_session_id'] as Uint8List?) ?? Uint8List(0);

  final int cipherSuite = params['cipher_suite'] as int;
  final int compressionMethod = params['compression_method'] ?? 0;

  final int selectedGroup = params['selected_group'] as int;
  final Uint8List serverKeyShare = params['server_key_share'] as Uint8List;

  final List<dynamic>? extraExts = params['extra_extensions'];

  // ---------------------------
  // 1) legacy_version
  // TLS 1.3 requires 0x0303
  // ---------------------------
  final int legacyVersion = 0x0303;
  final body = <int>[];

  body.add((legacyVersion >> 8) & 0xFF);
  body.add(legacyVersion & 0xFF);

  // ---------------------------
  // 2) random (32 bytes)
  // ---------------------------
  body.addAll(serverRandom);

  // ---------------------------
  // 3) legacy_session_id
  // ---------------------------
  body.add(sessionId.length & 0xFF);
  body.addAll(sessionId);

  // ---------------------------
  // 4) cipher_suite
  // ---------------------------
  body.add((cipherSuite >> 8) & 0xFF);
  body.add(cipherSuite & 0xFF);

  // ---------------------------
  // 5) legacy_compression_method (must be 0)
  // ---------------------------
  body.add(compressionMethod & 0xFF);

  // ---------------------------
  // 6) Extensions (TLS 1.3)
  // ---------------------------
  final exts = <int>[];

  if (version == 0x0304) {
    // -------- supported_versions (0x002B) --------
    exts.addAll([
      0x00, 0x2B, // extension type
      0x00, 0x02, // length = 2
      0x03, 0x04, // TLS 1.3
    ]);

    // -------- key_share (0x0033) --------
    final ks = <int>[];

    // group
    ks.add((selectedGroup >> 8) & 0xFF);
    ks.add(selectedGroup & 0xFF);

    // key share length
    ks.add((serverKeyShare.length >> 8) & 0xFF);
    ks.add(serverKeyShare.length & 0xFF);

    // public key bytes
    ks.addAll(serverKeyShare);

    exts.addAll([
      0x00, 0x33, // key_share
      (ks.length >> 8) & 0xFF,
      ks.length & 0xFF,
      ...ks,
    ]);
  }

  // -------- Extra extensions (raw passthrough) --------
  if (extraExts != null && extraExts.isNotEmpty) {
    for (var e in extraExts) {
      final int type = e.type;
      final Uint8List data = e.data;

      exts.add((type >> 8) & 0xFF);
      exts.add(type & 0xFF);

      exts.add((data.length >> 8) & 0xFF);
      exts.add(data.length & 0xFF);

      exts.addAll(data);
    }
  }

  // Write extension total length
  body.add((exts.length >> 8) & 0xFF);
  body.add(exts.length & 0xFF);
  body.addAll(exts);

  // ---------------------------
  // 7) Wrap in TLS Handshake header (ServerHello = 2)
  // ---------------------------
  final msg = <int>[];
  msg.add(0x02); // handshake type = server_hello

  final int len = body.length;
  msg.add((len >> 16) & 0xFF);
  msg.add((len >> 8) & 0xFF);
  msg.add(len & 0xFF);

  msg.addAll(body);

  return Uint8List.fromList(msg);
}


Uint8List buildEncryptedExtensions({
  List<int>? alpnProtocols,
}) {
  final body = <int>[];

  final extensions = <int>[];

  // ---------- ALPN (0x0010) ----------
  if (alpnProtocols != null && alpnProtocols.isNotEmpty) {
    final alpn = <int>[];

    // ALPN list length placeholder
    final proto = utf8.encode(alpnProtocols.first);

    // length of one protocol entry
    alpn.add(proto.length);
    alpn.addAll(proto);

    extensions.addAll([
      0x00, 0x10, // ALPN type
      0x00, (alpn.length + 2) & 0xFF, // total ext len
      0x00, alpn.length,             // ALPN list length
      ...alpn
    ]);
  }

  // ---------- Finalize extensions ----------
  body.add((extensions.length >> 8) & 0xFF);
  body.add(extensions.length & 0xFF);
  body.addAll(extensions);

  // ---------- Handshake wrapper ----------
  final msg = <int>[];
  msg.add(0x08); // handshake type = EncryptedExtensions

  final len = body.length;
  msg.addAll([
    (len >> 16) & 0xFF,
    (len >> 8) & 0xFF,
    len & 0xFF,
  ]);

  msg.addAll(body);
  return Uint8List.fromList(msg);
}

Uint8List buildCertificate({
  required Uint8List certificate,
}) {
  final body = <int>[];

  // ---------- certificate_request_context ----------
  body.add(0x00); // length = 0, server authentication

  // ---------- certificate_list length (3 bytes) ----------
  final certLen = certificate.length + 3; // each entry has 3-byte length
  body.addAll([
    (certLen >> 16) & 0xFF,
    (certLen >> 8) & 0xFF,
    certLen & 0xFF,
  ]);

  // ---------- certificate_entry ----------
  body.addAll([
    (certificate.length >> 16) & 0xFF,
    (certificate.length >> 8) & 0xFF,
    certificate.length & 0xFF,
  ]);
  body.addAll(certificate);

  // ---------- extensions (0-length for now) ----------
  body.add(0x00);
  body.add(0x00);

  // ---------- Handshake wrapper ----------
  final msg = <int>[11]; // certificate = 11

  final len = body.length;
  msg.addAll([
    (len >> 16) & 0xFF,
    (len >> 8) & 0xFF,
    len & 0xFF,
  ]);

  msg.addAll(body);
  return Uint8List.fromList(msg);
}


Uint8List buildCertificateVerify({
  required int algorithm, // e.g. 0x0401 = rsa_pkcs1_sha256
  required Uint8List signature,
}) {
  final body = <int>[];

  // signature_algorithm (2 bytes)
  body.add((algorithm >> 8) & 0xFF);
  body.add(algorithm & 0xFF);

  // signature length (2 bytes)
  body.add((signature.length >> 8) & 0xFF);
  body.add(signature.length & 0xFF);

  // signature bytes
  body.addAll(signature);

  // handshake wrapper
  final msg = <int>[15]; // CertificateVerify = 15

  final len = body.length;
  msg.addAll([
    (len >> 16) & 0xFF,
    (len >> 8) & 0xFF,
    len & 0xFF,
  ]);

  msg.addAll(body);
  return Uint8List.fromList(msg);
}

Uint8List buildFinished(
  Uint8List finishedKey,
  Uint8List transcriptHash,
) {
  final hmacSha256 =
      Hmac(sha256, finishedKey); // RFC 8446 default for TLS_AES_128_GCM_SHA256

  final mac = hmacSha256.convert(transcriptHash).bytes;

  final body = <int>[]..addAll(mac);

  final msg = <int>[20]; // Finished = 20

  msg.addAll([
    (body.length >> 16) & 0xFF,
    (body.length >> 8) & 0xFF,
    body.length & 0xFF,
  ]);

  msg.addAll(body);

  return Uint8List.fromList(msg);
}