// =============================================================
// tls_server_handshake.dart
//
// Fully session‑driven, runnable TLS 1.3 server handshake builders
// for QUIC. No hard‑coded bytes, no replay artifacts.
//
// ✅ CORRECTED: QUIC transport parameters (extension 0x0039)
// are now ALWAYS generated and included, as REQUIRED by RFC 9001.
//
// This version matches your actual EcdsaCert implementation:
//
//   class EcdsaCert {
//     Uint8List cert;        // DER certificate
//     Uint8List privateKey;  // raw EC scalar (32 bytes)
//     Uint8List publickKey;  // raw EC public key (uncompressed)
//     Uint8List fingerPrint;
//   }
// =============================================================

import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:crypto/crypto.dart' as crypto;

import '../cipher/ecdsa.dart';
import '../handshake/server_hello.dart';
import '../hash.dart';
import '../hkdf.dart';
import '../cipher/x25519.dart';
import 'cert_utils.dart';
import 'quic_server_session.dart';

// =============================================================
// Constants
// =============================================================

const int tlsAes128GcmSha256 = 0x1301;
const int x25519Group = 0x001d;

// TLS 1.3 signature algorithm
// ecdsa_secp256r1_sha256
const int ecdsaP256Sha256 = 0x0403;

// QUIC transport parameter IDs (RFC 9000)
const int tpInitialMaxData = 0x0004;
const int tpInitialMaxStreamDataBidiLocal = 0x0005;
const int tpInitialMaxStreamDataBidiRemote = 0x0006;
const int tpInitialMaxStreamsBidi = 0x0008;
const int tpIdleTimeout = 0x0001;
// =============================================================
// Helper types
// =============================================================

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

// =============================================================
// QUIC Transport Parameters (MANDATORY)
// =============================================================

Uint8List _encodeVarInt(int v) {
  // QUIC varint encoding (RFC 9000)
  // 1 byte:  0..63
  // 2 bytes: 64..16383
  // 4 bytes: 16384..1073741823
  // 8 bytes: 1073741824..(2^62-1)
  if (v < 0x40) {
    // 00
    return Uint8List.fromList([v & 0x3f]);
  } else if (v < 0x4000) {
    // 01
    return Uint8List.fromList([0x40 | ((v >> 8) & 0x3f), v & 0xff]);
  } else if (v < 0x40000000) {
    // 10
    return Uint8List.fromList([
      0x80 | ((v >> 24) & 0x3f),
      (v >> 16) & 0xff,
      (v >> 8) & 0xff,
      v & 0xff,
    ]);
  } else if (v < 0x4000000000000000) {
    // 11
    final b = ByteData(8);
    b.setUint8(0, 0xC0 | ((v >> 56) & 0x3f));
    b.setUint8(1, (v >> 48) & 0xff);
    b.setUint8(2, (v >> 40) & 0xff);
    b.setUint8(3, (v >> 32) & 0xff);
    b.setUint8(4, (v >> 24) & 0xff);
    b.setUint8(5, (v >> 16) & 0xff);
    b.setUint8(6, (v >> 8) & 0xff);
    b.setUint8(7, v & 0xff);
    return b.buffer.asUint8List();
  } else {
    throw ArgumentError('varint out of range: $v');
  }
}

Uint8List _tp(int id, int value) {
  final v = _encodeVarInt(value);
  return Uint8List.fromList([
    ..._encodeVarInt(id),
    ..._encodeVarInt(v.length),
    ...v,
  ]);
}

/// ✅ Minimal but VALID server transport parameters
Uint8List buildQuicTransportParameters() {
  return Uint8List.fromList([
    ..._tp(tpIdleTimeout, 30),
    ..._tp(tpInitialMaxData, 1 << 20),
    ..._tp(tpInitialMaxStreamDataBidiLocal, 1 << 18),
    ..._tp(tpInitialMaxStreamDataBidiRemote, 1 << 18),
    ..._tp(tpInitialMaxStreamsBidi, 16),
  ]);
}

// =============================================================
// ServerHello
// =============================================================

// Uint8List buildServerHello({
//   required Uint8List serverRandom,
//   required Uint8List publicKey,
//   required Uint8List sessionId,
//   required int cipherSuite,
//   required int group,
// }) {
//   final body = BytesBuilder();

//   body.add([0x03, 0x03]); // legacy_version
//   body.add(serverRandom);
//   body.addByte(sessionId.length);
//   body.add(sessionId);
//   body.add([(cipherSuite >> 8) & 0xff, cipherSuite & 0xff]);
//   body.addByte(0x00); // compression

//   final extensions = BytesBuilder();

//   // supported_versions
//   extensions.add([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);

//   // key_share
//   final ks = BytesBuilder()
//     ..add([(group >> 8) & 0xff, group & 0xff])
//     ..add([(publicKey.length >> 8) & 0xff, publicKey.length & 0xff])
//     ..add(publicKey);

//   final ksBytes = ks.toBytes();

//   extensions.add([
//     0x00,
//     0x33,
//     (ksBytes.length >> 8) & 0xff,
//     ksBytes.length & 0xff,
//     ...ksBytes,
//   ]);

//   final extBytes = extensions.toBytes();
//   body.add([(extBytes.length >> 8) & 0xff, extBytes.length & 0xff]);
//   body.add(extBytes);

//   final bodyBytes = body.toBytes();

//   return Uint8List.fromList([
//     0x02,
//     (bodyBytes.length >> 16) & 0xff,
//     (bodyBytes.length >> 8) & 0xff,
//     bodyBytes.length & 0xff,
//     ...bodyBytes,
//   ]);
// }

// =============================================================
// EncryptedExtensions
// =============================================================

Uint8List buildAlpnExt(String protocol) {
  final p = Uint8List.fromList(utf8.encode(protocol));
  return Uint8List.fromList([0x00, p.length + 1, p.length, ...p]);
}

Uint8List buildEncryptedExtensions(List<BuiltExtension> extensions) {
  final ext = BytesBuilder();

  for (final e in extensions) {
    ext.add([
      (e.type >> 8) & 0xff,
      e.type & 0xff,
      (e.data.length >> 8) & 0xff,
      e.data.length & 0xff,
      ...e.data,
    ]);
  }

  final extBytes = ext.toBytes();
  final body = BytesBuilder()
    ..add([(extBytes.length >> 8) & 0xff, extBytes.length & 0xff])
    ..add(extBytes);

  final bodyBytes = body.toBytes();

  return Uint8List.fromList([
    0x08,
    (bodyBytes.length >> 16) & 0xff,
    (bodyBytes.length >> 8) & 0xff,
    bodyBytes.length & 0xff,
    ...bodyBytes,
  ]);
}

// =============================================================
// Certificate
// =============================================================

Uint8List buildCertificate(List<CertificateEntry> certificates) {
  final certList = BytesBuilder();

  for (final c in certificates) {
    certList.add([
      (c.cert.length >> 16) & 0xff,
      (c.cert.length >> 8) & 0xff,
      c.cert.length & 0xff,
      ...c.cert,
      (c.extensions.length >> 8) & 0xff,
      c.extensions.length & 0xff,
      ...c.extensions,
    ]);
  }

  final certBytes = certList.toBytes();
  final body = BytesBuilder()
    ..addByte(0x00)
    ..add([
      (certBytes.length >> 16) & 0xff,
      (certBytes.length >> 8) & 0xff,
      certBytes.length & 0xff,
    ])
    ..add(certBytes);

  final bodyBytes = body.toBytes();

  return Uint8List.fromList([
    0x0b,
    (bodyBytes.length >> 16) & 0xff,
    (bodyBytes.length >> 8) & 0xff,
    bodyBytes.length & 0xff,
    ...bodyBytes,
  ]);
}

// =============================================================
// CertificateVerify (ECDSA)
// =============================================================

Uint8List buildServerCertificateVerify({
  required EcdsaCert cert,
  required Uint8List transcriptHash,
}) {
  final context = utf8.encode('TLS 1.3, server CertificateVerify');
  final padding = Uint8List(64);

  final toBeSigned = Uint8List.fromList([
    ...context,
    ...padding,
    ...transcriptHash,
  ]);

  final hash = crypto.sha256.convert(toBeSigned).bytes;
  final signature = ecdsaSign(hash, cert.privateKey);
  final totalLen = 4 + signature.length;

  return Uint8List.fromList([
    0x0f,
    (totalLen >> 16) & 0xff,
    (totalLen >> 8) & 0xff,
    totalLen & 0xff,
    (ecdsaP256Sha256 >> 8) & 0xff,
    ecdsaP256Sha256 & 0xff,
    (signature.length >> 8) & 0xff,
    signature.length & 0xff,
    ...signature,
  ]);
}

// =============================================================
// One‑shot helper used by QuicServerSession
// =============================================================

ServerHandshakeArtifacts buildServerHandshakeArtifacts({
  required Uint8List serverRandom,
  required Uint8List serverPublicKey,
  required EcdsaCert serverCert,
  required Uint8List transcriptHashBeforeCertVerify,
  String alpnProtocol = 'ping/1.0',
}) {
  final sh = buildServerHello(
    serverRandom: serverRandom,
    publicKey: serverPublicKey,
    sessionId: Uint8List(0),
    cipherSuite: tlsAes128GcmSha256,
    group: x25519Group,
  );

  final ee = buildEncryptedExtensions([
    BuiltExtension(type: 0x0010, data: buildAlpnExt(alpnProtocol)),
    BuiltExtension(type: 0x0039, data: buildQuicTransportParameters()),
  ]);

  final cert = buildCertificate([CertificateEntry(cert: serverCert.cert)]);

  final cv = buildServerCertificateVerify(
    cert: serverCert,
    transcriptHash: transcriptHashBeforeCertVerify,
  );

  return ServerHandshakeArtifacts(
    serverHello: sh,
    encryptedExtensions: ee,
    certificate: cert,
    certificateVerify: cv,
  );
}

// =============================================================
// Demo main (runnable)
// =============================================================

void main() {
  final keyPair = KeyPair.generate();
  final serverCert = generateSelfSignedCertificate();

  final serverRandom = Uint8List.fromList(
    List.generate(32, (_) => math.Random.secure().nextInt(256)),
  );

  final dummyTranscriptHash = createHash(Uint8List(0));

  final artifacts = buildServerHandshakeArtifacts(
    serverRandom: serverRandom,
    serverPublicKey: keyPair.publicKeyBytes,
    serverCert: serverCert,
    transcriptHashBeforeCertVerify: dummyTranscriptHash,
  );

  print('ServerHello:        ${HEX.encode(artifacts.serverHello)}');
  print('EncryptedExtensions:${HEX.encode(artifacts.encryptedExtensions)}');
  print('Certificate:        ${HEX.encode(artifacts.certificate)}');
  print('CertificateVerify:  ${HEX.encode(artifacts.certificateVerify)}');
}
