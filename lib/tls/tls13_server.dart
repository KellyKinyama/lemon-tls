// ===========================================================
// TLS 1.3 SERVER (Corrected for EC signing + correct ECDHE + correct transcript)
// ===========================================================

import 'dart:typed_data';
import 'dart:math';

import '../handlers/record_layer.dart';
// import '../handlers/handshake_messages.dart';
import '../handlers/key_schedule.dart';
// import '../handlers/tls_key_share.dart';

import '../hash.dart'; // your SHA256
import '../hkdf.dart'; // your HKDF-Expand-Label + HKDF-Extract
import 'package:basic_utils/basic_utils.dart';

import 'ecdsa.dart';
import 'handshake_messages.dart';
import 'tls_key_share.dart'; // for EC signing

// ======================================================================
// TLS SERVER CONTEXT
// ======================================================================

class Tls13ServerContext {
  late Uint8List clientRandom;
  late Uint8List clientSessionId;
  late Uint8List clientPublicKey;
  late int selectedGroup;

  late List<int> clientCipherSuites;
  late List<int> clientGroups;
  late List<int> clientSignatureAlgorithms;

  late int selectedCipherSuite;
  late Uint8List sharedSecret;

  final transcript = BytesBuilder();
}

// ======================================================================
// TLS SERVER ENGINE
// ======================================================================

class Tls13Server {
  final TlsRecordLayer recordLayer = TlsRecordLayer();
  final Tls13ServerContext context = Tls13ServerContext();

  final Uint8List serverCertificateDer; // ✅ DER certificate
  final Uint8List serverEcPrivateKey; // ✅ raw 32‑byte EC scalar

  Tls13Server({
    required this.serverCertificateDer,
    required this.serverEcPrivateKey,
  });

  // ===========================================================
  // Step 1 — Parse ClientHello
  // ===========================================================

  void handleClientHello(Uint8List clientHelloRecord) {
    final rec = TLSPlaintext.fromBytes(clientHelloRecord);
    final frag = rec.fragment;

    final type = frag[0];
    final length = (frag[1] << 16) | (frag[2] << 8) | frag[3];
    final body = frag.sublist(4, 4 + length);

    if (type != 1) {
      throw Exception("Expected ClientHello");
    }

    _parseClientHelloBody(body);
  }

  void _parseClientHelloBody(Uint8List body) {
    int off = 0;

    off += 2; // legacy_version
    context.clientRandom = body.sublist(off, off + 32);
    off += 32;

    final sidLen = body[off++];
    context.clientSessionId = body.sublist(off, off + sidLen);
    off += sidLen;

    // Cipher suites
    final csLen = (body[off] << 8) | body[off + 1];
    off += 2;
    final csEnd = off + csLen;

    final suites = <int>[];
    while (off < csEnd) {
      suites.add((body[off] << 8) | body[off + 1]);
      off += 2;
    }
    context.clientCipherSuites = suites;

    final compLen = body[off++];
    off += compLen;

    // Extensions
    final extLen = (body[off] << 8) | body[off + 1];
    off += 2;

    Uint8List? kp;
    int? group;

    final groups = <int>[];
    final sigAlgs = <int>[];

    final extEnd = off + extLen;

    while (off < extEnd) {
      final etype = (body[off] << 8) | body[off + 1];
      off += 2;
      final elen = (body[off] << 8) | body[off + 1];
      off += 2;

      final data = body.sublist(off, off + elen);
      off += elen;

      switch (etype) {
        case 0x000a: // supported_groups
          final glen = (data[0] << 8) | data[1];
          int p = 2;
          while (p < 2 + glen) {
            groups.add((data[p] << 8) | data[p + 1]);
            p += 2;
          }
          break;

        case 0x002d: // signature_algorithms
          final slen = (data[0] << 8) | data[1];
          int p = 2;
          while (p < 2 + slen) {
            sigAlgs.add((data[p] << 8) | data[p + 1]);
            p += 2;
          }
          break;

        case 0x0033: // key_share
          group = (data[0] << 8) | data[1];
          final pkLen = (data[2] << 8) | data[3];
          kp = data.sublist(4, 4 + pkLen);
          break;
      }
    }

    context.clientGroups = groups;
    context.clientSignatureAlgorithms = sigAlgs;

    if (kp == null || group == null) {
      throw Exception("Missing client key_share");
    }

    context.selectedGroup = group;
    context.clientPublicKey = kp;

    // Update transcript
    context.transcript.add(body);
  }

  // ===========================================================
  // Step 2 — Build ServerHello + ECDHE
  // ===========================================================

  List<Uint8List> buildServerHelloFlight() {
    context.selectedCipherSuite = 0x1301; // TLS_AES_128_GCM_SHA256

    // ✅ generate real ECDHE shared secret
    final ks = TlsKeyShare.generate(
      group: context.selectedGroup,
      clientPublicKey: context.clientPublicKey,
    );

    context.sharedSecret = ks.sharedSecret;

    final serverRandom = Uint8List.fromList(
      List.generate(32, (_) => Random.secure().nextInt(255)),
    );

    final sh = buildServerHello(
      random: serverRandom,
      sessionId: context.clientSessionId,
      cipherSuite: context.selectedCipherSuite,
      group: context.selectedGroup,
      serverPublicKey: ks.publicKey,
    );

    context.transcript.add(sh.sublist(4)); // handshake body only

    return [sh];
  }

  // ===========================================================
  // Step 3 — KeySchedule
  // ===========================================================

  late Tls13KeySchedule keySchedule;

  void computeHandshakeSecrets() {
    final thash = createHash(context.transcript.toBytes());

    keySchedule = Tls13KeySchedule()
      ..computeHandshakeSecrets(
        sharedSecret: context.sharedSecret,
        helloHash: thash,
      );

    recordLayer.setKeys(
      clientKey: keySchedule.clientHandshakeKey,
      clientIV: keySchedule.clientHandshakeIV,
      serverKey: keySchedule.serverHandshakeKey,
      serverIV: keySchedule.serverHandshakeIV,
    );
  }

  // ===========================================================
  // Step 4 — EncryptedExtensions, Certificate, CertVerify, Finished
  // ===========================================================

  List<Uint8List> buildEncryptedFlight() {
    final out = <Uint8List>[];

    // -------------------------------------------------------
    // 1) EncryptedExtensions
    // -------------------------------------------------------
    final ee = buildEncryptedExtensions(alpn: ["http/1.1"]);
    context.transcript.add(ee.sublist(4));
    out.add(recordLayer.encrypt(ee));

    // -------------------------------------------------------
    // 2) Certificate
    // -------------------------------------------------------
    final certMsg = buildCertificateMessage(
      certificateDer: serverCertificateDer,
    );
    context.transcript.add(certMsg.sublist(4));
    out.add(recordLayer.encrypt(certMsg));

    // -------------------------------------------------------
    // 3) CertificateVerify (ECDSA P‑256 / SHA‑256)
    // -------------------------------------------------------
    final sigHash = createHash(context.transcript.toBytes());

    // ✅ USE RAW 32‑BYTE PRIVATE KEY
    // serverEcPrivateKey is already Uint8List(32)
    final Uint8List privateKeyScalar = serverEcPrivateKey;

    // ✅ CALL YOUR SIGNER CORRECTLY
    final Uint8List signature = tls13EcdsaSign(
      privateKeyScalar, // raw scalar
      sigHash, // SHA‑256 transcript hash
    );

    final certVerify = buildCertificateVerify(
      algorithm: 0x0403, // ecdsa_secp256r1_sha256 (TLS 1.3)
      signature: signature,
    );

    context.transcript.add(certVerify.sublist(4));
    out.add(recordLayer.encrypt(certVerify));

    // -------------------------------------------------------
    // 4) Finished
    // -------------------------------------------------------
    final finHash = createHash(context.transcript.toBytes());

    final finishedKey = hkdfExpandLabel(
      keySchedule.serverHandshakeTrafficSecret,
      Uint8List(0),
      "finished",
      32,
    );

    final finishedMac = hmacSha256(finishedKey, finHash);

    final fin = buildFinished(finishedMac: finishedMac);

    context.transcript.add(fin.sublist(4));
    out.add(recordLayer.encrypt(fin));

    return out;
  }

  // ===========================================================
  // Step 5 — Handle ClientFinished
  // ===========================================================

  bool handleClientRecord(Uint8List record) {
    final plaintext = recordLayer.decrypt(record);

    final type = plaintext[0];
    if (type != 20) throw Exception("Expected Finished");

    final len = (plaintext[1] << 16) | (plaintext[2] << 8) | plaintext[3];
    final verifyData = plaintext.sublist(4, 4 + len);

    context.transcript.add(plaintext.sublist(4)); // add body only

    final thash = createHash(context.transcript.toBytes());

    final finishedKey = hkdfExpandLabel(
      keySchedule.clientHandshakeTrafficSecret,
      Uint8List(0),
      "finished",
      32,
    );

    final expected = hmacSha256(finishedKey, thash);

    // constant‑time compare
    if (!_equal(expected, verifyData)) {
      throw Exception("ClientFinished verification failed");
    }

    return true;
  }

  bool _equal(Uint8List a, Uint8List b) {
    int diff = a.length ^ b.length;
    for (int i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}
