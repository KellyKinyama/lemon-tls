// ============================================================================
// TLS 1.3 SERVER HANDSHAKE ENGINE — TRANSCRIPT-CORRECT VERSION
// RFC 8446 compliant (byte-exact transcript hashing)
// ============================================================================

import 'dart:typed_data';
import 'package:hex/hex.dart';

import '../hash.dart'; // createHash(), hmacSha256()
import '../hkdf.dart'; // hkdfExpandLabel()
import 'tls13_keyshcedule.dart'; // Tls13KeySchedule
import 'tls_constants.dart';
import 'tls_hello.dart';
import 'tls_extensions.dart';
import 'tls_certificate.dart';
import 'tls_certificate_verify.dart';
import 'tls_keyshare.dart';
import 'tls_record_layer.dart';

// ============================================================================
// Helpers
// ============================================================================

Uint8List _randBytes(int n) {
  final out = Uint8List(n);
  for (int i = 0; i < n; i++) {
    out[i] = (DateTime.now().microsecondsSinceEpoch >> (i % 8)) & 0xFF;
  }
  return out;
}

/// Wrap a handshake BODY as a Handshake message
Uint8List _handshake(int type, Uint8List body) {
  final len = body.length;
  return Uint8List.fromList([
    type,
    (len >> 16) & 0xFF,
    (len >> 8) & 0xFF,
    len & 0xFF,
    ...body,
  ]);
}

// ============================================================================
// Byte‑exact TLS 1.3 transcript
// ============================================================================

class HandshakeTranscript {
  final BytesBuilder _buf = BytesBuilder(copy: false);

  void add(Uint8List handshakeBytes) {
    _buf.add(handshakeBytes);
  }

  Uint8List hash() {
    return createHash(_buf.toBytes());
  }

  Uint8List bytes() => _buf.toBytes();
}

// ============================================================================
// TLS 1.3 Server Session
// ============================================================================

class Tls13ServerSession {
  final Uint8List certificate;
  final Uint8List privateKey;

  late HandshakeTranscript transcript;
  late Uint8List clientRandom;

  late Tls13KeySchedule keySchedule;
  late TlsRecordLayer recordLayer;

  late int selectedGroup;
  late Uint8List serverPublicKey;

  bool handshakeComplete = false;

  Tls13ServerSession({required this.certificate, required this.privateKey});

  // ==========================================================================
  // STEP 1 — ClientHello → ServerHello
  // ==========================================================================

  /// Input: FULL ClientHello handshake bytes
  Uint8List handleClientHello(Uint8List clientHelloHandshake) {
    transcript = HandshakeTranscript();

    // ✅ Add exact ClientHello wire bytes to transcript
    transcript.add(clientHelloHandshake);

    // ✅ Parse ONLY body (skip handshake header)
    final clientHelloBody = clientHelloHandshake.sublist(4);

    // legacy_version (2) + random (32)
    clientRandom = clientHelloBody.sublist(2, 34);

    final parsed = parseHello(TLSMessageType.CLIENT_HELLO, clientHelloBody);
    final extensions = parsed["extensions"] as List;

    // Negotiation
    final groups = _extractSupportedGroups(extensions);
    final shares = _extractKeyShares(extensions);
    if (shares.isEmpty) {
      throw Exception("ClientHello missing key_share");
    }

    selectedGroup =
        _negotiateGroup(groups, shares) ??
        (throw Exception("No mutually supported ECDHE group"));

    final clientPub =
        shares.firstWhere((e) => e["group"] == selectedGroup)["key_exchange"]
            as Uint8List;

    final ks = Tls13KeyShare.generate(
      group: selectedGroup,
      clientPublicKey: clientPub,
    );
    serverPublicKey = ks.publicKey;

    // Build ServerHello BODY
    final shBody = buildHello("server", {
      "random": _randBytes(32),
      "cipher_suite": CipherSuite.tlsAes128GcmSha256,
      "session_id": parsed["session_id"],
      "extensions": [
        {"type": TLSExt.SUPPORTED_VERSIONS, "value": TLSVersion.TLS1_3},
        {
          "type": TLSExt.KEY_SHARE,
          "value": {"group": selectedGroup, "key_exchange": serverPublicKey},
        },
      ],
    });

    // Build ServerHello HANDSHAKE
    final serverHello = _handshake(HandshakeType.serverHello, shBody);

    // ✅ Add ServerHello wire bytes
    transcript.add(serverHello);

    // Key schedule
    keySchedule = Tls13KeySchedule();
    keySchedule.computeHandshakeSecrets(
      sharedSecret: ks.sharedSecret,
      helloHash: transcript.hash(),
    );

    // 🔑 Log secrets
    print(
      "CLIENT_HANDSHAKE_TRAFFIC_SECRET "
      "${HEX.encode(clientRandom)} "
      "${HEX.encode(keySchedule.clientHandshakeTrafficSecret)}",
    );
    print(
      "SERVER_HANDSHAKE_TRAFFIC_SECRET "
      "${HEX.encode(clientRandom)} "
      "${HEX.encode(keySchedule.serverHandshakeTrafficSecret)}",
    );

    recordLayer = TlsRecordLayer();
    recordLayer.setHandshakeKeys(
      clientKey: keySchedule.clientHandshakeKey,
      clientIV: keySchedule.clientHandshakeIV,
      serverKey: keySchedule.serverHandshakeKey,
      serverIV: keySchedule.serverHandshakeIV,
    );

    return serverHello;
  }

  // ==========================================================================
  // EncryptedExtensions
  // ==========================================================================

  Uint8List buildEncryptedExtensions() {
    final hs = _handshake(
      HandshakeType.encryptedExtensions,
      buildExtensions([]),
    );
    transcript.add(hs);
    return recordLayer.encrypt(hs);
  }

  // ==========================================================================
  // Certificate
  // ==========================================================================

  Uint8List buildCertificateMessage() {
    final body = buildCertificate({
      "version": TLSVersion.TLS1_3,
      "request_context": Uint8List(0),
      "entries": [
        {"cert": certificate, "extensions": []},
      ],
    });

    final hs = _handshake(HandshakeType.certificate, body);
    transcript.add(hs);
    return recordLayer.encrypt(hs);
  }

  // ==========================================================================
  // CertificateVerify
  // ==========================================================================

  Uint8List buildCertificateVerifyMessage() {
    final body = buildCertificateVerify(
      privateKey: privateKey,
      transcriptHash: transcript.hash(),
    );

    final hs = _handshake(HandshakeType.certificateVerify, body);
    transcript.add(hs);
    return recordLayer.encrypt(hs);
  }

  // ==========================================================================
  // Finished
  // ==========================================================================

  Uint8List buildFinishedMessage() {
    final finishedKey = hkdfExpandLabel(
      keySchedule.serverHandshakeTrafficSecret,
      Uint8List(0),
      "finished",
      32,
    );

    final verifyData = hmacSha256(finishedKey, transcript.hash());

    final hs = _handshake(HandshakeType.finished, verifyData);

    transcript.add(hs);
    final rec = recordLayer.encrypt(hs);

    keySchedule.computeApplicationSecrets(transcript.hash());
    handshakeComplete = true;

    return rec;
  }

  // ==========================================================================
  // Extension helpers
  // ==========================================================================

  List<int> _extractSupportedGroups(List exts) =>
      (exts.firstWhere((e) => e["type"] == TLSExt.SUPPORTED_GROUPS)["value"]
              as List)
          .cast<int>();

  List<Map<String, dynamic>> _extractKeyShares(List exts) =>
      (exts.firstWhere((e) => e["type"] == TLSExt.KEY_SHARE)["value"] as List)
          .cast<Map<String, dynamic>>();

  int? _negotiateGroup(List<int> groups, List<Map<String, dynamic>> shares) {
    const prefs = [Tls13KeyShare.x25519, Tls13KeyShare.secp256r1];
    for (final g in prefs) {
      if (groups.contains(g) && shares.any((s) => s["group"] == g)) {
        return g;
      }
    }
    return null;
  }
}

// ============================================================================
// Constants
// ============================================================================

class HandshakeType {
  static const int clientHello = 1;
  static const int serverHello = 2;
  static const int encryptedExtensions = 8;
  static const int certificate = 11;
  static const int certificateVerify = 15;
  static const int finished = 20;
}

class CipherSuite {
  static const int tlsAes128GcmSha256 = 0x1301;
}
