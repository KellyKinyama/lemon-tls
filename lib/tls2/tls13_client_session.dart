// ============================================================================
// TLS 1.3 SERVER HANDSHAKE ENGINE
// RFC 8446-Compliant Server-Side Handshake
// ============================================================================

import 'dart:typed_data';

import '../hash.dart'; // createHash(), hmacSha256()
import '../hkdf.dart'; // hkdfExpandLabel()
import 'tls13_keyshcedule.dart'; // Tls13KeySchedule
import 'tls_constants.dart';
import 'tls_hello.dart';
import 'tls_extensions.dart';
import 'tls_certificate.dart';
import 'tls_certificate_verify.dart'; // buildCertificateVerifyMessage()
import 'tls_keyshare.dart'; // Tls13KeyShare
import 'tls_new_session_ticket.dart';
import 'tls_record_layer.dart';

// ============================================================================
// Helper RNG (NOT crypto-secure)
// ============================================================================
Uint8List _randBytes(int n) {
  final out = Uint8List(n);
  for (int i = 0; i < n; i++) {
    out[i] = (DateTime.now().microsecondsSinceEpoch >> (i % 8)) & 0xFF;
  }
  return out;
}

// ============================================================================
// TLS 1.3 Server Session
// ============================================================================
class Tls13ClientSession {
  final Uint8List certificate; // DER
  final Uint8List privateKey; // P‑256 private key (raw 32 bytes)

  late Uint8List clientHello; // handshake struct
  late Uint8List serverHello; // handshake struct

  late Uint8List handshakeHash; // TH_1
  late Uint8List transcriptHash; // TH_2
  late Uint8List transcriptAfterCert; // TH_3
  late Uint8List transcriptBeforeFinished; // TH_4

  late Tls13KeySchedule keySchedule;
  late TlsRecordLayer recordLayer;

  late Uint8List sharedSecret;
  late int selectedGroup;
  late Uint8List serverPublicKey;

  bool handshakeComplete = false;

  Tls13ClientSession({required this.certificate, required this.privateKey});

  // ==========================================================================
  // STEP 1 — Handle ClientHello **BODY ONLY** (no handshake header)
  // ==========================================================================
  Uint8List handleClientHello(Uint8List clientHelloBody) {
    // ✅ clientHelloBody starts at legacy_version (03 03)
    // We rebuild the full handshake struct for transcript hash:
    clientHello = Uint8List.fromList([
      1, // ClientHello
      (clientHelloBody.length >> 16) & 0xFF,
      (clientHelloBody.length >> 8) & 0xFF,
      clientHelloBody.length & 0xFF,
      ...clientHelloBody,
    ]);

    // ✅ parse body only
    final parsed = parseHello(TLSMessageType.CLIENT_HELLO, clientHelloBody);
    final List extensions = parsed["extensions"];

    // -----------------------------------------------------------------------
    // SUPPORTED_GROUPS
    // -----------------------------------------------------------------------
    final groups = _extractSupportedGroups(extensions);

    // -----------------------------------------------------------------------
    // KEY_SHARE
    // -----------------------------------------------------------------------
    final keyshares = _extractKeyShares(extensions);
    if (keyshares.isEmpty) {
      throw Exception("ClientHello missing key_share");
    }

    // -----------------------------------------------------------------------
    // NEGOTIATE GROUP
    // -----------------------------------------------------------------------
    selectedGroup =
        _negotiateGroup(groups, keyshares) ??
        (throw Exception("No mutually supported ECDHE group"));

    final entry = keyshares.firstWhere(
      (e) => e["group"] == selectedGroup,
      orElse: () => throw Exception("Client missing matching key_share"),
    );

    final Uint8List clientPub = entry["key_exchange"];

    // -----------------------------------------------------------------------
    // Compute ECDHE shared secret
    // -----------------------------------------------------------------------
    final ks = Tls13KeyShare.generate(
      group: selectedGroup,
      clientPublicKey: clientPub,
    );

    sharedSecret = ks.sharedSecret;
    serverPublicKey = ks.publicKey;

    // -----------------------------------------------------------------------
    // Build ServerHello plaintext
    // -----------------------------------------------------------------------
    // serverHello = buildHello("server", {
    //   "random": _randBytes(32),
    //   "cipher_suite": 0x1301,
    //   "session_id": parsed["session_id"],
    //   "extensions": [
    //     {"type": "SUPPORTED_VERSIONS", "value": TLSVersion.TLS1_3},
    //     {
    //       "type": "KEY_SHARE",
    //       "value": {"group": selectedGroup, "key_exchange": serverPublicKey},
    //     },
    //   ],
    // });

    final serverHelloBody = buildHello("server", {
      "random": _randBytes(32),
      "cipher_suite": 0x1301,
      "session_id": parsed["session_id"],
      "extensions": [
        {"type": "SUPPORTED_VERSIONS", "value": TLSVersion.TLS1_3},
        {
          "type": "KEY_SHARE",
          "value": {"group": selectedGroup, "key_exchange": serverPublicKey},
        },
      ],
    });

    // ✅ Wrap in Handshake header
    final len = serverHelloBody.length;
    serverHello = Uint8List.fromList([
      2, // HandshakeType.server_hello
      (len >> 16) & 0xFF,
      (len >> 8) & 0xFF,
      len & 0xFF,
      ...serverHelloBody,
    ]);

    // -----------------------------------------------------------------------
    // TH_1 = Hash(ClientHello || ServerHello)
    // -----------------------------------------------------------------------
    handshakeHash = createHash(
      Uint8List.fromList([...clientHello, ...serverHello]),
    );

    // -----------------------------------------------------------------------
    // Initialize Key Schedule
    // -----------------------------------------------------------------------
    keySchedule = Tls13KeySchedule();
    keySchedule.computeHandshakeSecrets(
      sharedSecret: sharedSecret,
      helloHash: handshakeHash,
    );

    // -----------------------------------------------------------------------
    // Initialize record layer
    // -----------------------------------------------------------------------
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
  // STEP 2 — EncryptedExtensions
  // ==========================================================================
  Uint8List buildEncryptedExtensions() {
    final body = buildExtensions([]);
    final rec = recordLayer.encrypt(body);

    transcriptHash = createHash(
      Uint8List.fromList([...handshakeHash, ...body]),
    );

    return rec;
  }

  // ==========================================================================
  // STEP 3 — Certificate
  // ==========================================================================
  Uint8List buildCertificateMessage() {
    final body = buildCertificate({
      "version": TLSVersion.TLS1_3,
      "request_context": Uint8List(0),
      "entries": [
        {"cert": certificate, "extensions": []},
      ],
    });

    final rec = recordLayer.encrypt(body);

    transcriptAfterCert = createHash(
      Uint8List.fromList([...transcriptHash, ...body]),
    );

    return rec;
  }

  // ==========================================================================
  // STEP 4 — CertificateVerify
  // ==========================================================================
  Uint8List buildCertificateVerifyMessage() {
    final body = buildCertificateVerify(
      privateKey: privateKey,
      transcriptHash: transcriptAfterCert,
    );

    final rec = recordLayer.encrypt(body);

    transcriptBeforeFinished = createHash(
      Uint8List.fromList([...transcriptAfterCert, ...body]),
    );

    return rec;
  }

  // ==========================================================================
  // STEP 5 — Finished
  // ==========================================================================
  Uint8List buildFinishedMessage() {
    final finishedKey = hkdfExpandLabel(
      keySchedule.serverHandshakeTrafficSecret,
      Uint8List(0),
      "finished",
      32,
    );

    final verifyData = hmacSha256(finishedKey, transcriptBeforeFinished);

    final rec = recordLayer.encrypt(verifyData);

    final th5 = createHash(
      Uint8List.fromList([...transcriptBeforeFinished, ...verifyData]),
    );

    keySchedule.computeApplicationSecrets(th5);

    handshakeComplete = true;

    return rec;
  }

  // ==========================================================================
  // EXTENSION DECODERS
  // ==========================================================================

  // ✅ SUPPORTED_GROUPS
  List<int> _extractSupportedGroups(List exts) {
    for (final e in exts) {
      if (e["type"] == TLSExt.SUPPORTED_GROUPS) {
        print("🔍 _extractSupportedGroups: raw value = ${e["value"]}");
        print(
          "🔍 _extractSupportedGroups: runtime types = ${(e["value"] as List).map((v) => v.runtimeType).toList()}",
        );

        if (e["value"] is List) {
          final fixed = (e["value"] as List)
              .map(
                (v) => v is int
                    ? v
                    : v is num
                    ? v.toInt()
                    : 0,
              )
              .toList();
          print("✅ _extractSupportedGroups: FIXED list = $fixed");
          return fixed;
        }

        if (e["data"] is Uint8List) {
          final raw = e["data"] as Uint8List;
          final out = <int>[];
          int off = 2;
          while (off + 2 <= raw.length) {
            out.add((raw[off] << 8) | raw[off + 1]);
            off += 2;
          }
          print("✅ _extractSupportedGroups (raw path): $out");
          return out;
        }
      }
    }
    print("⚠️ _extractSupportedGroups: none found");
    return [];
  }

  // ✅ KEY_SHARE
  List<Map<String, dynamic>> _extractKeyShares(List exts) {
    for (final e in exts) {
      if (e["type"] == TLSExt.KEY_SHARE) {
        // ✅ Preferred: ClientHello decoded via handler
        if (e["value"] is List) {
          final list = (e["value"] as List)
              .map(
                (m) => {
                  "group": (m["group"] as num).toInt(),
                  "key_exchange": m["key_exchange"] as Uint8List,
                },
              )
              .toList();
          return list;
        }

        // ✅ ServerHello branch (NO vector<2>)
        if (e["data"] is Uint8List) {
          final raw = e["data"] as Uint8List;

          if (raw.length < 4) return [];

          final group = (raw[0] << 8) | raw[1];
          final klen = (raw[2] << 8) | raw[3];

          if (4 + klen != raw.length) return [];

          return [
            {"group": group, "key_exchange": raw.sublist(4, 4 + klen)},
          ];
        }
      }
    }
    return [];
  }

  // ✅ Group Negotiation
  int? _negotiateGroup(List<int> groups, List<Map<String, dynamic>> keyshares) {
    print("🔍 NEGOTIATE: groups = $groups");
    print("🔍 NEGOTIATE: keyshares = $keyshares");
    print(
      "🔍 NEGOTIATE: keyshare group runtime types = ${keyshares.map((m) => m["group"].runtimeType).toList()}",
    );

    const preferred = [Tls13KeyShare.x25519, Tls13KeyShare.secp256r1];

    if (groups.isEmpty) {
      final ksGroups = keyshares
          .map((e) => (e["group"] as num).toInt())
          .toList();
      print("🔍 NEGOTIATE: fallback ksGroups = $ksGroups");

      for (final g in preferred) {
        if (ksGroups.contains(g)) {
          print("✅ NEGOTIATE: selected (fallback) = $g");
          return g;
        }
      }
    }

    for (final g in preferred) {
      if (groups.contains(g)) {
        print("✅ NEGOTIATE: selected = $g");
        return g;
      }
    }

    print("❌ NEGOTIATE: no match");
    return null;
  }
}
