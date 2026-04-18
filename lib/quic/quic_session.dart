import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:lemon_tls/quic/hkdf.dart';
import 'package:lemon_tls/tls2/crypto_hash.dart';
import 'package:x25519/x25519.dart';

import 'buffer.dart';
import 'cipher/p256.dart';
import 'crypto.dart';
import 'frames/quic_frames.dart';
import 'handshake/certificate.dart';
import 'handshake/certificate_verify.dart';
import 'handshake/client_hello.dart';
import 'handshake/encrypted_extensions.dart';
import 'handshake/finished.dart';
import 'handshake/server_hello.dart';
import 'handshake/tls_messages.dart';
import 'packet/payload_parser2.dart';
import 'quic_keys.dart';

Uint8List quicHkdfExpandLabel({
  required Uint8List secret,
  required String label,
  required int length,
}) {
  final labelBytes = utf8.encode(label);

  final hkdfLabel = BytesBuilder()
    ..addByte(length >> 8)
    ..addByte(length & 0xff)
    ..addByte(labelBytes.length)
    ..add(labelBytes)
    ..addByte(0); // empty context

  return hkdfExpand(
    prk: secret,
    info: hkdfLabel.toBytes(),
    outputLength: length,
  );
}

class QUICSession {
  final Uint8List dcid;
  final String address;
  final int port;

  InitialKeys? initialRead;
  InitialKeys? initialWrite;

  HandshakeKeys? handshakeRead;
  HandshakeKeys? handshakeWrite;

  OneRttKeys? oneRttRead;
  OneRttKeys? oneRttWrite;

  int largestPn = -1;
  // State for keys, stream limits, largest PN, etc., would be managed here.

  // ✅ Store the parsed ClientHello here
  ClientHello? clientHello;

  // ✅ TLS handshake transcript (per-session)
  final List<Uint8List> transcript = [];

  Uint8List? clientHelloRaw;

  // X25519 ephemeral keypair
  late QuicKeyPair x25519;

  // P‑256 ephemeral keypair
  late Uint8List p256Priv;
  late Uint8List p256Pub;

  // 32‑byte TLS server_random
  late Uint8List serverRandom;

  QUICSession({required this.dcid, required this.address, required this.port}) {
    x25519 = QuicKeyPair.generate();

    var aliceKeyPair = generateKeyPair();
    // Generate P‑256 keypair
    p256Priv = Uint8List.fromList(aliceKeyPair.privateKey);
    p256Pub = Uint8List.fromList(aliceKeyPair.publicKey);

    // if (p256Pub.length != 65 || p256Pub[0] != 0x04) {
    //   throw Exception(
    //     "Generated P-256 pubkey must be uncompressed (65 bytes).",
    //   );
    // }

    // Random bytes for ServerHello
    final rnd = math.Random.secure();
    serverRandom = Uint8List.fromList(
      List.generate(32, (_) => rnd.nextInt(256)),
    );
  }

  ClientHello buildInitialClientHello(String hostname) {
    final rnd = math.Random.secure();
    final random = Uint8List.fromList(
      List.generate(32, (_) => rnd.nextInt(256)),
    );

    final extensions = <TlsExtension>[];

    /* ============================================
   * Helper: Build correct TlsExtension object
   * ============================================ */
    TlsExtension makeExt(int type, QuicBuffer buf) {
      final bytes = buf.toBytes();
      return TlsExtension(type: type, length: bytes.length, data: bytes);
    }

    /* =========================
   * 1. Server Name Indication
   * ========================= */
    final hostBytes = Uint8List.fromList(hostname.codeUnits);

    final sniBuf = QuicBuffer()
      ..pushUint16(hostBytes.length + 3) // server_name_list length
      ..pushUint8(0x00) // host_name
      ..pushUint16(hostBytes.length)
      ..pushBytes(hostBytes);

    extensions.add(makeExt(0x0000, sniBuf));

    /* =========================
   * 2. Supported Groups
   * ========================= */
    final groupsBuf = QuicBuffer()
      ..pushUint16(4) // length of group list in bytes
      ..pushUint16(0x001d) // x25519
      ..pushUint16(0x0017); // secp256r1

    extensions.add(makeExt(0x000a, groupsBuf));

    /* =========================
   * 3. Key Share (x25519)
   * ========================= */
    final keyShareEntry = QuicBuffer()
      ..pushUint16(0x001d)
      ..pushUint16(x25519.publicKey.length)
      ..pushBytes(x25519.publicKey);

    final keyShareBuf = QuicBuffer()
      ..pushUint16(keyShareEntry.writeIndex) // correct length
      ..pushBytes(keyShareEntry.toBytes());

    extensions.add(makeExt(0x0033, keyShareBuf));

    /* =========================
   * 4. Supported Versions (TLS 1.3 only)
   * ========================= */
    final versionsBuf = QuicBuffer()
      ..pushUint8(2) // byte length of version list
      ..pushUint8(0x03) // TLS 1.3
      ..pushUint8(0x04);

    extensions.add(makeExt(0x002b, versionsBuf));

    /* =========================
   * 5. Signature Algorithms
   * ========================= */
    final sigBuf = QuicBuffer()
      ..pushUint16(4) // byte length
      ..pushUint16(0x0403) // ecdsa_secp256r1_sha256
      ..pushUint16(0x0804); // rsa_pss_rsae_sha256

    extensions.add(makeExt(0x000d, sigBuf));

    /* =========================
   * 6. ALPN (MANDATORY for QUIC)
   * ========================= */
    final alpnProto = Uint8List.fromList('h3'.codeUnits);

    final alpnBuf = QuicBuffer()
      ..pushUint16(alpnProto.length + 1)
      ..pushUint8(alpnProto.length)
      ..pushBytes(alpnProto);

    extensions.add(makeExt(0x0010, alpnBuf));

    /* =========================
   * 7. PSK Key Exchange Modes
   * ========================= */
    final pskBuf = QuicBuffer()
      ..pushUint8(1) // length
      ..pushUint8(1); // psk_dhe_ke

    extensions.add(makeExt(0x002d, pskBuf));

    /* =========================
   * 8. QUIC Transport Parameters  (RFC 9000 TLV)
   * ========================= */

    final tpBuf = QuicBuffer();

    // ---- max_idle_timeout = 30000 (0x7530) ----
    tpBuf.pushVarint(0x01); // parameter id
    tpBuf.pushVarint(2); // length in bytes
    tpBuf.pushUint16(30000); // raw value

    // ---- initial_max_data = 0x100000 ----
    tpBuf.pushVarint(0x04);
    tpBuf.pushVarint(4);
    tpBuf.pushUint32(0x100000);

    extensions.add(makeExt(0x0039, tpBuf));

    /* =========================
   * Final ClientHello Object
   * ========================= */
    return ClientHello(
      type: 'client_hello',
      legacyVersion: 0x0303,
      random: random,
      sessionId: Uint8List(0),
      cipherSuites: const [
        0x1301, // TLS_AES_128_GCM_SHA256
        0x1302, // TLS_AES_256_GCM_SHA384
      ],
      compressionMethods: Uint8List.fromList([0x00]),
      extensions: extensions,
      rawData: Uint8List(0),
    );
  }

  void onServerHello(ServerHello sh) {
    print("🔧 QUICSession.onServerHello(): deriving handshake secrets");

    if (clientHelloRaw == null) {
      throw StateError("ClientHello raw bytes missing");
    }

    final ks = sh.keyShareEntry!;
    Uint8List sharedSecret;

    // ============================================================
    // 1) ECDHE
    // ============================================================
    if (ks.group == 0x001d) {
      sharedSecret = X25519(x25519.privateKey, ks.pub);
    } else if (ks.group == 0x0017) {
      sharedSecret = generateP256SharedSecret(ks.pub, p256Priv);
    } else {
      throw StateError("Unsupported key_share group");
    }

    // ============================================================
    // 2) Transcript hash
    // ============================================================
    final transcriptHash = createHash(
      Uint8List.fromList([...clientHelloRaw!, ...sh.rawBytes!]),
    );

    // ============================================================
    // 3) TLS 1.3 secret chain (THIS WAS MISSING)
    // ============================================================

    // early_secret = HKDF-Extract(0, 0)
    final zero = Uint8List(32);
    final earlySecret = hkdfExtract(zero, salt: zero);

    // derived_secret = HKDF-Expand-Label(early_secret, "derived", "", HashLen)
    final derivedSecret = hkdfExpandLabel(
      secret: earlySecret,
      label: "derived",
      context: Uint8List(0),
      length: 32,
    );

    // handshake_secret = HKDF-Extract(derived_secret, shared_secret)
    final handshakeSecret = hkdfExtract(sharedSecret, salt: derivedSecret);

    // ============================================================
    // 4) Handshake traffic secrets
    // ============================================================
    final clientHsTraffic = hkdfExpandLabel(
      secret: handshakeSecret,
      label: "c hs traffic",
      context: transcriptHash,
      length: 32,
    );

    final serverHsTraffic = hkdfExpandLabel(
      secret: handshakeSecret,
      label: "s hs traffic",
      context: transcriptHash,
      length: 32,
    );

    // ============================================================
    // 5) QUIC handshake packet keys (TLS HKDF‑Expand‑Label)
    // ============================================================
    Uint8List qKey(Uint8List s) => hkdfExpandLabel(
      secret: s,
      label: "quic key",
      context: Uint8List(0),
      length: 16,
    );

    Uint8List qIv(Uint8List s) => hkdfExpandLabel(
      secret: s,
      label: "quic iv",
      context: Uint8List(0),
      length: 12,
    );

    Uint8List qHp(Uint8List s) => hkdfExpandLabel(
      secret: s,
      label: "quic hp",
      context: Uint8List(0),
      length: 16,
    );

    // ============================================================
    // 6) Install keys (direction matters)
    // ============================================================
    handshakeRead = HandshakeKeys(
      key: qKey(serverHsTraffic), // server → client
      iv: qIv(serverHsTraffic),
      hp: qHp(serverHsTraffic),
    );

    handshakeWrite = HandshakeKeys(
      key: qKey(clientHsTraffic), // client → server
      iv: qIv(clientHsTraffic),
      hp: qHp(clientHsTraffic),
    );

    print("✅ Handshake keys installed (TLS‑correct)");
  }

  void onEncryptedExtensions(EncryptedExtensions ee) {
    print("🔧 QUICSession.onEncryptedExtensions()");
  }

  void onCertificate(CertificateMessage cert) {
    print("🔧 QUICSession.onCertificate()");
  }

  void onCertificateVerify(CertificateVerify cv) {
    print("🔧 QUICSession.onCertificateVerify()");
  }

  void onFinished(FinishedMessage fin) {
    print("🔧 QUICSession.onFinished()");
    // TODO: install 1‑RTT keys
  }

  // Mock method to simulate processing decrypted frames
  // void handleDecryptedPacket(Uint8List plaintext) {
  //   // In a full implementation, this calls the frame parser and stream handlers.
  //   print(
  //     'Session ${HEX.encode(dcid)} received ${plaintext.length} bytes of plaintext.',
  //   );

  //   parsePayload(plaintext, this);
  // }

  void handleDecryptedPacket(Uint8List plaintext) {
    print(
      'Session ${HEX.encode(dcid)} received ${plaintext.length} bytes of plaintext.',
    );

    // -----------------------------
    // 1. Parse QUIC payload (frames)
    // -----------------------------
    final parsedPayload = parsePayload(plaintext, this);

    for (final frame in parsedPayload.frames) {
      if (frame is CryptoFrame) {
        print(
          "📦 Received CRYPTO frame: offset=${frame.offset}, len=${frame.data.length}",
        );

        // ---------------------------------------
        // 2. Parse TLS handshake messages inside CRYPTO frame
        // ---------------------------------------
        final tlsMessages = parseTlsMessages(frame.data);

        // Append raw frame data to transcript for key schedule later
        transcript.add(frame.data);

        // ---------------------------------------
        // 3. Process each TLS handshake message
        // ---------------------------------------
        for (final msg in tlsMessages) {
          // ---------------------------
          // ✅ ServerHello
          // ---------------------------
          if (msg is ServerHello) {
            print("🔑 Handling ServerHello…");

            // Save server random and keyshare info
            // (Optional but useful)
            serverRandom = msg.random;

            // This will later derive handshake keys
            onServerHello(msg);
          }

          // ---------------------------
          // ✅ EncryptedExtensions
          // ---------------------------
          if (msg is EncryptedExtensions) {
            print("✅ Received EncryptedExtensions");
            // nothing to derive yet
          }

          // ---------------------------
          // ✅ Certificate
          // ---------------------------
          if (msg is CertificateMessage) {
            print("✅ Received Certificate (${msg.certificates.length} certs)");
          }

          // ---------------------------
          // ✅ CertificateVerify
          // ---------------------------
          if (msg is CertificateVerify) {
            print("✅ Received CertificateVerify");
          }

          // ---------------------------
          // ✅ Finished
          // ---------------------------
          if (msg is FinishedMessage) {
            print("✅ Received Finished – ready for 1‑RTT key derivation");
            onFinished(msg);
          }
        }
      }
    }
  }

  // =============================================================
  // TLS 1.3 → QUIC handshake secret derivation
  // =============================================================

  // =============================================================
  // Handshake helpers
  // =============================================================
}



  // -------------------------------------------------
  // P‑256 (uses keys already generated in constructor)
  // -------------------------------------------------


