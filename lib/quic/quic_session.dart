import 'dart:math' as math;
import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:x25519/x25519.dart';

import 'buffer.dart';
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

import 'package:elliptic/elliptic.dart';
import 'package:elliptic/ecdh.dart';

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
    );
  }

  void onServerHello(ServerHello sh) {
  print("🔧 QUICSession.onServerHello(): Received ServerHello");

  // TODO: derive handshake keys here
  if (handshakeRead == null) {
    print("❌ No Handshake read keys installed");
  } else {
    print("✅ Handshake keys installed, ready for Handshake packets");
  }
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
  print('Session ${HEX.encode(dcid)} received ${plaintext.length} bytes of plaintext.');

  // -----------------------------
  // 1. Parse QUIC payload (frames)
  // -----------------------------
  final (frames, _, :largest, :firstRange, :delay, :type) =
      parsePayload(plaintext, this) as (
        List<QuicFrame>,
        Object?,
        {int? largest, int? firstRange, int? delay, String? type}
      );

  for (final frame in frames) {
    if (frame is CryptoFrame) {
      print("📦 Received CRYPTO frame: offset=${frame.offset}, len=${frame.data.length}");

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
          _onServerHello(msg);
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
          _onServerFinished(msg);
        }
      }
    }
  }
}
}
