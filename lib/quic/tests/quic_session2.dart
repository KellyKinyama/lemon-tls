// quic_session.dart// qudart:typed_data';

import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:hex/hex.dart';

import '../hkdf.dart';
import '../hash.dart';
import '../crypto.dart';

import '../packet/payload_parser.dart';
import '../frames/quic_frames.dart';

import '../handshake/client_hello.dart';
import '../handshake/server_hello.dart';
import '../handshake/encrypted_extensions.dart';
import '../handshake/certificate.dart';
import '../handshake/certificate_verify.dart';
import '../handshake/finished.dart';

import '../cipher/x25519.dart';

// quic_session.dart// qudart:typed_data';

import 'package:collection/collection.dart';
import 'package:hex/hex.dart';

/// ================================================================
/// Encryption Levels
/// ================================================================
enum QuicEncryptionLevel { initial, handshake, application }

/// ================================================================
/// QUIC Key Container
/// ================================================================
class QuicKeys {
  final Uint8List key;
  final Uint8List iv;
  final Uint8List hp;

  const QuicKeys({required this.key, required this.iv, required this.hp});
}

/// ================================================================
/// QUIC Session (Authoritative Crypto + State Machine)
/// ================================================================
class QuicSession {
  final Uint8List dcid;

  QuicEncryptionLevel encryptionLevel = QuicEncryptionLevel.initial;

  // Packet numbers per level
  final Map<QuicEncryptionLevel, int> _nextPn = {
    QuicEncryptionLevel.initial: 0,
    QuicEncryptionLevel.handshake: 0,
    QuicEncryptionLevel.application: 0,
  };

  // Keys
  QuicKeys? initialRead, initialWrite;
  QuicKeys? handshakeRead, handshakeWrite;
  QuicKeys? appRead, appWrite;

  // TLS handshake state
  ClientHello? clientHello;
  Uint8List? clientHelloRaw;

  final List<Uint8List> _handshakeMessages = [];

  Uint8List? handshakeSecret;
  Uint8List? handshakeHash;

  // X25519
  late final X25519KeyPair x25519;

  /// ------------------------------------------------------------
  /// Constructor (Client)
  /// ------------------------------------------------------------
  QuicSession.client({required this.dcid}) {
    x25519 = X25519KeyPair.generate();
  }

  /// ------------------------------------------------------------
  /// Packet number management
  /// ------------------------------------------------------------
  int nextPacketNumber() {
    final pn = _nextPn[encryptionLevel]!;
    _nextPn[encryptionLevel] = pn + 1;
    return pn;
  }

  /// ------------------------------------------------------------
  /// Build CRYPTO payload for Initial (ClientHello)
  /// ------------------------------------------------------------
  Uint8List buildInitialCryptoPayload() {
    final ch = buildInitialClientHello("localhost");
    final raw = ch.build_tls_client_hello2();

    clientHello = ch;
    clientHelloRaw = raw;
    _handshakeMessages.add(raw);

    // CRYPTO frame: type=0x06, offset=0, len, data
    return Uint8List.fromList([0x06, 0x00, raw.length, ...raw]);
  }

  /// ------------------------------------------------------------
  /// Receive decrypted QUIC payload (frames)
  /// ------------------------------------------------------------
  void onDecryptedPayload(Uint8List plaintext) {
    final parsed = parsePayload(plaintext, this);

    for (final frame in parsed.frames) {
      if (frame is CryptoFrame) {
        _handleCryptoFrame(frame.data);
      }
    }
  }

  /// ------------------------------------------------------------
  /// TLS CRYPTO frame handler
  /// ------------------------------------------------------------
  void _handleCryptoFrame(Uint8List cryptoData) {
    final messages = parseTlsMessages(cryptoData);

    for (final msg in messages) {
      _handshakeMessages.add(msg.rawBytes!);

      if (msg is ServerHello) {
        _onServerHello(msg);
      } else if (msg is EncryptedExtensions) {
        // no action
      } else if (msg is CertificateMessage) {
        // no action
      } else if (msg is CertificateVerify) {
        // no action
      } else if (msg is FinishedMessage) {
        _onFinished(msg);
      }
    }
  }

  /// ------------------------------------------------------------
  /// ServerHello → derive handshake secrets + keys
  /// ------------------------------------------------------------
  void _onServerHello(ServerHello sh) {
    final sharedSecret = x25519SharedSecret(
      privateKey: x25519.privateKey,
      publicKey: sh.keyShareEntry!.pub,
    );

    final transcriptHash = createHash(
      Uint8List.fromList(_handshakeMessages.expand((b) => b).toList()),
    );

    // TLS 1.3 key schedule
    final zero = Uint8List(32);
    final earlySecret = hkdfExtract(zero, salt: zero);
    final emptyHash = createHash(Uint8List(0));

    final derivedSecret = hkdfExpandLabel(
      secret: earlySecret,
      label: "derived",
      context: emptyHash,
      length: 32,
    );

    handshakeSecret = hkdfExtract(sharedSecret, salt: derivedSecret);
    handshakeHash = transcriptHash;

    final clientHsTraffic = hkdfExpandLabel(
      secret: handshakeSecret!,
      label: "c hs traffic",
      context: transcriptHash,
      length: 32,
    );

    final serverHsTraffic = hkdfExpandLabel(
      secret: handshakeSecret!,
      label: "s hs traffic",
      context: transcriptHash,
      length: 32,
    );

    handshakeWrite = _deriveQuicKeys(clientHsTraffic);
    handshakeRead = _deriveQuicKeys(serverHsTraffic);

    encryptionLevel = QuicEncryptionLevel.handshake;

    print("🔐 Handshake keys installed");
  }

  /// ------------------------------------------------------------
  /// Finished → verify + install 1‑RTT keys
  /// ------------------------------------------------------------
  void _onFinished(FinishedMessage fin) {
    final finishedKey = hkdfExpandLabel(
      secret: handshakeSecret!,
      label: "finished",
      context: Uint8List(0),
      length: 32,
    );

    final expected = hmacSha256(key: finishedKey, data: handshakeHash!);

    if (!const ListEquality<int>().equals(expected, fin.verifyData)) {
      throw StateError("❌ TLS Finished verification failed");
    }

    _installApplicationKeys();

    encryptionLevel = QuicEncryptionLevel.application;
    print("✅ Handshake complete → 1‑RTT active");
  }

  /// ------------------------------------------------------------
  /// Application traffic keys (derived once)
  /// ------------------------------------------------------------
  void _installApplicationKeys() {
    final emptyHash = createHash(Uint8List(0));

    final derivedSecret = hkdfExpandLabel(
      secret: handshakeSecret!,
      label: "derived",
      context: emptyHash,
      length: 32,
    );

    final masterSecret = hkdfExtract(Uint8List(32), salt: derivedSecret);

    final clientApp = hkdfExpandLabel(
      secret: masterSecret,
      label: "c ap traffic",
      context: handshakeHash!,
      length: 32,
    );

    final serverApp = hkdfExpandLabel(
      secret: masterSecret,
      label: "s ap traffic",
      context: handshakeHash!,
      length: 32,
    );

    appWrite = _deriveQuicKeys(clientApp);
    appRead = _deriveQuicKeys(serverApp);
  }

  /// ------------------------------------------------------------
  /// QUIC key derivation helper
  /// ------------------------------------------------------------
  QuicKeys _deriveQuicKeys(Uint8List trafficSecret) {
    final key = hkdfExpandLabel(
      secret: trafficSecret,
      label: "quic key",
      context: Uint8List(0),
      length: 16,
    );

    final iv = hkdfExpandLabel(
      secret: trafficSecret,
      label: "quic iv",
      context: Uint8List(0),
      length: 12,
    );

    final hp = hkdfExpandLabel(
      secret: trafficSecret,
      label: "quic hp",
      context: Uint8List(0),
      length: 16,
    );

    return QuicKeys(key: key, iv: iv, hp: hp);
  }
}
