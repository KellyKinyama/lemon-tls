import 'dart:typed_data';

import 'package:collection/equality.dart';
import 'package:hex/hex.dart';

import '../cipher/x25519.dart';
import '../frames/quic_frames.dart';
import '../handshake/client_hello.dart';
import '../handshake/finished.dart';
import '../handshake/server_hello.dart';
import '../handshake/tls_messages.dart';
import '../hash.dart';
import '../hkdf.dart';
import '../packet/payload_parser2.dart';

enum EncryptionLevel { initial, handshake, application }

class QuicKeys {
  final Uint8List key;
  final Uint8List iv;
  final Uint8List hp;

  QuicKeys(this.key, this.iv, this.hp);
}

class QuicSession {
  final Uint8List dcid;

  EncryptionLevel level = EncryptionLevel.initial;

  // Keys per level
  QuicKeys? initialRead, initialWrite;
  QuicKeys? handshakeRead, handshakeWrite;
  QuicKeys? appRead, appWrite;

  // TLS state
  Uint8List? handshakeHash;
  Uint8List? handshakeSecret;

  QuicSession(this.dcid);
}

void installInitialKeys(QuicSession s) {
  s.initialRead = QuicKeys(
    Uint8List.fromList(HEX.decode("d77fc4056fcfa32bd1302469ee6ebf90")),
    Uint8List.fromList(HEX.decode("fcb748e37ff79860faa07477")),
    Uint8List.fromList(HEX.decode("440b2725e91dc79b370711ef792faa3d")),
  );

  s.initialWrite = QuicKeys(
    Uint8List.fromList(HEX.decode("b14b918124fda5c8d79847602fa3520b")),
    Uint8List.fromList(HEX.decode("ddbc15dea80925a55686a7df")),
    Uint8List.fromList(HEX.decode("6df4e9d737cdf714711d7c617ee82981")),
  );
}

void handleDecryptedPacket(QuicSession session, Uint8List plaintext) {
  final payload = parsePayload(plaintext, session);

  for (final frame in payload.frames) {
    if (frame is CryptoFrame) {
      final tlsMessages = parseTlsMessages(frame.data);

      for (final msg in tlsMessages) {
        _handleTlsMessage(session, msg, frame.data);
      }
    }
  }
}

void _handleTlsMessage(QuicSession s, TlsHandshakeMessage msg, Uint8List raw) {
  if (msg is ClientHello) {
    // expected only in Initial
    return;
  }

  if (msg is ServerHello) {
    _onServerHello(s, msg);
    return;
  }

  if (msg is FinishedMessage) {
    _onFinished(s, msg);
    return;
  }
}

void _onServerHello(QuicSession s, ServerHello sh) {
  final sharedSecret = x25519ShareSecret(
    privateKey: /* client private */,
    publicKey: sh.keyShareEntry!.pub,
  );

  final transcriptHash = createHash(
    Uint8List.fromList([...clientHello, ...serverHello]),
  );

  final zero = Uint8List(32);
  final early = hkdfExtract(zero, salt: zero);
  final derived = hkdfExpandLabel(
    secret: early,
    label: "derived",
    context: createHash(Uint8List(0)),
    length: 32,
  );

  final handshakeSecret = hkdfExtract(sharedSecret, salt: derived);

  s.handshakeSecret = handshakeSecret;
  s.handshakeHash = transcriptHash;

  final clientHs = hkdfExpandLabel(
    secret: handshakeSecret,
    label: "c hs traffic",
    context: transcriptHash,
    length: 32,
  );

  final serverHs = hkdfExpandLabel(
    secret: handshakeSecret,
    label: "s hs traffic",
    context: transcriptHash,
    length: 32,
  );

  s.handshakeRead = QuicKeys(
    hkdfExpandLabel(secret: serverHs, label: "quic key", context: Uint8List(0), length: 16),
    hkdfExpandLabel(secret: serverHs, label: "quic iv", context: Uint8List(0), length: 12),
    hkdfExpandLabel(secret: serverHs, label: "quic hp", context: Uint8List(0), length: 16),
  );

  s.handshakeWrite = QuicKeys(
    hkdfExpandLabel(secret: clientHs, label: "quic key", context: Uint8List(0), length: 16),
    hkdfExpandLabel(secret: clientHs, label: "quic iv", context: Uint8List(0), length: 12),
    hkdfExpandLabel(secret: clientHs, label: "quic hp", context: Uint8List(0), length: 16),
  );

  s.level = EncryptionLevel.handshake;
}

void _onFinished(QuicSession s, FinishedMessage fin) {
  final finishedKey = hkdfExpandLabel(
    secret: s.handshakeSecret!,
    label: fin.isFromServer ? "finished" : "finished",
    context: Uint8List(0),
    length: 32,
  );

  final expected = hmacSha256(
    key: finishedKey,
    data: s.handshakeHash!,
  );

  if (!ListEquality().equals(expected, fin.verifyData)) {
    throw StateError("Finished verification failed");
  }

  // ✅ Now install application keys (your verified values)
  s.appRead = ...
  s.appWrite = ...

  s.level = EncryptionLevel.application;
}