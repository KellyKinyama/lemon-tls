// quic_crypto.dart
import 'dart:math' as math;
import 'dart:typed_data';

import 'hkdf.dart'; // ✅ your canonical HKDF file
import 'package:x25519/x25519.dart';

//
// ==========================================================
// QUIC CONSTANTS (RFC 9001)
// ==========================================================
//

final Uint8List quicInitialSalt = Uint8List.fromList([
  0xef,
  0x4f,
  0xf2,
  0xf3,
  0x2c,
  0xf1,
  0x95,
  0x0b,
  0xa7,
  0x4b,
  0x90,
  0x63,
  0x4f,
  0x2a,
  0xb2,
  0x6a,
]);

//
// ==========================================================
// QUIC HKDF-EXPAND-LABEL
// ==========================================================
// QUIC uses *different labels* than TLS 1.3:
//   "quic key", "quic iv", "quic hp"
//
// This MUST NOT use TLS 1.3's "tls13 " LABEL.
//
Uint8List quicHkdfExpandLabel({
  required Uint8List secret,
  required String label,
  required Uint8List context,
  required int length,
}) {
  final fullLabel = Uint8List.fromList("quic $label".codeUnits);

  final info = BytesBuilder()
    ..addByte(length >> 8)
    ..addByte(length & 0xFF)
    ..addByte(fullLabel.length)
    ..add(fullLabel)
    ..addByte(context.length)
    ..add(context);

  return hkdfExpand(prk: secret, info: info.toBytes(), outputLength: length);
}

//
// ==========================================================
// BASIC PRIMITIVES
// ==========================================================
//

Uint8List quicNonce(Uint8List iv, int packetNumber) {
  final out = Uint8List(iv.length);
  final pn = Uint8List(iv.length);

  final bd = ByteData.sublistView(pn);
  bd.setUint64(iv.length - 8, packetNumber, Endian.big);

  for (int i = 0; i < iv.length; i++) {
    out[i] = iv[i] ^ pn[i];
  }
  return out;
}

//
// ==========================================================
// QUIC INITIAL KEYS
// ==========================================================
//
class QuicInitialKeys {
  final Uint8List clientKey;
  final Uint8List clientIv;
  final Uint8List clientHpKey;

  final Uint8List serverKey;
  final Uint8List serverIv;
  final Uint8List serverHpKey;

  QuicInitialKeys(Uint8List dcid)
    : clientKey = quicHkdfExpandLabel(
        secret: hkdfExtract(dcid, salt: quicInitialSalt),
        label: "client in",
        context: Uint8List(0),
        length: 32,
      ),
      serverKey = quicHkdfExpandLabel(
        secret: hkdfExtract(dcid, salt: quicInitialSalt),
        label: "server in",
        context: Uint8List(0),
        length: 32,
      ),
      clientIv = quicHkdfExpandLabel(
        secret: quicHkdfExpandLabel(
          secret: hkdfExtract(dcid, salt: quicInitialSalt),
          label: "client in",
          context: Uint8List(0),
          length: 32,
        ),
        label: "iv",
        context: Uint8List(0),
        length: 12,
      ),
      serverIv = quicHkdfExpandLabel(
        secret: quicHkdfExpandLabel(
          secret: hkdfExtract(dcid, salt: quicInitialSalt),
          label: "server in",
          context: Uint8List(0),
          length: 32,
        ),
        label: "iv",
        context: Uint8List(0),
        length: 12,
      ),
      clientHpKey = quicHkdfExpandLabel(
        secret: quicHkdfExpandLabel(
          secret: hkdfExtract(dcid, salt: quicInitialSalt),
          label: "client in",
          context: Uint8List(0),
          length: 32,
        ),
        label: "hp",
        context: Uint8List(0),
        length: 16,
      ),
      serverHpKey = quicHkdfExpandLabel(
        secret: quicHkdfExpandLabel(
          secret: hkdfExtract(dcid, salt: quicInitialSalt),
          label: "server in",
          context: Uint8List(0),
          length: 32,
        ),
        label: "hp",
        context: Uint8List(0),
        length: 16,
      );
}

//
// ==========================================================
// X25519 Keypair for QUIC
// ==========================================================
//
class QuicKeyPair {
  final Uint8List privateKey;

  QuicKeyPair._(this.privateKey);

  Uint8List get publicKey => Uint8List.fromList(X25519(privateKey, basePoint));

  Uint8List exchange(Uint8List peerPublic) =>
      Uint8List.fromList(X25519(privateKey, peerPublic));

  static QuicKeyPair generate() {
    final r = math.Random.secure();
    final priv = Uint8List(32);
    for (int i = 0; i < 32; i++) {
      priv[i] = r.nextInt(256);
    }
    return QuicKeyPair._(priv);
  }
}

//
// ==========================================================
// QUIC HANDSHAKE KEYS
// ==========================================================
//
class QuicTrafficKeys {
  final Uint8List key;
  final Uint8List iv;
  final Uint8List hpKey;

  QuicTrafficKeys({required this.key, required this.iv, required this.hpKey});
}

class QuicHandshakeKeys {
  final QuicTrafficKeys client;
  final QuicTrafficKeys server;

  QuicHandshakeKeys(this.client, this.server);
}

//
// ==========================================================
// QUIC 1‑RTT KEYS
// ==========================================================
//
class Quic1RttKeys {
  final QuicTrafficKeys client;
  final QuicTrafficKeys server;

  Quic1RttKeys(this.client, this.server);
}

//
// ==========================================================
// DERIVING HANDSHAKE / 1‑RTT KEYS WITH YOUR HKDF
// ==========================================================
//
QuicHandshakeKeys deriveQuicHandshakeKeys({
  required Uint8List handshakeSecret,
  required Uint8List transcriptHash,
}) {
  final clientSecret = quicHkdfExpandLabel(
    secret: handshakeSecret,
    label: "c hs traffic",
    context: transcriptHash,
    length: 32,
  );

  final serverSecret = quicHkdfExpandLabel(
    secret: handshakeSecret,
    label: "s hs traffic",
    context: transcriptHash,
    length: 32,
  );

  return QuicHandshakeKeys(
    QuicTrafficKeys(
      key: quicHkdfExpandLabel(
        secret: clientSecret,
        label: "key",
        context: Uint8List(0),
        length: 16,
      ),
      iv: quicHkdfExpandLabel(
        secret: clientSecret,
        label: "iv",
        context: Uint8List(0),
        length: 12,
      ),
      hpKey: quicHkdfExpandLabel(
        secret: clientSecret,
        label: "hp",
        context: Uint8List(0),
        length: 16,
      ),
    ),
    QuicTrafficKeys(
      key: quicHkdfExpandLabel(
        secret: serverSecret,
        label: "key",
        context: Uint8List(0),
        length: 16,
      ),
      iv: quicHkdfExpandLabel(
        secret: serverSecret,
        label: "iv",
        context: Uint8List(0),
        length: 12,
      ),
      hpKey: quicHkdfExpandLabel(
        secret: serverSecret,
        label: "hp",
        context: Uint8List(0),
        length: 16,
      ),
    ),
  );
}

Quic1RttKeys deriveQuic1RttKeys({
  required Uint8List masterSecret,
  required Uint8List transcriptHash,
}) {
  final clientSecret = quicHkdfExpandLabel(
    secret: masterSecret,
    label: "c ap traffic",
    context: transcriptHash,
    length: 32,
  );

  final serverSecret = quicHkdfExpandLabel(
    secret: masterSecret,
    label: "s ap traffic",
    context: transcriptHash,
    length: 32,
  );

  return Quic1RttKeys(
    QuicTrafficKeys(
      key: quicHkdfExpandLabel(
        secret: clientSecret,
        label: "key",
        context: Uint8List(0),
        length: 16,
      ),
      iv: quicHkdfExpandLabel(
        secret: clientSecret,
        label: "iv",
        context: Uint8List(0),
        length: 12,
      ),
      hpKey: quicHkdfExpandLabel(
        secret: clientSecret,
        label: "hp",
        context: Uint8List(0),
        length: 16,
      ),
    ),
    QuicTrafficKeys(
      key: quicHkdfExpandLabel(
        secret: serverSecret,
        label: "key",
        context: Uint8List(0),
        length: 16,
      ),
      iv: quicHkdfExpandLabel(
        secret: serverSecret,
        label: "iv",
        context: Uint8List(0),
        length: 12,
      ),
      hpKey: quicHkdfExpandLabel(
        secret: serverSecret,
        label: "hp",
        context: Uint8List(0),
        length: 16,
      ),
    ),
  );
}
