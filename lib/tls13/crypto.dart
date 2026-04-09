import 'dart:math' as math;
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:pointycastle/export.dart'
    show
        HKDFKeyDerivator,
        HMac,
        SHA256Digest,
        KeyParameter,
        Pbkdf2Parameters,
        X25519PrivateKeyParameters,
        X25519PublicKeyParameters;
import 'package:x25519/x25519.dart';

import 'hkdf.dart';

/// XORs the per-record counter into the IV (TLS 1.3 nonce construction).
Uint8List xorIv(Uint8List iv, int num) {
  if (iv.length != 12) {
    // In TLS 1.3 AES-GCM the IV is 12 bytes.
    // Keep this check strict to match your current usage.
    throw ArgumentError('Expected 12-byte IV, got ${iv.length}.');
  }

  final formatted = Uint8List(12);
  // (b"\x00" * 4) + struct.pack(">q", num)
  // => 4 zero bytes + 8-byte big-endian counter.
  final bd = ByteData.sublistView(formatted);
  bd.setUint32(0, 0, Endian.big);
  bd.setUint64(4, num, Endian.big);

  final out = Uint8List(iv.length);
  for (var i = 0; i < iv.length; i++) {
    out[i] = iv[i] ^ formatted[i];
  }
  return out;
}

/// Builds the TLS 1.3 HKDF label and performs HKDF-Expand.
///
/// Equivalent to Python HKDF_Expand_Label using SHA-256 by default.
// Uint8List hkdfExpandLabel({
//   required Uint8List key,
//   required String label,
//   required Uint8List context,
//   required int length,
// }) {
//   final fullLabel = Uint8List.fromList([
//     ...'tls13 '.codeUnits,
//     ...label.codeUnits,
//   ]);

//   Uint8List u16be(int v) {
//     final out = Uint8List(2);
//     ByteData.sublistView(out).setUint16(0, v & 0xFFFF, Endian.big);
//     return out;
//   }

//   final info = Uint8List.fromList([
//     ...u16be(length),
//     fullLabel.length & 0xFF,
//     ...fullLabel,
//     context.length & 0xFF,
//     ...context,
//   ]);

//   // HKDF-Expand(PRK, info, length) with SHA-256
//   final hkdf = HKDFKeyDerivator(HMac(SHA256Digest(), 64))
//     ..init(
//       Pbkdf2Parameters(Uint8List(0), 0, length),
//     ); // parameters object used for output length

//   // PointyCastle HKDFKeyDerivator uses KeyParameter(PRK) as input key and takes `info` as "iv".
//   // There is some API variance by version; this pattern is common:
//   hkdf.init(Pbkdf2Parameters(info, 0, length));
//   final okm = Uint8List(length);
//   hkdf.deriveKey(key, 0, okm, 0);
//   return okm;
// }

/// HKDF-Extract(salt, ikm) => PRK (SHA-256), implemented from RFC 5869.
Uint8List hkdfExtractSha256({required Uint8List salt, required Uint8List ikm}) {
  final h = crypto.Hmac(crypto.sha256, salt);
  return Uint8List.fromList(h.convert(ikm).bytes);
}

Uint8List sha256(Uint8List data) =>
    Uint8List.fromList(crypto.sha256.convert(data).bytes);

class ApplicationKeys {
  final Uint8List clientKey;
  final Uint8List clientIv;
  final Uint8List serverKey;
  final Uint8List serverIv;
  final Uint8List masterSecret;

  ApplicationKeys({
    required this.clientKey,
    required this.clientIv,
    required this.serverKey,
    required this.serverIv,
    required this.masterSecret,
  });

  Uint8List resumptionMasterSecret(Uint8List someHash) {
    return hkdfExpandLabel(
      secret: masterSecret,
      label: 'res master',
      context: someHash,
      length: 32,
    );
  }

  @override
  String toString() {
    String hx(Uint8List b) =>
        b.map((e) => e.toRadixString(16).padLeft(2, '0')).join();
    return 'ApplicationKeys('
        'clientKey=${hx(clientKey)},'
        'clientIv=${hx(clientIv)},'
        'serverKey=${hx(serverKey)},'
        'serverIv=${hx(serverIv)},'
        'masterSecret=${hx(masterSecret)}'
        ')';
  }
}

class HandshakeKeys {
  final Uint8List clientKey;
  final Uint8List clientIv;
  final Uint8List clientHandshakeTrafficSecret;
  final Uint8List serverKey;
  final Uint8List serverIv;
  final Uint8List serverHandshakeTrafficSecret;
  final Uint8List handshakeSecret;

  HandshakeKeys({
    required this.clientKey,
    required this.clientIv,
    required this.clientHandshakeTrafficSecret,
    required this.serverKey,
    required this.serverIv,
    required this.serverHandshakeTrafficSecret,
    required this.handshakeSecret,
  });
}

class EarlyKeys {
  final Uint8List binderKey;
  final Uint8List earlySecret;
  final Uint8List clientEarlyTrafficSecret;

  EarlyKeys({
    required this.binderKey,
    required this.earlySecret,
    required this.clientEarlyTrafficSecret,
  });

  Uint8List get clientEarlyKey => hkdfExpandLabel(
    secret: clientEarlyTrafficSecret,
    label: 'key',
    context: Uint8List(0),
    length: 16,
  );

  Uint8List get clientEarlyIv => hkdfExpandLabel(
    secret: clientEarlyTrafficSecret,
    label: 'iv',
    context: Uint8List(0),
    length: 12,
  );
}

class KeyPair {
  final Uint8List _privateKey;

  KeyPair._(this._privateKey);

  /// Raw 32-byte X25519 public key.
  /// Raw 32-byte X25519 public key.
  Uint8List get publicKeyBytes {
    // Public key = X25519(privateKey, basePoint)
    final pub = X25519(_privateKey, basePoint);
    return Uint8List.fromList(pub);
  }

  /// Raw 32-byte X25519 private key.
  Uint8List get privateKeyBytes => Uint8List.fromList(_privateKey);

  /// X25519 DH: shared = X25519(private, peerPublic)
  Uint8List exchange(Uint8List peerPubKeyBytes) {
    final shared = X25519(_privateKey, peerPubKeyBytes);
    return Uint8List.fromList(shared);
  }

  EarlyKeys deriveEarlyKeys(Uint8List psk, Uint8List clientHelloHash) {
    // Python uses HKDF(...)._extract(psk) with salt=b"\x00", info=b"\x00"
    // For HKDF-Extract, "info" is not used; treat salt as 0x00.
    final earlySecret = hkdfExtractSha256(
      salt: Uint8List.fromList([0x00]),
      ikm: psk,
    );

    final emptyHash = sha256(Uint8List(0));

    final binderKey = hkdfExpandLabel(
      secret: earlySecret,
      label: 'res binder',
      context: emptyHash,
      length: 32,
    );

    final clientEarlyTrafficSecret = hkdfExpandLabel(
      secret: earlySecret,
      label: 'c e traffic',
      context: clientHelloHash,
      length: 32,
    );

    return EarlyKeys(
      binderKey: binderKey,
      earlySecret: earlySecret,
      clientEarlyTrafficSecret: clientEarlyTrafficSecret,
    );
  }

  HandshakeKeys derive(Uint8List sharedSecret, Uint8List helloHash) {
    // early_secret = HKDF-Extract(salt=0x00, IKM=00..00(32))
    final earlySecret = hkdfExtractSha256(
      salt: Uint8List.fromList([0x00]),
      ikm: Uint8List(32),
    );

    final emptyHash = sha256(Uint8List(0));

    final derivedSecret = hkdfExpandLabel(
      secret: earlySecret,
      label: 'derived',
      context: emptyHash,
      length: 32,
    );

    // handshake_secret = HKDF-Extract(salt=derived_secret, IKM=shared_secret)
    final handshakeSecret = hkdfExtractSha256(
      salt: derivedSecret,
      ikm: sharedSecret,
    );

    final clientHsTrafficSecret = hkdfExpandLabel(
      secret: handshakeSecret,
      label: 'c hs traffic',
      context: helloHash,
      length: 32,
    );
    final serverHsTrafficSecret = hkdfExpandLabel(
      secret: handshakeSecret,
      label: 's hs traffic',
      context: helloHash,
      length: 32,
    );

    final clientKey = hkdfExpandLabel(
      secret: clientHsTrafficSecret,
      label: 'key',
      context: Uint8List(0),
      length: 16,
    );
    final serverKey = hkdfExpandLabel(
      secret: serverHsTrafficSecret,
      label: 'key',
      context: Uint8List(0),
      length: 16,
    );

    final clientIv = hkdfExpandLabel(
      secret: clientHsTrafficSecret,
      label: 'iv',
      context: Uint8List(0),
      length: 12,
    );
    final serverIv = hkdfExpandLabel(
      secret: serverHsTrafficSecret,
      label: 'iv',
      context: Uint8List(0),
      length: 12,
    );

    return HandshakeKeys(
      clientKey: clientKey,
      clientIv: clientIv,
      clientHandshakeTrafficSecret: clientHsTrafficSecret,
      serverKey: serverKey,
      serverIv: serverIv,
      serverHandshakeTrafficSecret: serverHsTrafficSecret,
      handshakeSecret: handshakeSecret,
    );
  }

  ApplicationKeys deriveApplicationKeys(
    Uint8List handshakeSecret,
    Uint8List handshakeHash,
  ) {
    final emptyHash = sha256(Uint8List(0));

    final derivedSecret = hkdfExpandLabel(
      secret: handshakeSecret,
      label: 'derived',
      context: emptyHash,
      length: 32,
    );

    // master_secret = HKDF-Extract(salt=derived_secret, IKM=00..00(32))
    final masterSecret = hkdfExtractSha256(
      salt: derivedSecret,
      ikm: Uint8List(32),
    );

    final clientApTrafficSecret = hkdfExpandLabel(
      secret: masterSecret,
      label: 'c ap traffic',
      context: handshakeHash,
      length: 32,
    );
    final serverApTrafficSecret = hkdfExpandLabel(
      secret: masterSecret,
      label: 's ap traffic',
      context: handshakeHash,
      length: 32,
    );

    final clientKey = hkdfExpandLabel(
      secret: clientApTrafficSecret,
      label: 'key',
      context: Uint8List(0),
      length: 16,
    );
    final serverKey = hkdfExpandLabel(
      secret: serverApTrafficSecret,
      label: 'key',
      context: Uint8List(0),
      length: 16,
    );

    final clientIv = hkdfExpandLabel(
      secret: clientApTrafficSecret,
      label: 'iv',
      context: Uint8List(0),
      length: 12,
    );
    final serverIv = hkdfExpandLabel(
      secret: serverApTrafficSecret,
      label: 'iv',
      context: Uint8List(0),
      length: 12,
    );

    return ApplicationKeys(
      clientKey: clientKey,
      clientIv: clientIv,
      serverKey: serverKey,
      serverIv: serverIv,
      masterSecret: masterSecret,
    );
  }

  static KeyPair generate() {
    final seed = Uint8List(32);
    final rnd = math.Random.secure();
    for (var i = 0; i < seed.length; i++) {
      seed[i] = rnd.nextInt(256);
    }
    return KeyPair._(seed);
  }
}
