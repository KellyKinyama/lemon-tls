// lib/quic_initial_secrets.dart
import 'dart:typed_data';
import 'package:lemon_tls/tls13/crypto.dart';

import 'crypto.dart';
// import 'hkdf.dart';
// import 'quic_aead.dart';

class QuicInitialKeySet {
  final Uint8List key;
  final Uint8List iv;
  final Uint8List hp;

  QuicInitialKeySet(this.key, this.iv, this.hp);
}

final Map<int, Uint8List> quicInitialSalts = {
  0x00000001: Uint8List.fromList([
    0x38,
    0x76,
    0x2c,
    0xf7,
    0xf5,
    0x59,
    0x34,
    0xb3,
    0x4d,
    0x17,
    0x9a,
    0xe6,
    0xa4,
    0xc8,
    0x0c,
    0xad,
    0xcc,
    0xbb,
    0x7f,
    0x0a,
  ]),
  0xff00001d: Uint8List.fromList([
    0xaf,
    0xbf,
    0xec,
    0x28,
    0x99,
    0x93,
    0xd2,
    0x4c,
    0x9e,
    0x97,
    0x86,
    0xf1,
    0x9c,
    0x61,
    0x11,
    0xe0,
    0x43,
    0x90,
    0xa8,
    0x99,
  ]),
  0xff000020: Uint8List.fromList([
    0x7f,
    0xbc,
    0xdb,
    0x0e,
    0x7c,
    0x66,
    0xbb,
    0x77,
    0x7b,
    0xe3,
    0x0e,
    0xbd,
    0x5f,
    0xa5,
    0x15,
    0x87,
    0x3d,
    0x8d,
    0x6e,
    0x67,
  ]),
  0x51303530: Uint8List.fromList([
    0x69,
    0x45,
    0x6f,
    0xbe,
    0xf1,
    0x6e,
    0xd7,
    0xdc,
    0x48,
    0x15,
    0x9d,
    0x98,
    0xd0,
    0x7f,
    0x5c,
    0x3c,
    0x3d,
    0x5a,
    0xa7,
    0x0a,
  ]),
};

QuicInitialKeySet quicDeriveInitialSecrets({
  required Uint8List dcid,
  required int version,
  required bool forRead,
}) {
  final salt = quicInitialSalts[version];
  if (salt == null) {
    throw "Unsupported QUIC version: 0x${version.toRadixString(16)}";
  }

  final label = forRead ? "client in" : "server in";

  final initSecret = hkdfExtractSha256(ikm: dcid, salt: salt);

  final secret2 = quicHkdfExpandLabel(
    secret: initSecret,
    label: label,
    context: Uint8List(0),
    length: 32,
  );

  final key = quicHkdfExpandLabel(
    secret: secret2,
    label: "quic key",
    context: Uint8List(0),
    length: 16,
  );

  final iv = quicHkdfExpandLabel(
    secret: secret2,
    label: "quic iv",
    context: Uint8List(0),
    length: 12,
  );

  final hp = quicHkdfExpandLabel(
    secret: secret2,
    label: "quic hp",
    context: Uint8List(0),
    length: 16,
  );

  return QuicInitialKeySet(key, iv, hp);
}
