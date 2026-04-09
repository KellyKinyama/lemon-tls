// ============================================================
//  QUIC CRYPTO – Consolidated Module
//  Implements:
//    - HKDF (using your hkdf.dart)
//    - QUIC Expand Label
//    - Initial Secrets (multi-version)
//    - Handshake & 1-RTT Key Derivation
//    - Nonce = IV XOR PacketNumber
//    - AES-GCM AEAD (PointyCastle)
//    - Header Protection (AES-ECB mask generation)
//    - Header Protection Removal (decrypt)
//    - Packet Number Expansion
// ============================================================

import 'dart:math' as math;
import 'dart:typed_data';
import 'package:lemon_tls/tls13/crypto.dart';
import 'package:pointycastle/export.dart';
import 'package:x25519/x25519.dart';

import 'hkdf.dart';

//
// ============================================================
// Helper
// ============================================================
Uint8List _concat(List<Uint8List> xs) {
  final total = xs.fold(0, (n, b) => n + b.length);
  final out = Uint8List(total);
  int offset = 0;

  for (final x in xs) {
    out.setRange(offset, offset + x.length, x);
    offset += x.length;
  }
  return out;
}

//
// ============================================================
// QUIC HKDF-Expand-Label (RFC 9001: uses "quic " prefix)
// ============================================================
Uint8List quicHkdfExpandLabel({
  required Uint8List secret,
  required String label,
  required Uint8List context,
  required int length,
}) {
  final fullLabel = Uint8List.fromList("quic $label".codeUnits);
  final info = BytesBuilder()
    ..addByte(length >> 8)
    ..addByte(length & 0xff)
    ..addByte(fullLabel.length)
    ..add(fullLabel)
    ..addByte(context.length)
    ..add(context);

  return hkdfExpand(prk: secret, info: info.toBytes(), outputLength: length);
}

//
// ============================================================
// QUIC Nonce = IV XOR PacketNumber (RFC 9001 §5.3)
// ============================================================
Uint8List quicNonce(Uint8List iv, int packetNumber) {
  final nonce = Uint8List.fromList(iv);
  var pn = packetNumber;

  for (int i = iv.length - 1; i >= 0; i--) {
    nonce[i] ^= (pn & 0xff);
    pn >>= 8;
  }
  return nonce;
}

//
// ============================================================
// AES-GCM AEAD (encrypt / decrypt)
// ============================================================
Uint8List? quicAeadEncrypt({
  required Uint8List key,
  required Uint8List iv,
  required int packetNumber,
  required Uint8List plaintext,
  required Uint8List aad,
}) {
  try {
    final nonce = quicNonce(iv, packetNumber);

    final cipher = GCMBlockCipher(AESFastEngine());
    cipher.init(true, AEADParameters(KeyParameter(key), 128, nonce, aad));

    final out = cipher.process(plaintext);
    return Uint8List.fromList(out);
  } catch (_) {
    return null;
  }
}

Uint8List? quicAeadDecrypt({
  required Uint8List key,
  required Uint8List iv,
  required int packetNumber,
  required Uint8List ciphertextWithTag,
  required Uint8List aad,
}) {
  try {
    final nonce = quicNonce(iv, packetNumber);

    final ciphertext = ciphertextWithTag.sublist(
      0,
      ciphertextWithTag.length - 16,
    );

    final tag = ciphertextWithTag.sublist(ciphertextWithTag.length - 16);

    final cipher = GCMBlockCipher(AESFastEngine());
    cipher.init(false, AEADParameters(KeyParameter(key), 128, nonce, aad));

    final out = cipher.process(ciphertext);
    cipher.process(tag); // authentication check

    return Uint8List.fromList(out);
  } catch (_) {
    return null;
  }
}

//
// ============================================================
// Header Protection (AES-ECB mask)
// ============================================================
Uint8List _aesEcbEncrypt(Uint8List key, Uint8List block16) {
  final cipher = ECBBlockCipher(AESFastEngine());
  cipher.init(true, KeyParameter(key));

  final out = Uint8List(block16.length);
  cipher.processBlock(block16, 0, out, 0);
  return out;
}

Uint8List applyHeaderProtection({
  required Uint8List packet,
  required int pnOffset,
  required Uint8List hpKey,
  required int pnLen,
}) {
  final sample = packet.sublist(pnOffset + 4, pnOffset + 20);
  final mask = _aesEcbEncrypt(hpKey, sample).sublist(0, 5);

  final first = packet[0];
  final isLong = (first & 0x80) != 0;

  if (isLong) {
    packet[0] ^= (mask[0] & 0x0f);
  } else {
    packet[0] ^= (mask[0] & 0x1f);
  }

  for (int i = 0; i < pnLen; i++) {
    packet[pnOffset + i] ^= mask[1 + i];
  }
  return packet;
}

int removeHeaderProtection({
  required Uint8List packet,
  required int pnOffset,
  required Uint8List hpKey,
  required bool isShort,
}) {
  final sample = packet.sublist(pnOffset + 4, pnOffset + 20);
  final mask = _aesEcbEncrypt(hpKey, sample).sublist(0, 5);

  if (isShort) {
    packet[0] ^= (mask[0] & 0x1f);
  } else {
    packet[0] ^= (mask[0] & 0x0f);
  }

  final pnLen = (packet[0] & 0x03) + 1;

  for (int i = 0; i < pnLen; i++) {
    packet[pnOffset + i] ^= mask[1 + i];
  }

  return pnLen;
}

//
// ============================================================
// Packet Number Decoding & Expansion
// ============================================================
int decodePn(Uint8List bytes, int offset, int pnLen) {
  var n = 0;
  for (int i = 0; i < pnLen; i++) {
    n = (n << 8) | bytes[offset + i];
  }
  return n;
}

int expandPn(int truncated, int pnLen, int largestSeen) {
  final pnWin = 1 << (pnLen * 8);
  final pnHalf = pnWin >> 1;
  final expected = largestSeen + 1;

  return truncated + pnWin * ((expected - truncated + pnHalf) ~/ pnWin);
}

//
// ============================================================
// Initial Keys – Multi Version (RFC 9001)
// ============================================================
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

class QuicInitialKeys {
  final Uint8List key;
  final Uint8List iv;
  final Uint8List hp;

  QuicInitialKeys(this.key, this.iv, this.hp);
}

QuicInitialKeys quicDeriveInitialSecrets({
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

  return QuicInitialKeys(
    quicHkdfExpandLabel(
      secret: secret2,
      label: "quic key",
      context: Uint8List(0),
      length: 16,
    ),
    quicHkdfExpandLabel(
      secret: secret2,
      label: "quic iv",
      context: Uint8List(0),
      length: 12,
    ),
    quicHkdfExpandLabel(
      secret: secret2,
      label: "quic hp",
      context: Uint8List(0),
      length: 16,
    ),
  );
}

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
