// lib/quic_hp.dart
import 'dart:typed_data';
import 'package:pointycastle/export.dart';

Uint8List _aesEcbEncrypt(Uint8List key, Uint8List sample) {
  final cipher = ECBBlockCipher(AESFastEngine());
  cipher.init(true, KeyParameter(key));

  final out = Uint8List(sample.length);
  for (int i = 0; i < sample.length; i += 16) {
    cipher.processBlock(sample, i, out, i);
  }
  return out;
}

/// Remove QUIC header protection and return PN length.
int quicRemoveHeaderProtection({
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

/// Expand truncated PN into full packet number
int quicExpandPN(int truncated, int pnLen, int largestReceived) {
  final pnWin = 1 << (pnLen * 8);
  final pnHalf = pnWin >> 1;
  final expected = largestReceived + 1;

  return truncated + pnWin * ((expected - truncated + pnHalf) ~/ pnWin);
}

int quicDecodePN(Uint8List bytes, int offset, int pnLen) {
  var out = 0;
  for (int i = 0; i < pnLen; i++) {
    out = (out << 8) | bytes[offset + i];
  }
  return out;
}
