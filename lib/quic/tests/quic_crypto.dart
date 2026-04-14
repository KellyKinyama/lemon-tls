// quic_crypto.dart
import 'dart:typed_data';

import 'package:hex/hex.dart';

import 'aead.dart';
import 'initialial_aead.dart';
import 'quic_session.dart';
import 'packet/quic_packet.dart';

/// ================================================================
/// QUIC Crypto Dispatcher
/// ================================================================
///
/// Responsibilities:
///   - Select correct keys for encryption level
///   - Build Additional Authenticated Data (AAD)
///   - Apply AEAD
///   - Apply/remove header protection
///
/// This file does NOT:
///   - Derive keys
///   - Handle TLS
///   - Parse frames
///

/// ------------------------------------------------------------
/// Encrypt a QUIC packet
/// ------------------------------------------------------------
Uint8List? encryptQuicPacket({
  required QuicEncryptionLevel level,
  required Uint8List plaintext,
  required QuicSession session,
  required int packetNumber,
}) {
  late QuicKeys keys;
  late int headerFlags;

  switch (level) {
    case QuicEncryptionLevel.initial:
      keys = session.initialWrite!;
      headerFlags = 0xC3; // Initial, PN length = 1
      break;
    case QuicEncryptionLevel.handshake:
      keys = session.handshakeWrite!;
      headerFlags = 0xE3; // Handshake, PN length = 1
      break;
    case QuicEncryptionLevel.application:
      keys = session.appWrite!;
      headerFlags = 0x43; // Short header, PN length = 1
      break;
  }

  // ------------------------------------------------------------
  // Build unprotected header
  // ------------------------------------------------------------
  final header = buildUnprotectedHeader(
    flags: headerFlags,
    dcid: session.dcid,
    packetNumber: packetNumber,
    isLongHeader: level != QuicEncryptionLevel.application,
  );

  // ------------------------------------------------------------
  // Encrypt payload
  // ------------------------------------------------------------
  final cipherText = aeadEncrypt(
    key: keys.key,
    iv: keys.iv,
    packetNumber: packetNumber,
    plaintext: plaintext,
    aad: header,
  );

  if (cipherText == null) return null;

  // ------------------------------------------------------------
  // Apply header protection
  // ------------------------------------------------------------
  final fullPacket = Uint8List.fromList([...header, ...cipherText]);

  applyHeaderProtection(
    packet: fullPacket,
    pnOffset: header.length - 1,
    hpKey: keys.hp,
    isLongHeader: level != QuicEncryptionLevel.application,
  );

  return fullPacket;
}

/// ------------------------------------------------------------
/// Decrypt a QUIC packet
/// ------------------------------------------------------------
DecryptedPacket? decryptQuicPacket(
  Uint8List packet,
  QuicSession session,
  int largestReceivedPn,
) {
  final firstByte = packet[0];
  final isLongHeader = (firstByte & 0x80) != 0;

  late QuicKeys keys;
  late QuicEncryptionLevel level;

  if (isLongHeader) {
    final packetType = (firstByte >> 4) & 0x03;
    if (packetType == 0x00) {
      keys = session.initialRead!;
      level = QuicEncryptionLevel.initial;
    } else {
      keys = session.handshakeRead!;
      level = QuicEncryptionLevel.handshake;
    }
  } else {
    keys = session.appRead!;
    level = QuicEncryptionLevel.application;
  }

  // ------------------------------------------------------------
  // Remove header protection
  // ------------------------------------------------------------
  final headerInfo = removeHeaderProtection(
    packet: packet,
    hpKey: keys.hp,
    isLongHeader: isLongHeader,
  );

  if (headerInfo == null) return null;

  final pn = headerInfo.packetNumber;
  final headerLength = headerInfo.headerLength;

  final aad = packet.sublist(0, headerLength);
  final ciphertext = packet.sublist(headerLength);

  // ------------------------------------------------------------
  // Decrypt payload
  // ------------------------------------------------------------
  final plaintext = aeadDecrypt(
    key: keys.key,
    iv: keys.iv,
    packetNumber: pn,
    ciphertextWithTag: ciphertext,
    aad: aad,
  );

  if (plaintext == null) return null;

  return DecryptedPacket(
    plaintext: plaintext,
    packetNumber: pn,
    encryptionLevel: level,
  );
}

/// ================================================================
/// Header Utilities
/// ================================================================

Uint8List buildUnprotectedHeader({
  required int flags,
  required Uint8List dcid,
  required int packetNumber,
  required bool isLongHeader,
}) {
  if (isLongHeader) {
    return Uint8List.fromList([
      flags,
      0x00,
      0x00,
      0x00,
      0x01, // QUIC v1
      dcid.length,
      ...dcid,
      0x00, // SCID length (client ignores)
      0x00, // token length
      packetNumber,
    ]);
  } else {
    return Uint8List.fromList([
      flags,
      ...dcid,
      packetNumber,
    ]);
  }
}

/// ================================================================
/// Header Protection
/// ================================================================

void applyHeaderProtection({
  required Uint8List packet,
  required int pnOffset,
  required Uint8List hpKey,
  required bool isLongHeader,
}) {
  final sample = packet.sublist(pnOffset + 4, pnOffset + 20);

  final mask = headerProtectionMask(hpKey, sample);

  if (isLongHeader) {
    packet[0] ^= mask[0] & 0x0F;
  } else {
    packet[0] ^= mask[0] & 0x1F;
  }

  packet[pnOffset] ^= mask[1];
}

HeaderInfo? removeHeaderProtection({
  required Uint8List packet,
  required Uint8List hpKey,
  required bool isLongHeader,
}) {
  final pnOffset = inferPnOffset(packet, isLongHeader);
  if (pnOffset < 0) return null;

  final sample = packet.sublist(pnOffset + 4, pnOffset + 20);
  final mask = headerProtectionMask(hpKey, sample);

  if (isLongHeader) {
    packet[0] ^= mask[0] & 0x0F;
  } else {
    packet[0] ^= mask[0] & 0x1F;
  }

  final pn = packet[pnOffset] ^ mask[1];

  return HeaderInfo(
    packetNumber: pn,
    headerLength: pnOffset + 1,
  );
}

/// ================================================================
/// Data Models
/// ================================================================

class DecryptedPacket {
  final Uint8List plaintext;
  final int packetNumber;
  final QuicEncryptionLevel encryptionLevel;

  DecryptedPacket({
    required this.plaintext,
    required this.packetNumber,
    required this.encryptionLevel,
  });
}

class HeaderInfo {
  final int packetNumber;
  final int headerLength;

  HeaderInfo({
    required this.packetNumber,
    required this.headerLength,
  });
}