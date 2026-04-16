import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:hex/hex.dart';

import '../packet/quic_packet.dart';
import '../utils.dart';
import 'test.dart';

void testClientInitialEncryption() {
  // --- Inputs taken from your working decryption tests ---

  final clientInitialKey = Uint8List.fromList(
    HEX.decode("b14b918124fda5c8d79847602fa3520b"),
  );
  final clientInitialIv = Uint8List.fromList(
    HEX.decode("ddbc15dea80925a55686a7df"),
  );
  final clientInitialHp = Uint8List.fromList(
    HEX.decode("6df4e9d737cdf714711d7c617ee82981"),
  );

  final dcid = Uint8List.fromList(
    HEX.decode("0001020304050607"), // server‑chosen CID
  );

  final scid = Uint8List.fromList(
    HEX.decode("635f636964"), // "c_cid"
  );

  final token = Uint8List(0); // empty token

  // This is the plaintext CRYPTO frame (already verified earlier)
  final cryptoFrames = buildCryptoFrame(clientHello);

  // Packet Number = 0 for first Initial
  const packetNumber = 0;

  final encrypted = encryptQuicPacket(
    'initial',
    cryptoFrames,
    clientInitialKey,
    clientInitialIv,
    clientInitialHp,
    packetNumber,
    dcid,
    scid,
    token,
  );

  if (encrypted == null) {
    throw StateError('Client Initial encryption failed');
  }

  print('Encrypted Client Initial: ${HEX.encode(encrypted)}');
  print('Expected Client Initial : ${HEX.encode(udp1ClientHello)}');

  if (!const ListEquality<int>().equals(encrypted, udp1ClientHello)) {
    throw StateError(
      'Client Initial packet mismatch!\n'
      'Expected: ${HEX.encode(udp1ClientHello)}\n'
      'Actual:   ${HEX.encode(encrypted)}',
    );
  }

  print('✅ Client Initial encryption matches reference packet');
}

Uint8List buildCryptoFrame(Uint8List cryptoData) {
  final offset = writeVarInt(0);
  final length = writeVarInt(cryptoData.length);

  return concatUint8Lists([
    Uint8List.fromList([0x06]), // CRYPTO frame type
    offset,
    length,
    cryptoData,
  ]);
}

void main() {
  testClientInitialEncryption();
}
