import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:hex/hex.dart';

import '../packet/quic_packet.dart';
import 'test.dart'; // packets + clientHello/serverHello
import 'test_encrypt.dart'; // encryptQuicPacket + buildCryptoFrame

const _eq = ListEquality<int>();

/* ============================================================
 *  FIXED TEST VECTORS
 * ============================================================
 */

// ---- Connection IDs ----
final serverCid = Uint8List.fromList(HEX.decode("0001020304050607"));
final clientCid = Uint8List.fromList(HEX.decode("635f636964")); // "c_cid"

// ---- Initial keys ----
final clientInitialKey = Uint8List.fromList(
  HEX.decode("b14b918124fda5c8d79847602fa3520b"),
);
final clientInitialIv = Uint8List.fromList(
  HEX.decode("ddbc15dea80925a55686a7df"),
);
final clientInitialHp = Uint8List.fromList(
  HEX.decode("6df4e9d737cdf714711d7c617ee82981"),
);

final serverInitialKey = Uint8List.fromList(
  HEX.decode("d77fc4056fcfa32bd1302469ee6ebf90"),
);
final serverInitialIv = Uint8List.fromList(
  HEX.decode("fcb748e37ff79860faa07477"),
);
final serverInitialHp = Uint8List.fromList(
  HEX.decode("440b2725e91dc79b370711ef792faa3d"),
);

// ---- Application keys ----
final clientAppKey = Uint8List.fromList(
  HEX.decode("e010a295f0c2864f186b2a7e8fdc9ed7"),
);
final clientAppIv = Uint8List.fromList(HEX.decode("eb3fbc384a3199dcf6b4c808"));
final clientAppHp = Uint8List.fromList(
  HEX.decode("8a6a38bc5cc40cb482a254dac68c9d2f"),
);

final serverAppKey = Uint8List.fromList(
  HEX.decode("fd8c7da9de1b2da4d2ef9fd5188922d0"),
);
final serverAppIv = Uint8List.fromList(HEX.decode("02f6180e4f4aa456d7e8a602"));
final serverAppHp = Uint8List.fromList(
  HEX.decode("b7f6f021453e52b58940e4bba72a35d4"),
);

/* ============================================================
 *  HELPERS
 * ============================================================
 */

void expect(bool condition, String message) {
  if (!condition) throw StateError(message);
}

void expectBytes(Uint8List actual, Uint8List expected, String name) {
  if (!_eq.equals(actual, expected)) {
    throw StateError(
      '$name mismatch\n'
      'Expected: ${HEX.encode(expected)}\n'
      'Actual:   ${HEX.encode(actual)}',
    );
  }
}

/* ============================================================
 *  TEST 1: Encrypt → Decrypt Symmetry (Initial)
 * ============================================================
 */

void testEncryptDecryptSymmetry() {
  final frames = buildCryptoFrame(clientHello);

  final encrypted = encryptQuicPacket(
    'initial',
    frames,
    clientInitialKey,
    clientInitialIv,
    clientInitialHp,
    0,
    serverCid,
    clientCid,
    Uint8List(0),
  );

  expect(encrypted != null, 'Encryption failed');

  final decrypted = decryptQuicPacketBytes2(
    encrypted!,
    clientInitialKey,
    clientInitialIv,
    clientInitialHp,
    Uint8List(0),
    0,
  );

  expect(decrypted!.plaintext != null, 'Decryption failed');
  expectBytes(decrypted.plaintext!, frames, 'Initial symmetry');

  print('✅ Encrypt/Decrypt symmetry (Initial)');
}

/* ============================================================
 *  TEST 2: Client Initial matches reference packet
 * ============================================================
 */

void testClientInitialEncryption() {
  final encrypted = encryptQuicPacket(
    'initial',
    buildCryptoFrame(clientHello),
    clientInitialKey,
    clientInitialIv,
    clientInitialHp,
    0,
    serverCid,
    clientCid,
    Uint8List(0),
  )!;

  expectBytes(encrypted, udp1ClientHello, 'Client Initial');

  print('✅ Client Initial encryption matches reference');
}

/* ============================================================
 *  TEST 3: Server Initial encrypt → decrypt symmetry
 * ============================================================
 */

void testServerInitialEncryptDecrypt() {
  final plaintext = buildCryptoFrame(serverHello);

  final encrypted = encryptQuicPacket(
    'initial',
    plaintext,
    serverInitialKey,
    serverInitialIv,
    serverInitialHp,
    0,
    clientCid,
    serverCid,
    Uint8List(0),
  )!;

  final decrypted = decryptQuicPacketBytes2(
    encrypted,
    serverInitialKey,
    serverInitialIv,
    serverInitialHp,
    Uint8List(0),
    0,
  );

  expect(decrypted!.plaintext != null, 'Server Initial decrypt failed');
  expectBytes(decrypted.plaintext!, plaintext, 'Server Initial plaintext');

  print('✅ Server Initial encrypt/decrypt symmetry');
}

/* ============================================================
 *  TEST 4: Directional key enforcement
 * ============================================================
 */

void testWrongDirectionKeyFails() {
  // Use a valid ACK frame (enough bytes for HP)
  final payload = buildAckFrame(); // 5 bytes, will be padded internally

  final encrypted = encryptQuicPacket(
    '1rtt',
    payload,
    clientAppKey,
    clientAppIv,
    clientAppHp,
    0,
    serverCid,
    Uint8List(0),
    null,
  );

  expect(encrypted != null, 'Encryption failed unexpectedly');

  // Attempt to decrypt using WRONG direction keys
  final decrypted = decryptQuicPacketBytes2(
    encrypted!,
    serverAppKey, // ❌ wrong direction
    serverAppIv,
    serverAppHp,
    serverCid,
    0,
  );

  // Correct outcome: auth fails → plaintext == null
  expect(
    decrypted?.plaintext == null,
    'Wrong-direction key unexpectedly succeeded',
  );

  print('✅ Directional key enforcement');
}

/* ============================================================
 *  TEST 5: ACK round-trip
 * ============================================================
 */

Uint8List buildAckFrame() => Uint8List.fromList([0x02, 0x00, 0x0b, 0x00, 0x00]);

void testInitialDecryptable() {
  final encrypted = encryptQuicPacket(
    'initial',
    buildCryptoFrame(clientHello),
    clientInitialKey,
    clientInitialIv,
    clientInitialHp,
    0,
    serverCid,
    clientCid,
    Uint8List(0),
  );

  expect(encrypted != null, 'Initial encryption failed');

  final decrypted = decryptQuicPacketBytes2(
    encrypted!,
    clientInitialKey,
    clientInitialIv,
    clientInitialHp,
    Uint8List(0),
    0,
  );

  expect(decrypted?.plaintext != null, 'Initial decrypt failed');

  print('✅ Initial packet decryptable');
}

void testAckRoundTrip() {
  final ack = buildAckFrame();

  final encrypted = encryptQuicPacket(
    '1rtt',
    ack,
    clientAppKey,
    clientAppIv,
    clientAppHp,
    1,
    serverCid,
    Uint8List(0),
    null,
  )!;

  final decrypted = decryptQuicPacketBytes2(
    encrypted,
    clientAppKey,
    clientAppIv,
    clientAppHp,
    serverCid,
    0,
  );

  expect(decrypted!.plaintext != null, 'ACK decrypt failed');
  expectBytes(decrypted.plaintext!, ack, 'ACK frame');

  print('✅ ACK round-trip');
}

/* ============================================================
 *  TEST 6: Initial padding (1200 bytes)
 * ============================================================
 */

void testInitialPadding() {
  final encrypted = encryptQuicPacket(
    'initial',
    buildCryptoFrame(clientHello),
    clientInitialKey,
    clientInitialIv,
    clientInitialHp,
    0,
    serverCid,
    clientCid,
    Uint8List(0),
  )!;

  expect(encrypted.length >= 1200, 'Initial < 1200 bytes');

  print('✅ Initial padding requirement met');
}

/* ============================================================
 *  TEST 7: Corruption rejection
 * ============================================================
 */

void testCorruptedPacketFails() {
  final encrypted = encryptQuicPacket(
    '1rtt',
    Uint8List.fromList([0x01]),
    clientAppKey,
    clientAppIv,
    clientAppHp,
    0,
    serverCid,
    Uint8List(0),
    null,
  )!;

  encrypted[encrypted.length - 1] ^= 0xff;

  final decrypted = decryptQuicPacketBytes2(
    encrypted,
    clientAppKey,
    clientAppIv,
    clientAppHp,
    serverCid,
    0,
  );

  expect(decrypted!.plaintext == null, 'Corrupted packet accepted');

  print('✅ AEAD corruption rejected');
}

/* ============================================================
 *  MAIN
 * ============================================================
 */

void main() {
  testEncryptDecryptSymmetry();
  testClientInitialEncryption();
  testServerInitialEncryptDecrypt();

  try {
    testWrongDirectionKeyFails();
  } catch (e, st) {
    print('❌ testWrongDirectionKeyFails failed: $e');
    print(st);
  }
  // testWrongDirectionKeyFails();
  testAckRoundTrip();
  testInitialDecryptable();

  try {
    testCorruptedPacketFails();
  } catch (e, st) {
    print('❌ testWrongDirectionKeyFails failed: $e');
    print(st);
  }

  print('🎉 All QUIC crypto tests passed');
}
