import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:hex/hex.dart';

import '../packet/quic_packet.dart';
import '../utils.dart';
import 'test.dart';

final _bytesEq = const ListEquality<int>();

void expectBytesEqual(String name, Uint8List actual, String expectedHex) {
  final expected = Uint8List.fromList(HEX.decode(expectedHex));
  print("Got $name:      ${HEX.encode(actual)}");
  print("Expected $name: $expectedHex");

  if (!_bytesEq.equals(actual, expected)) {
    throw StateError(
      '$name does not match.\n'
      'Expected: $expectedHex\n'
      'Actual:   ${HEX.encode(actual)}',
    );
  }
}

enum QuicRole { client, server }

enum EncryptionLevel { initial, handshake, application }

class PacketNumberSpace {
  int largestPn = -1;

  int get referencePn => largestPn < 0 ? 0 : largestPn;

  void onPacketDecrypted(int pn) {
    if (pn > largestPn) {
      largestPn = pn;
    }
  }
}

class QuicTrafficKeys {
  final Uint8List key;
  final Uint8List iv;
  final Uint8List hp;

  const QuicTrafficKeys({
    required this.key,
    required this.iv,
    required this.hp,
  });
}

class QuicSession {
  final QuicRole role;

  /// Connection IDs
  late Uint8List myCid;
  late Uint8List peerCid;

  /// Packet number spaces
  final _pnSpaces = <EncryptionLevel, PacketNumberSpace>{
    EncryptionLevel.initial: PacketNumberSpace(),
    EncryptionLevel.handshake: PacketNumberSpace(),
    EncryptionLevel.application: PacketNumberSpace(),
  };

  /// Traffic keys by level and direction
  final _readKeys = <EncryptionLevel, QuicTrafficKeys>{};

  //client initial secrets
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

  //client initial secrets
  final serverInitialKey = Uint8List.fromList(
    HEX.decode("d77fc4056fcfa32bd1302469ee6ebf90"),
  );
  final serverInitialIv = Uint8List.fromList(
    HEX.decode("fcb748e37ff79860faa07477"),
  );
  final serverInitialHp = Uint8List.fromList(
    HEX.decode("440b2725e91dc79b370711ef792faa3d"),
  );

  // ---- Connection IDs ----
  final serverCid = Uint8List.fromList(HEX.decode("0001020304050607"));
  final clientCid = Uint8List.fromList(HEX.decode("635f636964")); // "c_cid"

  final s_cid = Uint8List.fromList(HEX.decode("735f636964")); // "s_cid"

  QuicSession(this.role);

  // ------------------------------------------------------------
  // Key installation
  // ------------------------------------------------------------

  void setReadKeys(EncryptionLevel level, QuicTrafficKeys keys) {
    _readKeys[level] = keys;
  }

  // ------------------------------------------------------------
  // Decrypt packet (core API)
  // ------------------------------------------------------------

  QuicDecryptedPacket decryptPacket(Uint8List packet, EncryptionLevel level) {
    final keys = _readKeys[level];
    if (keys == null) {
      throw StateError('No keys for $level');
    }

    final pnSpace = _pnSpaces[level]!;

    final dcid = level == EncryptionLevel.application ? peerCid : Uint8List(0);

    final result = decryptQuicPacketBytes2(
      packet,
      keys.key,
      keys.iv,
      keys.hp,
      dcid,
      pnSpace.referencePn,
    );

    if (result == null) {
      throw StateError('Decryption failed');
    }

    pnSpace.onPacketDecrypted(result.packetNumber);
    return result;
  }

  Uint8List buildClientInitial() {
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

    return encrypted!;
  }

  Uint8List buildServerInitial() {
    final cryptoFrame = buildCryptoFrame(serverHello);
    final ackFrame = Uint8List.fromList([0x02, 0x00, 0x42, 0x40, 0x00, 0x00]);
    final frames = concatUint8Lists([ackFrame, cryptoFrame]);

    final encrypted = encryptQuicPacket(
      'initial',
      frames,
      serverInitialKey,
      serverInitialIv,
      serverInitialHp,
      0,
      clientCid,
      s_cid,
      Uint8List(0),
    )!;

    return encrypted;
  }
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

void testEndToEnd() {
  final client = QuicSession(QuicRole.client);

  client.myCid = Uint8List.fromList(HEX.decode("735f636964")); // s_cid
  client.peerCid = Uint8List.fromList(HEX.decode("635f636964")); // c_cid

  // ✅ SERVER → CLIENT Initial traffic
  client.setReadKeys(
    EncryptionLevel.initial,
    QuicTrafficKeys(
      key: Uint8List.fromList(HEX.decode("d77fc4056fcfa32bd1302469ee6ebf90")),
      iv: Uint8List.fromList(HEX.decode("fcb748e37ff79860faa07477")),
      hp: Uint8List.fromList(HEX.decode("440b2725e91dc79b370711ef792faa3d")),
    ),
  );

  client.setReadKeys(
    EncryptionLevel.handshake,
    QuicTrafficKeys(
      key: Uint8List.fromList(HEX.decode("17abbf0a788f96c6986964660414e7ec")),
      iv: Uint8List.fromList(HEX.decode("09597a2ea3b04c00487e71f3")),
      hp: Uint8List.fromList(HEX.decode("2a18061c396c2828582b41b0910ed536")),
    ),
  );

  // ✅ SERVER → CLIENT application traffic
  client.setReadKeys(
    EncryptionLevel.application,
    QuicTrafficKeys(
      key: Uint8List.fromList(HEX.decode("fd8c7da9de1b2da4d2ef9fd5188922d0")),
      iv: Uint8List.fromList(HEX.decode("02f6180e4f4aa456d7e8a602")),
      hp: Uint8List.fromList(HEX.decode("b7f6f021453e52b58940e4bba72a35d4")),
    ),
  );

  final server = QuicSession(QuicRole.server);

  server.myCid = Uint8List.fromList(HEX.decode("635f636964")); // c_cid
  server.peerCid = Uint8List.fromList(HEX.decode("735f636964")); // s_cid

  // ✅ CLIENT → SERVER Initial traffic
  server.setReadKeys(
    EncryptionLevel.initial,
    QuicTrafficKeys(
      key: Uint8List.fromList(HEX.decode("b14b918124fda5c8d79847602fa3520b")),
      iv: Uint8List.fromList(HEX.decode("ddbc15dea80925a55686a7df")),
      hp: Uint8List.fromList(HEX.decode("6df4e9d737cdf714711d7c617ee82981")),
    ),
  );

  server.setReadKeys(
    EncryptionLevel.handshake,
    QuicTrafficKeys(
      key: Uint8List.fromList(HEX.decode("30a7e816f6a1e1b3434cf39cf4b415e7")),
      iv: Uint8List.fromList(HEX.decode("11e70a5d1361795d2bb04465")),
      hp: Uint8List.fromList(HEX.decode("84b3c21cacaf9f54c885e9a506459079")),
    ),
  );

  // ✅ CLIENT → SERVER application traffic
  server.setReadKeys(
    EncryptionLevel.application,
    QuicTrafficKeys(
      key: Uint8List.fromList(HEX.decode("e010a295f0c2864f186b2a7e8fdc9ed7")),
      iv: Uint8List.fromList(HEX.decode("eb3fbc384a3199dcf6b4c808")),
      hp: Uint8List.fromList(HEX.decode("8a6a38bc5cc40cb482a254dac68c9d2f")),
    ),
  );
  //client sends hello
  final clientInitial = client.buildClientInitial();
  expectBytesEqual(
    "client intial match: ",
    clientInitial,
    HEX.encode(udp1ClientHello),
  );

  server.decryptPacket(udp1ClientHello, EncryptionLevel.initial);
  print("");

  final serverInitial = server.buildServerInitial();
  expectBytesEqual(
    "Server intial match: ",
    serverInitial,
    HEX.encode(udp2ServerHello),
  );

  client.decryptPacket(udp2ServerHello, EncryptionLevel.initial);
  print("");
  client.decryptPacket(upd2HandshakePacket, EncryptionLevel.handshake);
  client.decryptPacket(udp3ServerHandshakeFinished, EncryptionLevel.handshake);
  server.decryptPacket(udp4ClientinitialAck, EncryptionLevel.initial);
  server.decryptPacket(udp5ClientHandshakeFinished, EncryptionLevel.handshake);

  server.decryptPacket(udp5ClientPing, EncryptionLevel.application);
  client.decryptPacket(udp6ServerHandshakeAck, EncryptionLevel.handshake);

  client.decryptPacket(udp6ServerApp, EncryptionLevel.application);
  server.decryptPacket(
    udp7ServerApp,
    EncryptionLevel.application,
  ); // client ACK
  client.decryptPacket(udp8ServerClose, EncryptionLevel.application);
}

void main() {
  testEndToEnd();
}
