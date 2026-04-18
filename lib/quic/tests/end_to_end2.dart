import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:hex/hex.dart';
import 'package:lemon_tls/quic/packet/payload_parser2.dart';

import '../packet/quic_packet.dart';
import '../utils.dart';
import 'test.dart';

final _bytesEq = const ListEquality<int>();

void expectBytesEqual(String name, Uint8List actual, String expectedHex) {
  final expected = Uint8List.fromList(HEX.decode(expectedHex));
  // print("Got $name:      ${HEX.encode(actual)}");
  // print("Expected $name: $expectedHex");

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
      logging: false,
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

  Uint8List buildHandshakeMsg() {
    // SERVER → CLIENT handshake protection keys (deduced from end_to_end.dart):
    // client.setReadKeys(EncryptionLevel.handshake, ...)
    final serverToClientHsKeys = QuicTrafficKeys(
      key: Uint8List.fromList(HEX.decode("17abbf0a788f96c6986964660414e7ec")),
      iv: Uint8List.fromList(HEX.decode("09597a2ea3b04c00487e71f3")),
      hp: Uint8List.fromList(HEX.decode("2a18061c396c2828582b41b0910ed536")),
    );

    // Build CRYPTO frame for the server handshake flight.
    // IMPORTANT: QUIC CRYPTO frame uses varints for offset/len in real QUIC,
    // but your test vectors likely use your buildCryptoFrame() helper—keep it consistent.
    final cryptoFrame = buildCryptoFrame(
      Uint8List.fromList(
        HEX.decode(
          "06 43 ff 40 b9 46 1e 8a 23 40 58 98 8e 7f 26 4d 7a b6 a5 1a 21 c6 29 79 b7 a6 79 f4 a0 87 70 85 6e 92 6d 37 1b 2e 89 16 9a a1 90 b8 03 63 6b b1 0c 0f b9 05 98 3d 2b 50 0a ad 26 83 df be 15 6e cc f6 66 de 1a 5a d4 5d 77 38 d5 e7 8b d1 7b c3 e6 d2 5f 9a d4 af ba 8f 81 de 9f 4d 55 72 11 8e 08 55 1a 4b b9 4b 56 a9 70 e8 04 c6 82 67 45 4b 51 7f c8 38 6c 9b ae 3a 77 cc cb 7f 29 0f 6e 58 fb a1 26 f0 53 33 a1 1f 8a b0 89 2e 6e 7a 89 58 53 82 d3 6e ef 25 29 cf 5b 7b 14 00 00 20 06 8f cb 60 6a a1 c8 aa 35 4d 7b 60 64 a3 32 8c f3 76 bc d9 f3 20 0e 68 ac e3 de 2e e9 fc ac cb",
        ),
      ),
    );

    // For server packets:
    //   DCID = client's CID (peerCid)
    //   SCID = server's CID (myCid)
    const pn = 0;

    final pkt = encryptQuicPacket(
      "handshake",
      cryptoFrame,
      serverToClientHsKeys.key,
      serverToClientHsKeys.iv,
      serverToClientHsKeys.hp,
      pn,
      peerCid,
      myCid,
      null,
    );

    if (pkt == null) {
      throw StateError("Failed to encrypt handshake packet");
    }
    return pkt;
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
  // final hsMsg = server.buildHandshakeMsg();
  // expectBytesEqual(
  //   "Server handshake match: ",
  //   hsMsg,
  //   HEX.encode(upd2HandshakePacket),
  // );
  final handshakePacket = client.decryptPacket(
    upd2HandshakePacket,
    EncryptionLevel.handshake,
  );
  parsePayload(handshakePacket.plaintext!);
  print("handshake packet: $handshakePacket");

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
