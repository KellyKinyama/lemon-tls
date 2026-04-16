import 'dart:typed_data';

import 'package:hex/hex.dart';

import '../packet/quic_packet.dart';
import 'test.dart';

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

  client.decryptPacket(udp2ServerHello, EncryptionLevel.initial);
  client.decryptPacket(upd2HandshakePacket, EncryptionLevel.handshake);
  client.decryptPacket(udp3ServerHandshakeFinished, EncryptionLevel.handshake);
  client.decryptPacket(udp6ServerHandshakeAck, EncryptionLevel.handshake);

  client.decryptPacket(udp6ServerApp, EncryptionLevel.application);
  client.decryptPacket(udp8ServerClose, EncryptionLevel.application);

  server.decryptPacket(udp1ClientHello, EncryptionLevel.initial);
  server.decryptPacket(udp4ClientinitialAck, EncryptionLevel.initial);
  server.decryptPacket(udp5ClientHandshakeFinished, EncryptionLevel.handshake);
  server.decryptPacket(udp5ClientPing, EncryptionLevel.application);
  server.decryptPacket(
    udp7ServerApp,
    EncryptionLevel.application,
  ); // client ACK
}

void main() {
  testEndToEnd();
}
