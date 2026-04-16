import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:hex/hex.dart';

import '../packet/quic_packet.dart';
import 'test.dart';

/* ============================================================
 *  ENUMS
 * ============================================================
 */

enum QuicRole { client, server }

enum EncryptionLevel { initial, handshake, application }

/* ============================================================
 *  PACKET NUMBER SPACE
 * ============================================================
 */

class PacketNumberSpace {
  int largestPn = -1;

  int get referencePn => largestPn < 0 ? 0 : largestPn;

  void onPacketDecrypted(int pn) {
    if (pn > largestPn) largestPn = pn;
  }
}

/* ============================================================
 *  TRAFFIC KEYS
 * ============================================================
 */

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

/* ============================================================
 *  TEST LOGGER (JSON → disk)
 * ============================================================
 */

class QuicTestLogger {
  final Directory baseDir;

  QuicTestLogger(String path)
    : baseDir = Directory(path)..createSync(recursive: true);

  static String hex(Uint8List b) => HEX.encode(b);

  void log(String name, Map<String, dynamic> data) {
    final file = File('${baseDir.path}/$name.json');
    file.writeAsStringSync(const JsonEncoder.withIndent('  ').convert(data));
  }
}

/* ============================================================
 *  QUIC SESSION (MINIMAL)
 * ============================================================
 */

class QuicSession {
  final QuicRole role;

  late Uint8List myCid;
  late Uint8List peerCid;

  final _pnSpaces = <EncryptionLevel, PacketNumberSpace>{
    EncryptionLevel.initial: PacketNumberSpace(),
    EncryptionLevel.handshake: PacketNumberSpace(),
    EncryptionLevel.application: PacketNumberSpace(),
  };

  final _readKeys = <EncryptionLevel, QuicTrafficKeys>{};

  QuicSession(this.role);

  void setReadKeys(EncryptionLevel level, QuicTrafficKeys keys) {
    _readKeys[level] = keys;
  }

  QuicDecryptedPacket decryptPacket(
    Uint8List packet,
    EncryptionLevel level, {
    required QuicTestLogger logger,
    required String name,
  }) {
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

    if (result!.plaintext == null) {
      throw StateError('Decryption failed (auth error)');
    }

    pnSpace.onPacketDecrypted(result!.packetNumber);

    // ✅ LOG USING THE REAL CLASS FIELDS
    logger.log(name, {
      "role": role.name,
      "encryption_level": level.name,

      "keys": {
        "key": QuicTestLogger.hex(keys.key),
        "iv": QuicTestLogger.hex(keys.iv),
        "hp": QuicTestLogger.hex(keys.hp),
      },

      "packet": {
        "packet_number": result.packetNumber,
        "key_phase": result.keyPhase,
        "dcid": QuicTestLogger.hex(dcid),
      },

      "plaintext": QuicTestLogger.hex(result.plaintext!),
      "protected_packet": QuicTestLogger.hex(packet),
    });

    return result;
  }

  /* ============================================================
 *  END‑TO‑END TEST (LOGGING ENABLED)
 * ============================================================
 */

  static void testEndToEndWithLogging() {
    final logger = QuicTestLogger('quic_logs');

    /* ------------------------------
   * CLIENT SESSION
   * ------------------------------
   */

    final client = QuicSession(QuicRole.client);

    client.myCid = Uint8List.fromList(HEX.decode("735f636964")); // s_cid
    client.peerCid = Uint8List.fromList(HEX.decode("635f636964")); // c_cid

    // Server → Client Initial
    client.setReadKeys(
      EncryptionLevel.initial,
      QuicTrafficKeys(
        key: Uint8List.fromList(HEX.decode("d77fc4056fcfa32bd1302469ee6ebf90")),
        iv: Uint8List.fromList(HEX.decode("fcb748e37ff79860faa07477")),
        hp: Uint8List.fromList(HEX.decode("440b2725e91dc79b370711ef792faa3d")),
      ),
    );

    // Server → Client Handshake
    client.setReadKeys(
      EncryptionLevel.handshake,
      QuicTrafficKeys(
        key: Uint8List.fromList(HEX.decode("17abbf0a788f96c6986964660414e7ec")),
        iv: Uint8List.fromList(HEX.decode("09597a2ea3b04c00487e71f3")),
        hp: Uint8List.fromList(HEX.decode("2a18061c396c2828582b41b0910ed536")),
      ),
    );

    // Server → Client Application
    client.setReadKeys(
      EncryptionLevel.application,
      QuicTrafficKeys(
        key: Uint8List.fromList(HEX.decode("fd8c7da9de1b2da4d2ef9fd5188922d0")),
        iv: Uint8List.fromList(HEX.decode("02f6180e4f4aa456d7e8a602")),
        hp: Uint8List.fromList(HEX.decode("b7f6f021453e52b58940e4bba72a35d4")),
      ),
    );

    /* ------------------------------
   * SERVER SESSION
   * ------------------------------
   */

    final server = QuicSession(QuicRole.server);

    server.myCid = Uint8List.fromList(HEX.decode("635f636964")); // c_cid
    server.peerCid = Uint8List.fromList(HEX.decode("735f636964")); // s_cid

    // Client → Server Initial
    server.setReadKeys(
      EncryptionLevel.initial,
      QuicTrafficKeys(
        key: Uint8List.fromList(HEX.decode("b14b918124fda5c8d79847602fa3520b")),
        iv: Uint8List.fromList(HEX.decode("ddbc15dea80925a55686a7df")),
        hp: Uint8List.fromList(HEX.decode("6df4e9d737cdf714711d7c617ee82981")),
      ),
    );

    // Client → Server Handshake
    server.setReadKeys(
      EncryptionLevel.handshake,
      QuicTrafficKeys(
        key: Uint8List.fromList(HEX.decode("30a7e816f6a1e1b3434cf39cf4b415e7")),
        iv: Uint8List.fromList(HEX.decode("11e70a5d1361795d2bb04465")),
        hp: Uint8List.fromList(HEX.decode("84b3c21cacaf9f54c885e9a506459079")),
      ),
    );

    // Client → Server Application
    server.setReadKeys(
      EncryptionLevel.application,
      QuicTrafficKeys(
        key: Uint8List.fromList(HEX.decode("e010a295f0c2864f186b2a7e8fdc9ed7")),
        iv: Uint8List.fromList(HEX.decode("eb3fbc384a3199dcf6b4c808")),
        hp: Uint8List.fromList(HEX.decode("8a6a38bc5cc40cb482a254dac68c9d2f")),
      ),
    );

    /* ------------------------------
   * DECRYPT ALL PACKETS + LOG
   * ------------------------------
   */

    client.decryptPacket(
      udp2ServerHello,
      EncryptionLevel.initial,
      logger: logger,
      name: 'client_server_initial',
    );

    client.decryptPacket(
      upd2HandshakePacket,
      EncryptionLevel.handshake,
      logger: logger,
      name: 'client_server_handshake',
    );

    client.decryptPacket(
      udp3ServerHandshakeFinished,
      EncryptionLevel.handshake,
      logger: logger,
      name: 'client_server_handshake_finished',
    );

    client.decryptPacket(
      udp6ServerHandshakeAck,
      EncryptionLevel.handshake,
      logger: logger,
      name: 'client_server_handshake_ack',
    );

    client.decryptPacket(
      udp6ServerApp,
      EncryptionLevel.application,
      logger: logger,
      name: 'client_server_application',
    );

    client.decryptPacket(
      udp8ServerClose,
      EncryptionLevel.application,
      logger: logger,
      name: 'client_server_close',
    );

    server.decryptPacket(
      udp1ClientHello,
      EncryptionLevel.initial,
      logger: logger,
      name: 'server_client_initial',
    );

    server.decryptPacket(
      udp4ClientinitialAck,
      EncryptionLevel.initial,
      logger: logger,
      name: 'server_client_initial_ack',
    );

    server.decryptPacket(
      udp5ClientHandshakeFinished,
      EncryptionLevel.handshake,
      logger: logger,
      name: 'server_client_handshake_finished',
    );

    server.decryptPacket(
      udp5ClientPing,
      EncryptionLevel.application,
      logger: logger,
      name: 'server_client_application',
    );

    server.decryptPacket(
      udp7ServerApp,
      EncryptionLevel.application,
      logger: logger,
      name: 'server_client_application_ack',
    );

    print('✅ End-to-end QUIC test completed. Logs written to ./quic_logs/');
  }
}
/* ============================================================
 *  MAIN
 * ============================================================
 */

void main() {
  QuicSession.testEndToEndWithLogging();
}
