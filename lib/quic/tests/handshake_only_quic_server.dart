import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:hex/hex.dart';

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

// import 'quic_logger.dart';
// import 'crypto_utils.dart'; // contains decryptQuicPacketBytes2, encryptQuicPacket, etc.
// import 'protocol.dart'; // frame parsing
// import 'utils.dart';

/* ============================================================
 *  LOGGER
 * ============================================================ */

final logger = QuicTestLogger('quic_logs');



/* ============================================================
 *  CONNECTION STATE
 * ============================================================ */

class QuicConnection {
  int version = 1;

  Uint8List? originalDcid;
  Uint8List? clientScid;

  int recvInitLargestPn = -1;
  int recvHsLargestPn = -1;

  int sendInitPn = 0;
  int sendHsPn = 0;

  final Map<int, Uint8List> initCrypto = {};
  int initCryptoOffset = 0;

  final Map<int, Uint8List> hsCrypto = {};
  int hsCryptoOffset = 0;

  final List<Uint8List> tlsTranscript = [];

  int? tlsCipher;
  Uint8List? tlsSharedSecret;
  Uint8List? tlsClientHsSecret;
  Uint8List? tlsServerHsSecret;
  bool tlsFinishedOk = false;

  QuicTrafficKeys? initRead;
  QuicTrafficKeys? initWrite;
  QuicTrafficKeys? hsRead;
  QuicTrafficKeys? hsWrite;

  bool handshakeComplete = false;
}

final Map<String, QuicConnection> connections = {};

/* ============================================================
 *  UTILITIES
 * ============================================================ */

({Uint8List data, int newOffset}) concatChunks(
  Map<int, Uint8List> chunks,
  int start,
) {
  final keys = chunks.keys.toList()..sort();
  final out = <int>[];
  var offset = start;

  for (final k in keys) {
    if (k != offset) break;
    out.addAll(chunks[k]!);
    offset += chunks[k]!.length;
    chunks.remove(k);
  }

  return (data: Uint8List.fromList(out), newOffset: offset);
}

void sendPacket(
  RawDatagramSocket socket,
  InternetAddress addr,
  int port,
  Uint8List packet,
) {
  socket.send(packet, addr, port);
}

/* ============================================================
 *  INITIAL PACKET HANDLING
 * ============================================================ */

void handleInitial(
  QuicConnection conn,
  Uint8List packet,
  RawDatagramSocket socket,
  InternetAddress addr,
  int port,
) {
  conn.initRead ??= quicDeriveInitSecrets(
    conn.originalDcid!,
    version: conn.version,
    direction: QuicInitialDirection.read,
    logger: logger,
  );

  conn.initWrite ??= quicDeriveInitSecrets(
    conn.originalDcid!,
    version: conn.version,
    direction: QuicInitialDirection.write,
    logger: logger,
  );

  final dec = decryptQuicPacketBytes2(
    packet,
    conn.initRead!.key,
    conn.initRead!.iv,
    conn.initRead!.hp,
    conn.originalDcid!,
    conn.recvInitLargestPn,
  );

  if (dec == null || dec.plaintext == null) return;
  conn.recvInitLargestPn = max(conn.recvInitLargestPn, dec.packetNumber);

  logger.log('server_rx_initial', {
    'packet_number': dec.packetNumber,
    'plaintext': QuicTestLogger.hex(dec.plaintext!),
    'protected_packet': QuicTestLogger.hex(packet),
  });

  final frames = parseQuicFrames(dec.plaintext!);

  for (final f in frames) {
    if (f.type == QuicFrameType.crypto) {
      conn.initCrypto[f.offset] = f.data;
    }
  }

  final merged = concatChunks(conn.initCrypto, conn.initCryptoOffset);
  conn.initCryptoOffset = merged.newOffset;

  if (merged.data.isEmpty) return;

  final tls = parseTlsMessage(merged.data);
  if (tls.type != 0x01) return; // ClientHello

  final parsed = parseTlsClientHello(tls.body);
  conn.tlsTranscript.add(merged.data);

  final picked = handleClientHello(parsed);
  conn.tlsCipher = picked.selectedCipher;
  conn.tlsSharedSecret = picked.sharedSecret;

  final serverRandom = Uint8List.fromList(
    List<int>.generate(32, (_) => Random.secure().nextInt(256)),
  );

  final serverHello = buildServerHello(
    serverRandom,
    picked.serverPublicKey,
    parsed.sessionId,
    conn.tlsCipher!,
    picked.selectedGroup,
  );

  conn.tlsTranscript.add(serverHello);

  sendCrypto(conn, 'initial', serverHello, socket, addr, port);

  final hs = tlsDeriveHandshakeSecrets(
    conn.tlsSharedSecret!,
    conn.tlsTranscript,
    getCipherInfo(conn.tlsCipher!).hash,
  );

  conn.tlsClientHsSecret = hs.clientHandshakeTrafficSecret;
  conn.tlsServerHsSecret = hs.serverHandshakeTrafficSecret;
}

/* ============================================================
 *  HANDSHAKE PACKET HANDLING
 * ============================================================ */

void handleHandshake(
  QuicConnection conn,
  Uint8List packet,
  RawDatagramSocket socket,
  InternetAddress addr,
  int port,
) {
  if (conn.hsRead == null && conn.tlsClientHsSecret != null) {
    conn.hsRead = quicDeriveFromTlsSecrets(conn.tlsClientHsSecret!);
    conn.hsWrite = quicDeriveFromTlsSecrets(conn.tlsServerHsSecret!);

    logger.log('handshake_keys', {
      'read': {
        'key': QuicTestLogger.hex(conn.hsRead!.key),
        'iv': QuicTestLogger.hex(conn.hsRead!.iv),
        'hp': QuicTestLogger.hex(conn.hsRead!.hp),
      },
      'write': {
        'key': QuicTestLogger.hex(conn.hsWrite!.key),
        'iv': QuicTestLogger.hex(conn.hsWrite!.iv),
        'hp': QuicTestLogger.hex(conn.hsWrite!.hp),
      },
    });
  }

  if (conn.hsRead == null) return;

  final dec = decryptQuicPacketBytes2(
    packet,
    conn.hsRead!.key,
    conn.hsRead!.iv,
    conn.hsRead!.hp,
    conn.originalDcid!,
    conn.recvHsLargestPn,
  );

  if (dec == null || dec.plaintext == null) return;
  conn.recvHsLargestPn = max(conn.recvHsLargestPn, dec.packetNumber);

  final frames = parseQuicFrames(dec.plaintext!);

  for (final f in frames) {
    if (f.type == QuicFrameType.crypto) {
      conn.hsCrypto[f.offset] = f.data;
    }
  }

  final merged = concatChunks(conn.hsCrypto, conn.hsCryptoOffset);
  conn.hsCryptoOffset = merged.newOffset;
  if (merged.data.isEmpty) return;

  final tls = parseTlsMessage(merged.data);
  conn.tlsTranscript.add(merged.data);

  if (tls.type == 0x14) {
    final cipher = getCipherInfo(conn.tlsCipher!);
    final finishedKey = hkdfExpandLabel(
      conn.tlsClientHsSecret!,
      'finished',
      Uint8List(0),
      cipher.hash.outputLen,
      cipher.hash,
    );

    final expected = hmac(
      cipher.str,
      finishedKey,
      hashTranscript(
        conn.tlsTranscript.sublist(0, conn.tlsTranscript.length - 1),
        cipher.hash,
      ),
    );

    if (const ListEquality().equals(expected, tls.body)) {
      conn.tlsFinishedOk = true;
      sendHandshakeDone(conn, socket, addr, port);
      conn.handshakeComplete = true;
    }
  }
}

/* ============================================================
 *  SENDING HELPERS
 * ============================================================ */

void sendCrypto(
  QuicConnection conn,
  String level,
  Uint8List data,
  RawDatagramSocket socket,
  InternetAddress addr,
  int port,
) {
  final frame = QuicFrame.crypto(
    offset: level == 'initial' ? conn.initCryptoOffset : conn.hsCryptoOffset,
    data: data,
  );

  final pn = level == 'initial' ? conn.sendInitPn++ : conn.sendHsPn++;

  final keys = level == 'initial' ? conn.initWrite! : conn.hsWrite!;

  final packet = encryptQuicPacket(
    level,
    encodeQuicFrames([frame]),
    keys.key,
    keys.iv,
    keys.hp,
    pn,
    conn.clientScid!,
    conn.originalDcid!,
    null,
  )!;

  logger.log('server_tx_${level}_$pn', {
    'packet_number': pn,
    'plaintext': QuicTestLogger.hex(data),
    'protected_packet': QuicTestLogger.hex(packet),
  });

  sendPacket(socket, addr, port, packet);
}

void sendHandshakeDone(
  QuicConnection conn,
  RawDatagramSocket socket,
  InternetAddress addr,
  int port,
) {
  final frame = QuicFrame.handshakeDone();
  final pn = conn.sendHsPn++;

  final packet = encryptQuicPacket(
    'handshake',
    encodeQuicFrames([frame]),
    conn.hsWrite!.key,
    conn.hsWrite!.iv,
    conn.hsWrite!.hp,
    pn,
    conn.clientScid!,
    conn.originalDcid!,
    null,
  )!;

  logger.log('server_tx_handshake_done', {
    'packet_number': pn,
    'protected_packet': QuicTestLogger.hex(packet),
  });

  sendPacket(socket, addr, port, packet);
}

/* ============================================================
 *  UDP SERVER MAIN
 * ============================================================ */

Future<void> main() async {
  final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 4433);

  print('✅ QUIC handshake‑only server listening on UDP 4433');

  socket.listen((event) {
    if (event != RawSocketEvent.read) return;

    final dg = socket.receive();
    if (dg == null) return;

    final packets = parseQuicDatagram(dg.data);

    for (final pkt in packets) {
      final key = pkt.dcid != null
          ? HEX.encode(pkt.dcid!)
          : '${dg.address.address}:${dg.port}';

      final conn = connections.putIfAbsent(key, () {
        final c = QuicConnection();
        c.originalDcid = pkt.dcid;
        c.clientScid = pkt.scid;
        return c;
      });

      if (pkt.type == 'initial') {
        handleInitial(conn, pkt.raw, socket, dg.address, dg.port);
      } else if (pkt.type == 'handshake') {
        handleHandshake(conn, pkt.raw, socket, dg.address, dg.port);
      }
    }
  });
}
