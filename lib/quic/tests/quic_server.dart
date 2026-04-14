// quic_server_option_b.dart
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:hex/hex.dart';

import 'packet/quic_packet.dart';
import 'packet/payload_parser.dart';
import 'quic_session.dart';
import 'quic_crypto.dart';
import 'quic_ack.dart';
import 'utils.dart';

/// ================================================================
/// QUIC Client (Transport + Packet Pump)
/// ================================================================
///
/// This file is intentionally *NOT* responsible for:
///   - TLS transcript correctness
///   - Secret derivation
///   - Finished verification
///
/// Those responsibilities live in `quic_session.dart`.
///
class QuicClient {
  final RawDatagramSocket socket;
  final QuicSession session;

  /// ACK tracking
  int largestReceivedPn = -1;
  final Set<int> receivedPns = {};

  final String serverAddress;
  final int serverPort;

  QuicClient({
    required this.socket,
    required this.session,
    required this.serverAddress,
    required this.serverPort,
  });

  /// ------------------------------------------------------------
  /// Start QUIC handshake (Initial → Handshake → 1‑RTT)
  /// ------------------------------------------------------------
  void start() {
    print("🚀 QUIC client starting (DCID=${HEX.encode(session.dcid)})");

    socket.listen((event) {
      if (event == RawSocketEvent.read) {
        final dg = socket.receive();
        if (dg == null) return;

        // Only accept packets from the peer we contacted
        if (dg.address.address != serverAddress || dg.port != serverPort) {
          return;
        }

        _onDatagram(dg);
      }
    });

    _sendInitial();
  }

  /// ------------------------------------------------------------
  /// Send Initial packet with ClientHello
  /// ------------------------------------------------------------
  void _sendInitial() {
    final plaintext = session.buildInitialCryptoPayload();

    final initialPacket = encryptQuicPacket(
      level: QuicEncryptionLevel.initial,
      plaintext: plaintext,
      session: session,
      packetNumber: 0,
    );

    if (initialPacket == null) {
      throw StateError("Failed to encrypt Initial packet");
    }

    // QUIC Initial MUST be ≥1200 bytes
    final padded = initialPacket.length >= 1200
        ? initialPacket
        : (Uint8List(1200)..setAll(0, initialPacket));

    socket.send(padded, InternetAddress(serverAddress), serverPort);

    print("📤 Sent Initial (${padded.length} bytes)");
  }

  /// ------------------------------------------------------------
  /// Incoming UDP datagram → one or more QUIC packets
  /// ------------------------------------------------------------
  void _onDatagram(Datagram dg) {
    final packets = splitCoalescedPackets(dg.data);

    for (final pkt in packets) {
      _onQuicPacket(pkt);
    }
  }

  /// ------------------------------------------------------------
  /// QUIC packet receive path
  /// ------------------------------------------------------------
  void _onQuicPacket(Uint8List packet) {
    final decrypted = decryptQuicPacket(packet, session, largestReceivedPn);

    if (decrypted == null || decrypted.plaintext == null) {
      print("❌ Failed to decrypt QUIC packet");
      return;
    }

    largestReceivedPn = math.max(largestReceivedPn, decrypted.packetNumber);
    receivedPns.add(decrypted.packetNumber);

    session.onDecryptedPayload(decrypted.plaintext!);

    _maybeSendAck();
  }

  /// ------------------------------------------------------------
  /// ACK generation (transport‑level, crypto‑agnostic)
  /// ------------------------------------------------------------
  void _maybeSendAck() {
    if (receivedPns.isEmpty) return;

    final ack = buildAckFromSet(
      receivedPns,
      ackDelayMicros: 0,
      ect0: 0,
      ect1: 0,
      ce: 0,
    );

    final ackFrame = ack.encode();

    final packet = encryptQuicPacket(
      level: session.encryptionLevel,
      plaintext: ackFrame,
      session: session,
      packetNumber: session.nextPacketNumber(),
    );

    if (packet == null) return;

    socket.send(packet, InternetAddress(serverAddress), serverPort);
  }
}

/// ================================================================
/// Entry point
/// ================================================================
Future<void> main() async {
  final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);

  final dcid = Uint8List.fromList(
    List.generate(8, (_) => math.Random.secure().nextInt(256)),
  );

  final session = QuicSession.client(dcid: dcid);

  final client = QuicClient(
    socket: socket,
    session: session,
    serverAddress: "127.0.0.1",
    serverPort: 4433,
  );

  client.start();
}
