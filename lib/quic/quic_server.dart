// quic_server.dart
import 'dart:io';
import 'dart:typed_data';
import 'dart:convert';

import 'client_hello.dart';
import 'crypto.dart';
import 'server_hello.dart';
import 'aead.dart';
import 'byte_reader.dart';

//
// ===================================================
// QUIC CRYPTO FRAME HELPERS
// ===================================================
//

Uint8List buildCryptoFrame(Uint8List data) {
  return Uint8List.fromList([
    0x06, // CRYPTO frame type
    0x00, // offset = 0
    data.length,
    ...data,
  ]);
}

//
// ===================================================
// QUIC Initial Packet Builder (NO header protection)
// ===================================================
//

Uint8List buildInitialPacket({
  required Uint8List dcid,
  required Uint8List scid,
  required int packetNumber,
  required Uint8List payload,
}) {
  return Uint8List.fromList([
    0xC3, // QUIC long header, Initial, PN length=1
    0x00, 0x00, 0x00, 0x01, // QUIC version = 1
    dcid.length,
    ...dcid,
    scid.length,
    ...scid,
    0x00, // token length = 0
    payload.length + 1, // length = ciphertext + PN
    packetNumber, // PN (1 byte)
    ...payload, // AEAD ciphertext || tag
  ]);
}

//
// ===================================================
// QUIC Initial Packet Parser
// (VERY minimal, only for toy server testing)
// ===================================================
//

class QuicInitialPacket {
  final Uint8List dcid;
  final Uint8List scid;
  final Uint8List payload;
  final int packetNumber;

  QuicInitialPacket({
    required this.dcid,
    required this.scid,
    required this.payload,
    required this.packetNumber,
  });

  static QuicInitialPacket parse(Uint8List packet) {
    int i = 0;

    final flags = packet[i++];
    if ((flags & 0xC0) != 0xC0) {
      throw StateError("Not a QUIC Initial packet");
    }

    // Skip version
    i += 4;

    final dcidLen = packet[i++];
    final dcid = packet.sublist(i, i + dcidLen);
    i += dcidLen;

    final scidLen = packet[i++];
    final scid = packet.sublist(i, i + scidLen);
    i += scidLen;

    final tokenLen = packet[i++];
    i += tokenLen;

    final length = packet[i++]; // varint simplified

    final packetNumber = packet[i++];
    final ciphertext = packet.sublist(i);

    return QuicInitialPacket(
      dcid: dcid,
      scid: scid,
      payload: ciphertext,
      packetNumber: packetNumber,
    );
  }
}

//
// ===================================================
// QUIC HANDSHAKE SERVER
// ===================================================
//

class QuicServer {
  final RawDatagramSocket socket;

  QuicServer(this.socket);

  void start() {
    print("✅ QUIC server listening on UDP port ${socket.port}");

    socket.listen((event) {
      if (event == RawSocketEvent.read) {
        final dg = socket.receive();
        if (dg != null) _onPacket(dg);
      }
    });
  }

  Future<void> _onPacket(Datagram dg) async {
    try {
      final pkt = QuicInitialPacket.parse(dg.data);

      //
      // =======================================================
      // 1) Derive QUIC Initial keys using your hkdf.dart
      // =======================================================
      //
      final initial = QuicInitialKeys(pkt.dcid);
      final aead = Aead(CipherSuite.aes128gcm);

      //
      // =======================================================
      // 2) AEAD-Decrypt the CRYPTO frame
      // =======================================================
      //
      final nonce = quicNonce(initial.clientIv, pkt.packetNumber);
      final plaintext = aead.decrypt(
        key: initial.clientKey,
        nonce: nonce,
        aad: Uint8List(0), // QUIC Initial uses empty AAD after HP removal
        ciphertext: pkt.payload,
      );

      final cryptoReader = ByteReader(plaintext);

      if (cryptoReader.readUint8() != 0x06) return; // CRYPTO frame only
      cryptoReader.readUint8(); // offset
      final cryptoLen = cryptoReader.readUint8();
      final handshakeBytes = cryptoReader.readBytes(cryptoLen);

      //
      // =======================================================
      // 3) Parse ClientHello (QUIC variant, NO RecordHeader)
      // =======================================================
      //
      final ch = ClientHello.deserialize(ByteReader(handshakeBytes));

      final clientKex = ch.parsedExtensions
          .whereType<ClientHelloKeyShare>()
          .first
          .keyExchange;

      //
      // =======================================================
      // 4) X25519: derive shared secret
      // =======================================================
      //
      final serverKeyPair = QuicKeyPair.generate();
      final shared = serverKeyPair.exchange(clientKex);

      //
      // =======================================================
      // 5) Build QUIC ServerHello (TLS 1.3 raw HH+body)
      // =======================================================
      //
      final sh = ServerHello.buildForQuic(
        keySharePublic: serverKeyPair.publicKey,
        cipherSuite: CipherSuite.aes128gcm,
      );

      final shBytes = sh.serialize(); // ✅ QUIC-safe bytes

      //
      // =======================================================
      // 6) Wrap ServerHello in CRYPTO frame
      // =======================================================
      //
      final cryptoFrame = buildCryptoFrame(shBytes);

      //
      // =======================================================
      // 7) AEAD-encrypt server Initial flight
      // =======================================================
      //
      final nonceServer = quicNonce(initial.serverIv, 1);
      final ciphertext = aead.encrypt(
        key: initial.serverKey,
        nonce: nonceServer,
        aad: Uint8List(0),
        plaintext: cryptoFrame,
      );

      //
      // =======================================================
      // 8) Build and send QUIC Initial packet
      // =======================================================
      //
      final out = buildInitialPacket(
        dcid: pkt.scid,
        scid: pkt.dcid,
        packetNumber: 1,
        payload: ciphertext,
      );

      socket.send(out, dg.address, dg.port);
      print("✅ Sent QUIC ServerHello (Initial packet)");
    } catch (e, st) {
      print("❌ QUIC handshake error: $e");
      print(st);
    }
  }
}

//
// ===================================================
// ENTRY POINT
// ===================================================
//

void main() async {
  final sock = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 4433);

  final server = QuicServer(sock);
  server.start();
}
