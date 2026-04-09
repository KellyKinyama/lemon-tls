// lib/quic_server.dart
import 'dart:io';
import 'dart:typed_data';

// QUIC crypto primitives
import 'crypto.dart';
import 'hkdf.dart';
import 'hash.dart';
import 'aead.dart';

// Helpers
import 'byte_reader.dart';

// TLS-only handshake structures
import 'handshake/client_hello.dart';
import 'handshake/server_hello.dart';
import 'handshake/encrypted_extensions.dart';
import 'handshake/finished.dart';
import 'quic_aead.dart';

// (Option B will add)
// import 'handshake/certificate.dart';
// import 'handshake/certificate_verify.dart';
// import 'cert/ecdsa_cert.dart';

//
// ===================================================================
// Utility: concat byte arrays
// ===================================================================
Uint8List _concat(List<Uint8List> xs) {
  final total = xs.fold(0, (a, b) => a + b.length);
  final out = Uint8List(total);
  int o = 0;
  for (final b in xs) {
    out.setRange(o, o + b.length, b);
    o += b.length;
  }
  return out;
}

//
// ===================================================================
// Build CRYPTO Frame
// ===================================================================
Uint8List buildCryptoFrame(Uint8List data) {
  return Uint8List.fromList([
    0x06, // CRYPTO
    0x00, // offset
    data.length,
    ...data,
  ]);
}

//
// ===================================================================
// Build QUIC Initial Packet (no HP)
// ===================================================================
Uint8List buildInitialPacket({
  required Uint8List dcid,
  required Uint8List scid,
  required int packetNumber,
  required Uint8List payload,
}) {
  return Uint8List.fromList([
    0xC3, // Long header, Initial
    0x00, 0x00, 0x00, 0x01, // version = 1
    dcid.length, ...dcid,
    scid.length, ...scid,
    0x00, // token length
    payload.length + 1,
    packetNumber,
    ...payload,
  ]);
}

//
// ===================================================================
// Build QUIC Handshake Packet (no HP)
// ===================================================================
Uint8List buildHandshakePacket({
  required Uint8List dcid,
  required Uint8List scid,
  required int packetNumber,
  required Uint8List payload,
}) {
  return Uint8List.fromList([
    0xE3, // Long header, Handshake
    0x00, 0x00, 0x00, 0x01,
    dcid.length, ...dcid,
    scid.length, ...scid,
    payload.length + 1,
    packetNumber,
    ...payload,
  ]);
}

//
// ===================================================================
// QUIC Initial Packet Parser
// ===================================================================
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

  static QuicInitialPacket parse(Uint8List pkt) {
    int i = 0;

    final flags = pkt[i++];
    if ((flags & 0xC0) != 0xC0) throw StateError("Not an Initial packet");

    i += 4; // version

    final dcidLen = pkt[i++];
    final dcid = pkt.sublist(i, i + dcidLen);
    i += dcidLen;

    final scidLen = pkt[i++];
    final scid = pkt.sublist(i, i + scidLen);
    i += scidLen;

    final tokenLen = pkt[i++];
    i += tokenLen;

    final _length = pkt[i++]; // simplified varint
    final pn = pkt[i++];
    final rest = pkt.sublist(i);

    return QuicInitialPacket(
      dcid: dcid,
      scid: scid,
      payload: rest,
      packetNumber: pn,
    );
  }
}

//
// ===================================================================
// QUIC Server Core
// ===================================================================
class QuicServer {
  final RawDatagramSocket socket;

  QuicServer(this.socket);

  final transcript = <Uint8List>[];

  void start() {
    print("✅ QUIC server listening on UDP ${socket.port}");

    socket.listen((ev) {
      if (ev == RawSocketEvent.read) {
        final dg = socket.receive();
        if (dg != null) _onPacket(dg);
      }
    });
  }

  Future<void> _onPacket(Datagram dg) async {
    try {
      final pkt = QuicInitialPacket.parse(dg.data);

      // ------------------------------
      // Initial Keys
      // ------------------------------
      final initial = QuicInitialKeys(pkt.dcid);
      final aead = Aead(CipherSuite.aes128gcm);

      // ------------------------------
      // Decrypt CRYPTO(ClientHello)
      // ------------------------------
      final nonce = quicNonce(initial.clientIv, pkt.packetNumber);
      final plaintext = aead.decrypt(
        key: initial.clientKey,
        nonce: nonce,
        aad: Uint8List(0),
        ciphertext: pkt.payload,
      );

      final br = ByteReader(plaintext);
      if (br.readUint8() != 0x06) return;

      br.readUint8(); // offset=0
      final len = br.readUint8();
      final chMsg = br.readBytes(len);

      transcript.add(chMsg);

      final ch = ClientHello.deserialize(ByteReader(chMsg));
      final clientPub = ch.parsedExtensions
          .whereType<ClientHelloKeyShare>()
          .first
          .keyExchange;

      // ------------------------------
      // Server KeyShare (X25519)
      // ------------------------------
      final serverKP = QuicKeyPair.generate();
      final shared = serverKP.exchange(clientPub);

      // ------------------------------
      // ServerHello
      // ------------------------------
      final sh = ServerHello.buildForQuic(
        keySharePublic: serverKP.publicKey,
        cipherSuite: CipherSuite.aes128gcm,
      );

      final shBytes = sh.serialize();
      transcript.add(shBytes);

      final shCrypto = buildCryptoFrame(shBytes);
      final shNonce = quicNonce(initial.serverIv, 1);

      final shCiphertext = aead.encrypt(
        key: initial.serverKey,
        nonce: shNonce,
        aad: Uint8List(0),
        plaintext: shCrypto,
      );

      final initialPacket = buildInitialPacket(
        dcid: pkt.scid,
        scid: pkt.dcid,
        packetNumber: 1,
        payload: shCiphertext,
      );

      socket.send(initialPacket, dg.address, dg.port);
      print("✅ Sent ServerHello");

      // ------------------------------
      // Derive HS keys
      // ------------------------------
      final hHash = createHash(_concat(transcript));

      final hsSecret = hkdfExtract(Uint8List(hHash.length), salt: hHash);
      final hsServer = quicHkdfExpandLabel(
        secret: hsSecret,
        label: "s hs traffic",
        context: hHash,
        length: 32,
      );

      final hsKey = quicHkdfExpandLabel(
        secret: hsServer,
        label: "key",
        context: Uint8List(0),
        length: 16,
      );

      final hsIv = quicHkdfExpandLabel(
        secret: hsServer,
        label: "iv",
        context: Uint8List(0),
        length: 12,
      );

      // ------------------------------
      // EncryptedExtensions + Finished
      // ------------------------------
      final ee = EncryptedExtensions.build();
      transcript.add(ee);

      final t2 = createHash(_concat(transcript));

      final fnKey = quicHkdfExpandLabel(
        secret: hsServer,
        label: "finished",
        context: Uint8List(0),
        length: 32,
      );

      final fin = FinishedMessage.build(finishedKey: fnKey, transcriptHash: t2);
      transcript.add(fin);

      final flight = _concat([ee, fin]);
      final hsCrypto = buildCryptoFrame(flight);

      final hsNonce = quicNonce(hsIv, 1);
      final hsCiphertext = aead.encrypt(
        key: hsKey,
        nonce: hsNonce,
        aad: Uint8List(0),
        plaintext: hsCrypto,
      );

      final hsPacket = buildHandshakePacket(
        dcid: pkt.scid,
        scid: pkt.dcid,
        packetNumber: 1,
        payload: hsCiphertext,
      );

      socket.send(hsPacket, dg.address, dg.port);
      print("✅ Sent Handshake Packet");
    } catch (e, st) {
      print("❌ QUIC handshake error: $e");
      print(st);
    }
  }
}

//
// ===================================================================
// Entry
// ===================================================================
void main() async {
  final sock = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 4433);
  final server = QuicServer(sock);
  server.start();
}
