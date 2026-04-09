// quic_server_option_b.dart
import 'dart:io';
import 'dart:typed_data';

// QUIC cryptography
import 'cert_utils.dart';
// import 'crypto.dart';
import 'handshake/certificate_verify.dart';
// import 'crypto.dart';
import 'hkdf.dart';
import 'hash.dart';
import 'aead.dart';

// Helpers
import 'byte_reader.dart';

// TLS Handshake Messages
import 'handshake/client_hello.dart';
import 'handshake/server_hello.dart';
import 'handshake/encrypted_extensions.dart';
import 'handshake/finished.dart';
import 'handshake/certificate.dart';

import 'quic_crypto.dart';
import 'quic_ack.dart'; // ✅ NEW
// (initial secrets now handled by quic_crypto.dart)

// ================================================================
// Utilities
// ================================================================
Uint8List _concat(List<Uint8List> xs) {
  final total = xs.fold(0, (n, p) => n + p.length);
  final out = Uint8List(total);
  var o = 0;
  for (final p in xs) {
    out.setRange(o, o + p.length, p);
    o += p.length;
  }
  return out;
}

// ================================================================
// CRYPTO Frame Builder
// ================================================================
Uint8List buildCryptoFrame(Uint8List data) =>
    Uint8List.fromList([0x06, 0x00, data.length, ...data]);

// ================================================================
// Packet Builders
// ================================================================
Uint8List buildInitialPacket({
  required Uint8List dcid,
  required Uint8List scid,
  required int packetNumber,
  required Uint8List payload,
}) {
  return Uint8List.fromList([
    0xC3, // Initial + PN length=1
    0x00, 0x00, 0x00, 0x01, // QUIC v1
    dcid.length, ...dcid,
    scid.length, ...scid,
    0x00, // token length
    payload.length + 1,
    packetNumber,
    ...payload,
  ]);
}

Uint8List buildHandshakePacket({
  required Uint8List dcid,
  required Uint8List scid,
  required int packetNumber,
  required Uint8List payload,
}) {
  return Uint8List.fromList([
    0xE3, // Handshake + PN len=1
    0x00, 0x00, 0x00, 0x01,
    dcid.length, ...dcid,
    scid.length, ...scid,
    payload.length + 1,
    packetNumber,
    ...payload,
  ]);
}

// ================================================================
// Initial Packet Parser
// ================================================================
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
    if ((flags & 0xC0) != 0xC0) throw StateError("Not Initial");

    i += 4; // version

    final dcidLen = pkt[i++];
    final dcid = pkt.sublist(i, i + dcidLen);
    i += dcidLen;

    final scidLen = pkt[i++];
    final scid = pkt.sublist(i, i + scidLen);
    i += scidLen;

    final tokenLen = pkt[i++];
    i += tokenLen;

    final _lenIgnored = pkt[i++];
    final pn = pkt[i++];

    final ciphertext = pkt.sublist(i);

    return QuicInitialPacket(
      dcid: dcid,
      scid: scid,
      payload: ciphertext,
      packetNumber: pn,
    );
  }
}

// ================================================================
// FULL OPTION-B QUIC SERVER (Now with ACK)
// ================================================================
class QuicServerB {
  final RawDatagramSocket socket;

  late final EcdsaCert cert;
  final transcript = <Uint8List>[];

  // ✅ ACK tracking
  int largestReceived = -1;
  final Set<int> receivedPns = {};

  QuicServerB(this.socket) {
    cert = generateSelfSignedCertificate();
    print("✅ Generated self-signed ECDSA-P256 certificate");
  }

  void start() {
    print("✅ QUIC Option-B server listening on UDP ${socket.port}");
    socket.listen((ev) {
      if (ev == RawSocketEvent.read) {
        final dg = socket.receive();
        if (dg != null) _onPacket(dg);
      }
    });
  }

  Future<void> _onPacket(Datagram dg) async {
    try {
      // ------------------------------------------------------------
      // 1) Parse Initial Packet
      // ------------------------------------------------------------
      final pkt = QuicInitialPacket.parse(dg.data);

      // ✅ Track PN for multi-range ACK
      receivedPns.add(pkt.packetNumber);
      if (pkt.packetNumber > largestReceived) {
        largestReceived = pkt.packetNumber;
      }

      // ------------------------------------------------------------
      // 2) Derive initial secrets (read side)
      // ------------------------------------------------------------
      final initSecrets = quicDeriveInitialSecrets(
        dcid: pkt.dcid,
        version: 0x00000001,
        forRead: true,
      );

      final plaintext = quicAeadDecrypt(
        key: initSecrets.key,
        iv: initSecrets.iv,
        packetNumber: pkt.packetNumber,
        ciphertextWithTag: pkt.payload,
        aad: Uint8List(0),
      );

      if (plaintext == null) {
        print("❌ Initial AEAD decrypt failed");
        return;
      }

      // ------------------------------------------------------------
      // 3) Extract CRYPTO(ClientHello)
      // ------------------------------------------------------------
      final br = ByteReader(plaintext);
      if (br.readUint8() != 0x06) return;

      br.readUint8(); // offset
      final len = br.readUint8();
      final chBytes = br.readBytes(len);

      transcript.add(chBytes);

      final ch = ClientHello.deserialize(ByteReader(chBytes));
      final clientPub = ch.parsedExtensions
          .whereType<ClientHelloKeyShare>()
          .first
          .keyExchange;

      // ------------------------------------------------------------
      // ✅ SEND ACK FOR CLIENT INITIAL
      // ------------------------------------------------------------
      final ackFrame = buildAckFromSet(
        receivedPns,
        ackDelayMicros: 0,
        ect0: 0,
        ect1: 0,
        ce: 0,
      );

      final ackBytes = ackFrame.encode();
      final ackCrypto = buildCryptoFrame(ackBytes);

      final ackCiphertext = quicAeadEncrypt(
        key: quicDeriveInitialSecrets(
          dcid: pkt.dcid,
          version: 0x00000001,
          forRead: false,
        ).key,
        iv: quicDeriveInitialSecrets(
          dcid: pkt.dcid,
          version: 0x00000001,
          forRead: false,
        ).iv,
        packetNumber: 1,
        plaintext: ackCrypto,
        aad: Uint8List(0),
      );

      if (ackCiphertext != null) {
        final ackPacket = buildInitialPacket(
          dcid: pkt.scid,
          scid: pkt.dcid,
          packetNumber: 1,
          payload: ackCiphertext,
        );
        socket.send(ackPacket, dg.address, dg.port);
        print("✅ Sent ACK for Client Initial");
      }

      // ------------------------------------------------------------
      // 4) X25519 Key Exchange
      // ------------------------------------------------------------
      final serverKP = QuicKeyPair.generate();
      final sharedSecret = serverKP.exchange(clientPub);

      // ------------------------------------------------------------
      // 5) Build and Send ServerHello
      // ------------------------------------------------------------
      final sh = ServerHello.buildForQuic(
        keySharePublic: serverKP.publicKey,
        cipherSuite: CipherSuite.aes128gcm,
      );

      final shBytes = sh.serialize();
      transcript.add(shBytes);

      final shCrypto = buildCryptoFrame(shBytes);

      final initialWrite = quicDeriveInitialSecrets(
        dcid: pkt.dcid,
        version: 0x00000001,
        forRead: false,
      );

      final shCiphertext = quicAeadEncrypt(
        key: initialWrite.key,
        iv: initialWrite.iv,
        packetNumber: 2,
        plaintext: shCrypto,
        aad: Uint8List(0),
      );

      final initialPacket = buildInitialPacket(
        dcid: pkt.scid,
        scid: pkt.dcid,
        packetNumber: 2,
        payload: shCiphertext!,
      );

      socket.send(initialPacket, dg.address, dg.port);
      print("✅ Sent ServerHello");

      // ------------------------------------------------------------
      // 6) Derive Handshake Secrets
      // ------------------------------------------------------------
      final helloHash = createHash(_concat(transcript));

      final handshakeSecret = hkdfExtract(
        Uint8List(helloHash.length),
        salt: helloHash,
      );

      final serverHsTS = quicHkdfExpandLabel(
        secret: handshakeSecret,
        label: "s hs traffic",
        context: helloHash,
        length: 32,
      );

      final serverHsKey = quicHkdfExpandLabel(
        secret: serverHsTS,
        label: "key",
        context: Uint8List(0),
        length: 16,
      );

      final serverHsIv = quicHkdfExpandLabel(
        secret: serverHsTS,
        label: "iv",
        context: Uint8List(0),
        length: 12,
      );

      // ------------------------------------------------------------
      // 7) EE, Cert, CertVerify, Finished
      // ------------------------------------------------------------
      final ee = EncryptedExtensions.build();
      transcript.add(ee);

      final certMsg = buildCertificateMessage(cert.cert);
      transcript.add(certMsg);

      final certHash = createHash(_concat(transcript));
      final certVerify = buildCertificateVerify(
        privateKeyBytes: cert.privateKey,
        transcriptHash: certHash,
      );
      transcript.add(certVerify);

      final finHash = createHash(_concat(transcript));
      final finishedKey = quicHkdfExpandLabel(
        secret: serverHsTS,
        label: "finished",
        context: Uint8List(0),
        length: 32,
      );
      final fin = FinishedMessage.build(
        finishedKey: finishedKey,
        transcriptHash: finHash,
      );
      transcript.add(fin);

      // ------------------------------------------------------------
      // 8) Send Handshake packet
      // ------------------------------------------------------------
      final hsFlight = _concat([ee, certMsg, certVerify, fin]);
      final hsCrypto = buildCryptoFrame(hsFlight);

      final hsCiphertext = quicAeadEncrypt(
        key: serverHsKey,
        iv: serverHsIv,
        packetNumber: 1,
        plaintext: hsCrypto,
        aad: Uint8List(0),
      );

      final hsPacket = buildHandshakePacket(
        dcid: pkt.scid,
        scid: pkt.dcid,
        packetNumber: 1,
        payload: hsCiphertext!,
      );

      socket.send(hsPacket, dg.address, dg.port);
      print("✅ Sent EE + Certificate + CertVerify + Finished");
    } catch (e, st) {
      print("❌ QUIC Handshake Error: $e");
      print(st);
    }
  }
}

// ================================================================
// Entry
// ================================================================
void main() async {
  final sock = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 4433);
  QuicServerB(sock).start();
}
