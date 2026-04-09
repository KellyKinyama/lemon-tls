// quic_server_option_b.dart
import 'dart:io';
import 'dart:typed_data';
// import 'dart:convert';

// QUIC cryptography
import 'cert_utils.dart';
import 'handshake/certificate_verify.dart';
import 'crypto.dart';
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
import 'quic_aead.dart';
import 'quic_initial_secrets.dart';
// import 'handshake/certificate_verify.dart';

// Certificate (ECDSA-P256 self-signed)
// import 'cert/ecdsa_cert.dart';

//
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

//
// ================================================================
// CRYPTO Frame (0x06)
// ================================================================
Uint8List buildCryptoFrame(Uint8List data) {
  return Uint8List.fromList([0x06, 0x00, data.length, ...data]);
}

//
// ================================================================
// QUIC Packet Builders (no header protection)
// ================================================================
Uint8List buildInitialPacket({
  required Uint8List dcid,
  required Uint8List scid,
  required int packetNumber,
  required Uint8List payload,
}) {
  return Uint8List.fromList([
    0xC3, // Initial
    0x00, 0x00, 0x00, 0x01,
    dcid.length, ...dcid,
    scid.length, ...scid,
    0x00, // no token
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
    0xE3, // Handshake
    0x00, 0x00, 0x00, 0x01,
    dcid.length, ...dcid,
    scid.length, ...scid,
    payload.length + 1,
    packetNumber,
    ...payload,
  ]);
}

//
// ================================================================
// Initial QUIC Packet Parser
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
    if ((flags & 0xC0) != 0xC0) {
      throw StateError("Not an Initial packet");
    }

    i += 4; // version
    final dcidLen = pkt[i++];
    final dcid = pkt.sublist(i, i + dcidLen);
    i += dcidLen;

    final scidLen = pkt[i++];
    final scid = pkt.sublist(i, i + scidLen);
    i += scidLen;

    final tokenLen = pkt[i++];
    i += tokenLen;

    final _length = pkt[i++];
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

//
// ================================================================
// FULL OPTION-B QUIC SERVER
// ================================================================
class QuicServerB {
  final RawDatagramSocket socket;

  late final EcdsaCert cert; // ECDSA self-signed
  final transcript = <Uint8List>[]; // TLS transcript

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
      // --------------------------------------------------------------------
      // 1) Parse QUIC Initial packet
      // --------------------------------------------------------------------
      final pkt = QuicInitialPacket.parse(dg.data);

      // --------------------------------------------------------------------
      // 2) Derive Initial Keys
      // --------------------------------------------------------------------
      final initial = QuicInitialKeys(pkt.dcid);
      final aead = Aead(CipherSuite.aes128gcm);

      // final nonce = quicNonce(initial.clientIv, pkt.packetNumber);
      // final plaintext = aead.decrypt(
      //   key: initial.clientKey,
      //   nonce: nonce,
      //   aad: Uint8List(0),
      //   ciphertext: pkt.payload,
      // );

      // 1) Derive *multi-version* initial secrets
      final initSecrets = quicDeriveInitialSecrets(
        dcid: pkt.dcid,
        version: 0x00000001,
        forRead: true,
      );

      // 2) QUIC Initial packets do NOT use header protection for now,
      // so pnOffset = static (DCID + SCID length known)
      final plaintext = quicAeadDecrypt(
        key: initSecrets.key,
        iv: initSecrets.iv,
        packetNumber: pkt.packetNumber,
        ciphertextWithTag: pkt.payload,
        aad: Uint8List(0),
      );

      // --------------------------------------------------------------------
      // 3) Extract CRYPTO(ClientHello)
      // --------------------------------------------------------------------
      final br = ByteReader(plaintext!);
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

      // --------------------------------------------------------------------
      // 4) Perform X25519 key exchange
      // --------------------------------------------------------------------
      final serverKP = QuicKeyPair.generate();
      final sharedSecret = serverKP.exchange(clientPub);

      // --------------------------------------------------------------------
      // 5) Build ServerHello (QUIC)
      // --------------------------------------------------------------------
      final sh = ServerHello.buildForQuic(
        keySharePublic: serverKP.publicKey,
        cipherSuite: CipherSuite.aes128gcm,
      );

      final shBytes = sh.serialize();
      transcript.add(shBytes);

      // Encrypt ServerHello
      final shCrypto = buildCryptoFrame(shBytes);
      final shNonce = quicNonce(initial.serverIv, 1);
      final shCiphertext = aead.encrypt(
        key: initial.serverKey,
        nonce: shNonce,
        aad: Uint8List(0),
        plaintext: shCrypto,
      );

      // Send Initial packet
      final initialPacket = buildInitialPacket(
        dcid: pkt.scid,
        scid: pkt.dcid,
        packetNumber: 1,
        payload: shCiphertext,
      );

      socket.send(initialPacket, dg.address, dg.port);
      print("✅ Sent ServerHello");

      // --------------------------------------------------------------------
      // 6) Derive Handshake Traffic Secrets
      // --------------------------------------------------------------------
      final helloHash = createHash(_concat(transcript));

      // TLS 1.3 secret derivation (QUIC version)
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

      // --------------------------------------------------------------------
      // 7) EncryptedExtensions
      // --------------------------------------------------------------------
      final ee = EncryptedExtensions.build();
      transcript.add(ee);

      // --------------------------------------------------------------------
      // 8) Certificate
      // --------------------------------------------------------------------
      final certMsg = buildCertificateMessage(cert.cert);
      transcript.add(certMsg);

      // --------------------------------------------------------------------
      // 9) CertificateVerify
      // --------------------------------------------------------------------
      final certHash = createHash(_concat(transcript));

      final certVerify = buildCertificateVerify(
        privateKeyBytes: cert.privateKey,
        transcriptHash: certHash,
      );

      transcript.add(certVerify);

      // --------------------------------------------------------------------
      // 10) Finished
      // --------------------------------------------------------------------
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

      // --------------------------------------------------------------------
      // 11) Build and Send Handshake Packet
      // --------------------------------------------------------------------
      final hsFlight = _concat([ee, certMsg, certVerify, fin]);
      final hsCrypto = buildCryptoFrame(hsFlight);

      final hsNonce = quicNonce(serverHsIv, 1);
      final hsCiphertext = aead.encrypt(
        key: serverHsKey,
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
      print("✅ Sent EE + Certificate + CertificateVerify + Finished");
    } catch (e, st) {
      print("❌ QUIC Handshake Error: $e");
      print(st);
    }
  }
}

//
// ================================================================
// Entry
// ================================================================
void main() async {
  final sock = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 4433);

  final server = QuicServerB(sock);
  server.start();
}
