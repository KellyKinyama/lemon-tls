// quic_server_option_b.dart
import 'dart:io';
import 'dart:typed_data';

// QUIC cryptography
import 'package:hex/hex.dart';
import 'package:lemon_tls/quic/packet/payload_parser.dart';
import 'package:lemon_tls/quic/packet/protocol.dart';

import 'cert_utils.dart';
// import 'crypto.dart';
import 'cipher/p256.dart';
import 'crypto.dart';
import 'handshake/certificate_verify.dart';
// import 'crypto.dart';
import 'handshake/keyshare.dart';
import 'hkdf.dart';
import 'hash.dart';
import 'aead.dart';

// Helpers
import 'byte_reader.dart';

// TLS Handshake Messages
// import 'handshake/client_hello.dart';
import 'handshake/server_hello.dart';
import 'handshake/encrypted_extensions.dart';
import 'handshake/finished.dart';
import 'handshake/certificate.dart';

import 'initialial_aead.dart';
import 'packet/quic_packet.dart';
import 'quic_crypto.dart';
import 'quic_ack.dart';
import 'quic_keys.dart';
import 'quic_session.dart';
// import 'tls_crypto.dart'; // ✅ NEW
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

  @override
  String toString() {
    // TODO: implement toString
    return """QuicInitialPacket{
     dcid: ${HEX.encode(dcid)},
      scid: ${HEX.encode(scid)},
      payload: ${HEX.encode(payload.sublist(0, 10))}... ,
      packetNumber: $packetNumber,
    }""";
  }
}

// ================================================================
// FULL OPTION-B QUIC SERVER (Now with ACK)
// ================================================================
class QuicServerB {
  final RawDatagramSocket socket;

  final Map<String, QUICSession> _quicSessions = {};

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

    socket.listen((event) {
      if (event == RawSocketEvent.read) {
        final dg = socket.receive();
        if (dg != null) {
          // ✅ NEVER PROCESS PACKETS ORIGINATING FROM OUR OWN SOCKET
          if (dg.port == socket.port) {
            // This is a self-sent packet → ignore it
            print("⚠️ Ignoring self-received packet (loopback).");
            return;
          }

          _onPacket(dg);
        }
      }
    });
  }

  void _receivingQuicPacket(InternetAddress address, int port, Uint8List msg) {
    if (msg.isEmpty) {
      print("empty message");
      return;
    }

    Uint8List _padTo1200(Uint8List pkt) {
      const minInitialSize = 1200;
      if (pkt.length >= minInitialSize) return pkt;
      final out = Uint8List(minInitialSize);
      out.setRange(0, pkt.length, pkt);
      return out;
    }

    // --- QUIC varint reader (RFC 9000) ---
    int _readVarInt(Uint8List b, int start, ({int value, int next}) out) =>
        throw UnimplementedError();
    ({int value, int next}) _readVarInt2(Uint8List b, int start) {
      if (start >= b.length) throw RangeError.range(start, 0, b.length - 1);
      final first = b[start];
      final prefix = first >> 6;
      final len = 1 << prefix; // 1,2,4,8
      if (start + len > b.length) {
        throw RangeError('varint overruns buffer');
      }
      int val = first & 0x3f;
      for (var i = 1; i < len; i++) {
        val = (val << 8) | b[start + i];
      }
      return (value: val, next: start + len);
    }

    print('\n--- Parsing the QU-IC Initial Packet with Debugging ---');

    final pkt = Uint8List.fromList(msg);
    final firstByte = pkt[0];
    final isLongHeader = (firstByte & 0x80) != 0;

    if (!isLongHeader) {
      print('Short header packet received (1-RTT not implemented).');
      return;
    }

    final isInitial = (firstByte & 0xF0) == 0xC0;
    if (!isInitial) {
      print(
        'Long header is not Initial (type=0x${firstByte.toRadixString(16)}). Ignored.',
      );
      return;
    }

    // ---- Correct Initial header parse ----
    var off = 1; // first byte
    if (pkt.length < off + 4) {
      print('Packet too short for version');
      return;
    }
    final version = ByteData.view(
      pkt.buffer,
      pkt.offsetInBytes + off,
      4,
    ).getUint32(0);
    off += 4;

    if (pkt.length < off + 1) {
      print('Packet too short for DCID len');
      return;
    }
    final dcidLen = pkt[off++];
    if (pkt.length < off + dcidLen) {
      print('Packet too short for DCID');
      return;
    }
    final dcid = Uint8List.sublistView(pkt, off, off + dcidLen);
    off += dcidLen;

    if (pkt.length < off + 1) {
      print('Packet too short for SCID len');
      return;
    }
    final scidLen = pkt[off++];
    if (pkt.length < off + scidLen) {
      print('Packet too short for SCID');
      return;
    }
    final scid = Uint8List.sublistView(pkt, off, off + scidLen);
    off += scidLen;

    print('DEBUG: Parsed DCID Length: $dcidLen');
    print('DEBUG: Parsed DCID (Hex): ${HEX.encode(dcid)}');
    print('DEBUG: Parsed SCID Length: $scidLen');
    print('DEBUG: Parsed SCID (Hex): ${HEX.encode(scid)}');

    // Token Length (varint) + Token
    late final int tokenLen;
    try {
      final rTokLen = _readVarInt2(pkt, off);
      tokenLen = rTokLen.value;
      off = rTokLen.next;
    } catch (e) {
      print('Packet too short for token length varint: $e');
      return;
    }
    if (pkt.length < off + tokenLen) {
      print('Packet too short for token');
      return;
    }
    off += tokenLen;

    // Length (varint): length of remainder of packet (pn + payload)
    late final int lengthField;
    try {
      final rLen = _readVarInt2(pkt, off);
      lengthField = rLen.value;
      off = rLen.next;
    } catch (e) {
      print('Packet too short for length varint: $e');
      return;
    }

    // We don't consume PN here; decryptQuicPacket() finds PN offset via header protection.
    print(
      'DEBUG: tokenLen=$tokenLen, lengthField=$lengthField, headerEndOffset=$off',
    );

    // ---- Session lookup uses client-chosen DCID (what browser used as DCID) ----
    final dcidHex = HEX.encode(dcid);
    var quicSession = _quicSessions[dcidHex];
    if (quicSession != null) {
      print(
        'Existing session Initial received; current demo ignores reprocessing.',
      );
      return;
    }

    quicSession = _quicSessions[dcidHex] = QUICSession(
      dcid: dcid,
      address: address.address,
      port: port,
    );
    quicSession.x25519 = QuicKeyPair.generate();

    try {
      // Initial secrets and keys
      final (clientSecret, serverSecret) = computeSecrets(
        dcid,
        Version.fromValue(version),
      );

      final (readKey, readIv, readHp) = computeInitialKeyAndIV(
        clientSecret,
        Version.fromValue(version),
      );
      quicSession.initialRead = InitialKeys(
        key: readKey,
        iv: readIv,
        hp: readHp,
      );

      final (writeKey, writeIv, writeHp) = computeInitialKeyAndIV(
        serverSecret,
        Version.fromValue(version),
      );
      quicSession.initialWrite = InitialKeys(
        key: writeKey,
        iv: writeIv,
        hp: writeHp,
      );

      // Decrypt Initial
      final decryptedPacket = decryptQuicPacket(
        pkt,
        quicSession.initialRead!.key,
        quicSession.initialRead!.iv,
        quicSession.initialRead!.hp,
        dcid,
        0,
      );

      if (decryptedPacket == null || decryptedPacket.plaintext == null) {
        print('❌ Failed to decrypt Initial packet');
        return;
      }

      print('✅ Successfully decrypted Initial packet.');
      receivedPns.add(decryptedPacket.packetNumber);

      // IMPORTANT: server MUST send to client's SCID as DCID
      final serverDcid = scid;
      final serverScid = dcid;

      // ACK in Initial
      final ackFrame = buildAckFromSet(
        receivedPns,
        ackDelayMicros: 0,
        ect0: 0,
        ect1: 0,
        ce: 0,
      );
      final ackPayload = ackFrame.encode();
      final ackPn = decryptedPacket.packetNumber + 1;

      final ackPacketRaw = encryptQuicPacket(
        "initial",
        ackPayload,
        quicSession.initialWrite!.key,
        quicSession.initialWrite!.iv,
        quicSession.initialWrite!.hp,
        ackPn,
        serverDcid,
        serverScid,
        Uint8List(0),
      );
      if (ackPacketRaw == null) {
        print("❌ Failed to build ACK Initial packet");
        return;
      }
      socket.send(_padTo1200(ackPacketRaw), address, port);
      print(
        "✅ Sent ACK for Client Initial PN=${decryptedPacket.packetNumber} (server PN=$ackPn)",
      );

      // Parse payload
      quicSession.handleDecryptedPacket(decryptedPacket.plaintext!);

      if (quicSession.clientHello == null) {
        print("❌ No ClientHello parsed — cannot send ServerHello.");
        return;
      }

      // ... keep your existing ServerHello + Handshake flight code here unchanged ...
    } catch (e, st) {
      print('Error processing Initial packet: $e');
      print(st);
      rethrow;
    }
  }

  void _onPacket(Datagram dg) {
    print('processing packet:');
    _receivingQuicPacket(dg.address, dg.port, dg.data);
    print('processing packet finished');
    // try {
    //   // ------------------------------------------------------------
    //   // 1) Parse Initial Packet
    //   // ------------------------------------------------------------
    //   final pkt = QuicInitialPacket.parse(dg.data);
    //   print("Quic packet: $pkt");

    //   // ✅ Track PN for multi-range ACK
    //   receivedPns.add(pkt.packetNumber);
    //   if (pkt.packetNumber > largestReceived) {
    //     largestReceived = pkt.packetNumber;
    //   }

    //   final v = Version.fromValue(0x00000001);

    //   final (serverSealer, serverOpener) = newInitialAEAD(
    //     pkt.dcid,
    //     Perspective.server,
    //     v,
    //   );

    //   serverOpener.open(cipherText, pn, ad)

    //   // ------------------------------------------------------------
    //   // 2) Derive initial secrets (read side)
    //   // ------------------------------------------------------------
    //   // final (clientSecret, serverSecret) = computeSecrets(pkt.dcid, v);
    //   // expect(clientSecret, equals(tt['expectedClientSecret']));

    //   // final (key, iv) = computeInitialKeyAndIV(serverSecret, v);

    //   // final trafficSecret = key;
    //   // final label = hkdfHeaderProtectionLabel(v);

    //   // final hpKey = hkdfExpandLabel(
    //   //   secret: trafficSecret,
    //   //   context: Uint8List(0),
    //   //   label: label,
    //   //   length: 16,
    //   // );
    //   // print(
    //   //   "key: ${HEX.encode(key)}, iv: ${HEX.encode(iv)}, hpkey: ${HEX.encode(hpKey)}",
    //   // );
    //   final initSecrets = quicDeriveInitialSecrets(
    //     dcid: pkt.dcid,
    //     version: 0x00000001,
    //     forRead: true,
    //   );

    //   print("Initial secrets: $initSecrets");

    //   final plaintext = quicAeadDecrypt(
    //     key: key,
    //     iv: iv,
    //     packetNumber: pkt.packetNumber,
    //     ciphertextWithTag: pkt.payload,
    //     aad: Uint8List(0),
    //   );

    //   if (plaintext == null) {
    //     print("❌ Initial AEAD decrypt failed");
    //     return;
    //   }

    //   // ------------------------------------------------------------
    //   // 3) Extract CRYPTO(ClientHello)
    //   // ------------------------------------------------------------
    //   final br = ByteReader(plaintext);
    //   if (br.readUint8() != 0x06) return;

    //   br.readUint8(); // offset
    //   final len = br.readUint8();
    //   final chBytes = br.readBytes(len);

    //   transcript.add(chBytes);

    //   final ch = ClientHello.deserialize(ByteReader(chBytes));
    //   final clientPub = ch.parsedExtensions
    //       .whereType<ClientHelloKeyShare>()
    //       .first
    //       .keyExchange;

    //   // ------------------------------------------------------------
    //   // ✅ SEND ACK FOR CLIENT INITIAL
    //   // ------------------------------------------------------------
    //   final ackFrame = buildAckFromSet(
    //     receivedPns,
    //     ackDelayMicros: 0,
    //     ect0: 0,
    //     ect1: 0,
    //     ce: 0,
    //   );

    //   final ackBytes = ackFrame.encode();
    //   final ackCrypto = buildCryptoFrame(ackBytes);

    //   final ackCiphertext = quicAeadEncrypt(
    //     key: quicDeriveInitialSecrets(
    //       dcid: pkt.dcid,
    //       version: 0x00000001,
    //       forRead: false,
    //     ).key,
    //     iv: quicDeriveInitialSecrets(
    //       dcid: pkt.dcid,
    //       version: 0x00000001,
    //       forRead: false,
    //     ).iv,
    //     packetNumber: 1,
    //     plaintext: ackCrypto,
    //     aad: Uint8List(0),
    //   );

    //   if (ackCiphertext != null) {
    //     final ackPacket = buildInitialPacket(
    //       dcid: pkt.scid,
    //       scid: pkt.dcid,
    //       packetNumber: 1,
    //       payload: ackCiphertext,
    //     );
    //     socket.send(ackPacket, dg.address, dg.port);
    //     print("✅ Sent ACK for Client Initial");
    //   }

    //   // ------------------------------------------------------------
    //   // 4) X25519 Key Exchange
    //   // ------------------------------------------------------------
    //   final serverKP = QuicKeyPair.generate();
    //   final sharedSecret = serverKP.exchange(clientPub);

    //   // ------------------------------------------------------------
    //   // 5) Build and Send ServerHello
    //   // ------------------------------------------------------------
    //   final sh = ServerHello.buildForQuic(
    //     keySharePublic: serverKP.publicKey,
    //     cipherSuite: CipherSuite.aes128gcm,
    //   );

    //   final shBytes = sh.serialize();
    //   transcript.add(shBytes);

    //   final shCrypto = buildCryptoFrame(shBytes);

    //   final initialWrite = quicDeriveInitialSecrets(
    //     dcid: pkt.dcid,
    //     version: 0x00000001,
    //     forRead: false,
    //   );

    //   final shCiphertext = quicAeadEncrypt(
    //     key: initialWrite.key,
    //     iv: initialWrite.iv,
    //     packetNumber: 2,
    //     plaintext: shCrypto,
    //     aad: Uint8List(0),
    //   );

    //   final initialPacket = buildInitialPacket(
    //     dcid: pkt.scid,
    //     scid: pkt.dcid,
    //     packetNumber: 2,
    //     payload: shCiphertext!,
    //   );

    //   socket.send(initialPacket, dg.address, dg.port);
    //   print("✅ Sent ServerHello");

    //   // ------------------------------------------------------------
    //   // 6) Derive Handshake Secrets
    //   // ------------------------------------------------------------
    //   final helloHash = createHash(_concat(transcript));

    //   final handshakeSecret = hkdfExtract(
    //     Uint8List(helloHash.length),
    //     salt: helloHash,
    //   );

    //   final serverHsTS = quicHkdfExpandLabel(
    //     secret: handshakeSecret,
    //     label: "s hs traffic",
    //     context: helloHash,
    //     length: 32,
    //   );

    //   final serverHsKey = quicHkdfExpandLabel(
    //     secret: serverHsTS,
    //     label: "key",
    //     context: Uint8List(0),
    //     length: 16,
    //   );

    //   final serverHsIv = quicHkdfExpandLabel(
    //     secret: serverHsTS,
    //     label: "iv",
    //     context: Uint8List(0),
    //     length: 12,
    //   );

    //   // ------------------------------------------------------------
    //   // 7) EE, Cert, CertVerify, Finished
    //   // ------------------------------------------------------------
    //   final ee = EncryptedExtensions.build();
    //   transcript.add(ee);

    //   final certMsg = buildCertificateMessage(cert.cert);
    //   transcript.add(certMsg);

    //   final certHash = createHash(_concat(transcript));
    //   final certVerify = buildCertificateVerify(
    //     privateKeyBytes: cert.privateKey,
    //     transcriptHash: certHash,
    //   );
    //   transcript.add(certVerify);

    //   final finHash = createHash(_concat(transcript));
    //   final finishedKey = quicHkdfExpandLabel(
    //     secret: serverHsTS,
    //     label: "finished",
    //     context: Uint8List(0),
    //     length: 32,
    //   );
    //   final fin = FinishedMessage.build(
    //     finishedKey: finishedKey,
    //     transcriptHash: finHash,
    //   );
    //   transcript.add(fin);

    //   // ------------------------------------------------------------
    //   // 8) Send Handshake packet
    //   // ------------------------------------------------------------
    //   final hsFlight = _concat([ee, certMsg, certVerify, fin]);
    //   final hsCrypto = buildCryptoFrame(hsFlight);

    //   final hsCiphertext = quicAeadEncrypt(
    //     key: serverHsKey,
    //     iv: serverHsIv,
    //     packetNumber: 1,
    //     plaintext: hsCrypto,
    //     aad: Uint8List(0),
    //   );

    //   final hsPacket = buildHandshakePacket(
    //     dcid: pkt.scid,
    //     scid: pkt.dcid,
    //     packetNumber: 1,
    //     payload: hsCiphertext!,
    //   );

    //   socket.send(hsPacket, dg.address, dg.port);
    //   print("✅ Sent EE + Certificate + CertVerify + Finished");
    // } catch (e, st) {
    //   print("❌ QUIC Handshake Error: $e");
    //   print(st);
    // }
  }
}

// ================================================================
// Entry
// ================================================================
void main() async {
  final sock = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 4433);
  QuicServerB(sock).start();
}
