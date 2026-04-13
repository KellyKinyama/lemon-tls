// quic_server_option_b.dart
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

// QUIC cryptography
import 'package:hex/hex.dart';
import 'package:lemon_tls/quic/packet/payload_parser.dart';
import 'package:lemon_tls/quic/packet/protocol.dart';
import 'package:lemon_tls/quic/utils.dart';

import 'buffer.dart';
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
class QuicClient {
  final RawDatagramSocket socket;

  QUICSession? myQuicSession;

  late final EcdsaCert cert;
  final transcript = <Uint8List>[];

  // ✅ ACK tracking
  int largestReceived = -1;
  final Set<int> receivedPns = {};

  String serverAddress;
  int serverPort;

  final Uint8List? providedServerHsKey;
  final Uint8List? providedServerHsIv;
  final Uint8List? providedServerHsHp;

  final Uint8List? provided1RttKey;
  final Uint8List? provided1RttIv;
  final Uint8List? provided1RttHp;

  QuicClient(
    this.socket, {
    this.myQuicSession,
    required this.serverAddress,
    required this.serverPort,

    this.providedServerHsKey,
    this.providedServerHsIv,
    this.providedServerHsHp,
    this.provided1RttKey,
    this.provided1RttIv,
    this.provided1RttHp,
  }) {
    cert = generateSelfSignedCertificate();
    print("✅ Generated self-signed ECDSA-P256 certificate");
  }

  // void start() {
  //   print("✅ QUIC Option-B server listening on UDP ${socket.port}");

  //   socket.listen((event) {
  //     if (event == RawSocketEvent.read) {
  //       final dg = socket.receive();
  //       if (dg != null) {
  //         // ✅ NEVER PROCESS PACKETS ORIGINATING FROM OUR OWN SOCKET
  //         if (dg.port == socket.port) {
  //           // This is a self-sent packet → ignore it
  //           print("⚠️ Ignoring self-received packet (loopback).");
  //           return;
  //         }

  //         _onPacket(dg);
  //       }
  //     }
  //   });
  // }

  void start() {
    print(
      "Initiating QUIC Handshake with DCID: ${HEX.encode(myQuicSession!.dcid)}",
    );

    socket.listen((event) {
      if (event == RawSocketEvent.read) {
        final dg = socket.receive();
        if (dg != null) {
          // ✅ NEVER PROCESS PACKETS ORIGINATING FROM OUR OWN SOCKET
          if (dg.address.address != serverAddress || dg.port != serverPort) {
            return;
          }

          _onPacket(dg);
        }
      }
    });

    // 1) Build the TLS ClientHello
    final ch = myQuicSession!.buildInitialClientHello("localhost");
    final tlsPayload = ch.build_tls_client_hello2();

    // ✅ REQUIRED for handshake transcript
    myQuicSession!.clientHello = ch;
    myQuicSession!.clientHelloRaw = tlsPayload;

    // 2) Wrap TLS payload into a QUIC CRYPTO frame
    // Frame: 0x06 | Offset(varint) | Length(varint) | Data
    final cryptoFrame = QuicBuffer()
      ..pushVarint(0x06)
      ..pushVarint(0)
      ..pushVarint(tlsPayload.length)
      ..pushBytes(tlsPayload);

    final plaintextPayload = cryptoFrame.toBytes();

    // 3) Derive Initial keys from client's chosen DCID (QUIC v1)
    final (clientSecret, serverSecret) = computeSecrets(
      myQuicSession!.dcid,
      Version.fromValue(1),
    );

    // Read = server secret (to read server->client Initial)
    final (readKey, readIv, readHp) = computeInitialKeyAndIV(
      serverSecret,
      Version.fromValue(1),
    );
    myQuicSession!.initialRead = InitialKeys(
      key: readKey,
      iv: readIv,
      hp: readHp,
    );

    // Write = client secret (to write client->server Initial)
    final (writeKey, writeIv, writeHp) = computeInitialKeyAndIV(
      clientSecret,
      Version.fromValue(1),
    );
    myQuicSession!.initialWrite = InitialKeys(
      key: writeKey,
      iv: writeIv,
      hp: writeHp,
    );

    // Install provided handshake keys (if any)
    if (providedServerHsKey != null &&
        providedServerHsIv != null &&
        providedServerHsHp != null) {
      myQuicSession!.handshakeRead = HandshakeKeys(
        key: providedServerHsKey!,
        iv: providedServerHsIv!,
        hp: providedServerHsHp!,
      );
    }

    // 4) Encrypt + header-protect an Initial packet using encryptQuicPacket()
    final packetNumber = 0;

    // Client-chosen SCID (can be any length up to 20; keep 8 for simplicity)
    final scid = Uint8List.fromList(const [
      0x11,
      0x22,
      0x33,
      0x44,
      0x55,
      0x66,
      0x77,
      0x88,
    ]);

    // Token is empty for first Initial
    final token = Uint8List(0);

    final initialPacket = encryptQuicPacket(
      'initial',
      plaintextPayload, // frames (CRYPTO frame), not raw TLS record
      writeKey,
      writeIv,
      writeHp,
      packetNumber,
      myQuicSession!.dcid, // DCID used for initial secrets
      scid,
      token,
    );

    if (initialPacket == null) {
      throw StateError('encryptQuicPacket(initial) failed');
    }

    // 5) Pad to at least 1200 bytes (QUIC Initial anti-amplification)
    final datagram = initialPacket.length >= 1200
        ? initialPacket
        : (Uint8List(1200)..setAll(0, initialPacket));

    // 6) Send
    socket.send(datagram, InternetAddress(serverAddress), serverPort);

    print(
      "🚀 Client Initial (${datagram.length} bytes) sent to ${myQuicSession!.address}:${myQuicSession!.port}",
    );
  }

  // void _receivingQuicPacket(InternetAddress address, int port, Uint8List msg) {
  //   if (msg.isEmpty) {
  //     print("empty message");
  //     return;
  //   }

  //   // Client-side receive path: ONLY decrypt + parse what the server sent.
  //   // Do NOT generate ACK/ServerHello/Handshake flights here.

  //   final decrypted = decryptQuicPacket(
  //     msg,
  //     myQuicSession!.initialRead!.key,
  //     myQuicSession!.initialRead!.iv,
  //     myQuicSession!.initialRead!.hp,
  //     myQuicSession!.dcid, // Used for short header parsing (if encountered)
  //     largestReceived < 0 ? 0 : largestReceived,
  //   );

  //   if (decrypted == null || decrypted.plaintext == null) {
  //     print("❌ Failed to decrypt incoming QUIC packet");
  //     return;
  //   }

  //   largestReceived = math.max(largestReceived, decrypted.packetNumber);
  //   receivedPns.add(decrypted.packetNumber);

  //   // Parse frames (CRYPTO etc.) and let the session handle them.
  //   // This is where you should process ServerHello, EE, Certificate, Finished, etc.
  //   myQuicSession!.handleDecryptedPacket(decrypted.plaintext!);
  // }

  void _receivingQuicPacket(InternetAddress address, int port, Uint8List msg) {
    if (msg.isEmpty) {
      print("empty message");
      return;
    }

    // ✅ Use the new decryptQuicPacket signature
    final decrypted = decryptQuicPacket(
      msg,
      myQuicSession!, // <-- pass the whole session
      largestReceived < 0 ? 0 : largestReceived,
    );

    if (decrypted == null || decrypted.plaintext == null) {
      print("❌ Failed to decrypt incoming QUIC packet");
      return;
    }

    // ✅ Track PNs for ACK logic
    largestReceived = math.max(largestReceived, decrypted.packetNumber);
    receivedPns.add(decrypted.packetNumber);

    // ✅ Feed decrypted CRYPTO to the QUIC/TLS handler
    myQuicSession!.handleDecryptedPacket(decrypted.plaintext!);
  }

  void _onPacket(Datagram dg) {
    print('📩 Received UDP datagram (${dg.data.length} bytes)');

    final packetList = splitCoalescedPackets(dg.data);

    print("🔍 Found ${packetList.length} QUIC packets in datagram");

    for (final pkt in packetList) {
      _receivingQuicPacket(dg.address, dg.port, pkt);
    }

    print('✅ Finished processing coalesced datagram\n');
  }

  //   void _onPacket(Datagram dg) {
  //     print('processing packet:');
  //     _receivingQuicPacket(dg.address, dg.port, dg.data);
  //     print('processing packet finished');
  //     // try {
  //     //   // ------------------------------------------------------------
  //     //   // 1) Parse Initial Packet
  //     //   // ------------------------------------------------------------
  //     //   final pkt = QuicInitialPacket.parse(dg.data);
  //     //   print("Quic packet: $pkt");

  //     //   // ✅ Track PN for multi-range ACK
  //     //   receivedPns.add(pkt.packetNumber);
  //     //   if (pkt.packetNumber > largestReceived) {
  //     //     largestReceived = pkt.packetNumber;
  //     //   }

  //     //   final v = Version.fromValue(0x00000001);

  //     //   final (serverSealer, serverOpener) = newInitialAEAD(
  //     //     pkt.dcid,
  //     //     Perspective.server,
  //     //     v,
  //     //   );

  //     //   serverOpener.open(cipherText, pn, ad)

  //     //   // ------------------------------------------------------------
  //     //   // 2) Derive initial secrets (read side)
  //     //   // ------------------------------------------------------------
  //     //   // final (clientSecret, serverSecret) = computeSecrets(pkt.dcid, v);
  //     //   // expect(clientSecret, equals(tt['expectedClientSecret']));

  //     //   // final (key, iv) = computeInitialKeyAndIV(serverSecret, v);

  //     //   // final trafficSecret = key;
  //     //   // final label = hkdfHeaderProtectionLabel(v);

  //     //   // final hpKey = hkdfExpandLabel(
  //     //   //   secret: trafficSecret,
  //     //   //   context: Uint8List(0),
  //     //   //   label: label,
  //     //   //   length: 16,
  //     //   // );
  //     //   // print(
  //     //   //   "key: ${HEX.encode(key)}, iv: ${HEX.encode(iv)}, hpkey: ${HEX.encode(hpKey)}",
  //     //   // );
  //     //   final initSecrets = quicDeriveInitialSecrets(
  //     //     dcid: pkt.dcid,
  //     //     version: 0x00000001,
  //     //     forRead: true,
  //     //   );

  //     //   print("Initial secrets: $initSecrets");

  //     //   final plaintext = quicAeadDecrypt(
  //     //     key: key,
  //     //     iv: iv,
  //     //     packetNumber: pkt.packetNumber,
  //     //     ciphertextWithTag: pkt.payload,
  //     //     aad: Uint8List(0),
  //     //   );

  //     //   if (plaintext == null) {
  //     //     print("❌ Initial AEAD decrypt failed");
  //     //     return;
  //     //   }

  //     //   // ------------------------------------------------------------
  //     //   // 3) Extract CRYPTO(ClientHello)
  //     //   // ------------------------------------------------------------
  //     //   final br = ByteReader(plaintext);
  //     //   if (br.readUint8() != 0x06) return;

  //     //   br.readUint8(); // offset
  //     //   final len = br.readUint8();
  //     //   final chBytes = br.readBytes(len);

  //     //   transcript.add(chBytes);

  //     //   final ch = ClientHello.deserialize(ByteReader(chBytes));
  //     //   final clientPub = ch.parsedExtensions
  //     //       .whereType<ClientHelloKeyShare>()
  //     //       .first
  //     //       .keyExchange;

  //     //   // ------------------------------------------------------------
  //     //   // ✅ SEND ACK FOR CLIENT INITIAL
  //     //   // ------------------------------------------------------------
  //     //   final ackFrame = buildAckFromSet(
  //     //     receivedPns,
  //     //     ackDelayMicros: 0,
  //     //     ect0: 0,
  //     //     ect1: 0,
  //     //     ce: 0,
  //     //   );

  //     //   final ackBytes = ackFrame.encode();
  //     //   final ackCrypto = buildCryptoFrame(ackBytes);

  //     //   final ackCiphertext = quicAeadEncrypt(
  //     //     key: quicDeriveInitialSecrets(
  //     //       dcid: pkt.dcid,
  //     //       version: 0x00000001,
  //     //       forRead: false,
  //     //     ).key,
  //     //     iv: quicDeriveInitialSecrets(
  //     //       dcid: pkt.dcid,
  //     //       version: 0x00000001,
  //     //       forRead: false,
  //     //     ).iv,
  //     //     packetNumber: 1,
  //     //     plaintext: ackCrypto,
  //     //     aad: Uint8List(0),
  //     //   );

  //     //   if (ackCiphertext != null) {
  //     //     final ackPacket = buildInitialPacket(
  //     //       dcid: pkt.scid,
  //     //       scid: pkt.dcid,
  //     //       packetNumber: 1,
  //     //       payload: ackCiphertext,
  //     //     );
  //     //     socket.send(ackPacket, dg.address, dg.port);
  //     //     print("✅ Sent ACK for Client Initial");
  //     //   }

  //     //   // ------------------------------------------------------------
  //     //   // 4) X25519 Key Exchange
  //     //   // ------------------------------------------------------------
  //     //   final serverKP = QuicKeyPair.generate();
  //     //   final sharedSecret = serverKP.exchange(clientPub);

  //     //   // ------------------------------------------------------------
  //     //   // 5) Build and Send ServerHello
  //     //   // ------------------------------------------------------------
  //     //   final sh = ServerHello.buildForQuic(
  //     //     keySharePublic: serverKP.publicKey,
  //     //     cipherSuite: CipherSuite.aes128gcm,
  //     //   );

  //     //   final shBytes = sh.serialize();
  //     //   transcript.add(shBytes);

  //     //   final shCrypto = buildCryptoFrame(shBytes);

  //     //   final initialWrite = quicDeriveInitialSecrets(
  //     //     dcid: pkt.dcid,
  //     //     version: 0x00000001,
  //     //     forRead: false,
  //     //   );

  //     //   final shCiphertext = quicAeadEncrypt(
  //     //     key: initialWrite.key,
  //     //     iv: initialWrite.iv,
  //     //     packetNumber: 2,
  //     //     plaintext: shCrypto,
  //     //     aad: Uint8List(0),
  //     //   );

  //     //   final initialPacket = buildInitialPacket(
  //     //     dcid: pkt.scid,
  //     //     scid: pkt.dcid,
  //     //     packetNumber: 2,
  //     //     payload: shCiphertext!,
  //     //   );

  //     //   socket.send(initialPacket, dg.address, dg.port);
  //     //   print("✅ Sent ServerHello");

  //     //   // ------------------------------------------------------------
  //     //   // 6) Derive Handshake Secrets
  //     //   // ------------------------------------------------------------
  //     //   final helloHash = createHash(_concat(transcript));

  //     //   final handshakeSecret = hkdfExtract(
  //     //     Uint8List(helloHash.length),
  //     //     salt: helloHash,
  //     //   );

  //     //   final serverHsTS = quicHkdfExpandLabel(
  //     //     secret: handshakeSecret,
  //     //     label: "s hs traffic",
  //     //     context: helloHash,
  //     //     length: 32,
  //     //   );

  //     //   final serverHsKey = quicHkdfExpandLabel(
  //     //     secret: serverHsTS,
  //     //     label: "key",
  //     //     context: Uint8List(0),
  //     //     length: 16,
  //     //   );

  //     //   final serverHsIv = quicHkdfExpandLabel(
  //     //     secret: serverHsTS,
  //     //     label: "iv",
  //     //     context: Uint8List(0),
  //     //     length: 12,
  //     //   );

  //     //   // ------------------------------------------------------------
  //     //   // 7) EE, Cert, CertVerify, Finished
  //     //   // ------------------------------------------------------------
  //     //   final ee = EncryptedExtensions.build();
  //     //   transcript.add(ee);

  //     //   final certMsg = buildCertificateMessage(cert.cert);
  //     //   transcript.add(certMsg);

  //     //   final certHash = createHash(_concat(transcript));
  //     //   final certVerify = buildCertificateVerify(
  //     //     privateKeyBytes: cert.privateKey,
  //     //     transcriptHash: certHash,
  //     //   );
  //     //   transcript.add(certVerify);

  //     //   final finHash = createHash(_concat(transcript));
  //     //   final finishedKey = quicHkdfExpandLabel(
  //     //     secret: serverHsTS,
  //     //     label: "finished",
  //     //     context: Uint8List(0),
  //     //     length: 32,
  //     //   );
  //     //   final fin = FinishedMessage.build(
  //     //     finishedKey: finishedKey,
  //     //     transcriptHash: finHash,
  //     //   );
  //     //   transcript.add(fin);

  //     //   // ------------------------------------------------------------
  //     //   // 8) Send Handshake packet
  //     //   // ------------------------------------------------------------
  //     //   final hsFlight = _concat([ee, certMsg, certVerify, fin]);
  //     //   final hsCrypto = buildCryptoFrame(hsFlight);

  //     //   final hsCiphertext = quicAeadEncrypt(
  //     //     key: serverHsKey,
  //     //     iv: serverHsIv,
  //     //     packetNumber: 1,
  //     //     plaintext: hsCrypto,
  //     //     aad: Uint8List(0),
  //     //   );

  //     //   final hsPacket = buildHandshakePacket(
  //     //     dcid: pkt.scid,
  //     //     scid: pkt.dcid,
  //     //     packetNumber: 1,
  //     //     payload: hsCiphertext!,
  //     //   );

  //     //   socket.send(hsPacket, dg.address, dg.port);
  //     //   print("✅ Sent EE + Certificate + CertVerify + Finished");
  //     // } catch (e, st) {
  //     //   print("❌ QUIC Handshake Error: $e");
  //     //   print(st);
  //     // }
  //   }
}

/// Parse *multiple* QUIC packets inside one UDP datagram.
/// Returns a list of fully parsed packet blobs extracted from [data].
// List<Uint8List> splitCoalescedPackets(Uint8List data) {
//   final packets = <Uint8List>[];
//   int i = 0;

//   while (i < data.length) {
//     if (i + 1 >= data.length) break;

//     final header = data[i];

//     // ✅ Long Header (Initial / Handshake / 0-RTT)
//     if ((header & 0x80) != 0) {
//       if (i + 5 > data.length) break;

//       final version = data.sublist(i + 1, i + 5);
//       final dcidLen = data[i + 5];

//       int pos = i + 6;
//       if (pos + dcidLen > data.length) break;

//       pos += dcidLen;
//       if (pos >= data.length) break;

//       final scidLen = data[pos];
//       pos += 1;
//       if (pos + scidLen > data.length) break;
//       pos += scidLen;

//       // TOKEN length (varint)
//       if (pos >= data.length) break;
//       final tokenLen = data[pos];
//       pos += 1 + tokenLen;

//       // packet_length (1 byte for now – real QUIC uses varint)
//       if (pos >= data.length) break;
//       final payloadLen = data[pos];
//       pos++;

//       final pn = data[pos]; // ignore, PN encrypted anyway
//       pos++;

//       final payloadStart = pos;
//       final payloadEnd = pos + payloadLen;
//       if (payloadEnd > data.length) break;

//       final pkt = data.sublist(i, payloadEnd);
//       packets.add(pkt);

//       i = payloadEnd;
//     }
//     // ✅ Short header (1-RTT etc.)
//     else {
//       // Short header always extends to the end of datagram (no explicit length)
//       packets.add(data.sublist(i));
//       break;
//     }
//   }

//   return packets;
// }

// --- QUIC varint parser ---
(int value, int bytesRead) parseVarInt(Uint8List data, int start) {
  final first = data[start];

  if (first < 0x40) {
    return (first, 1); // 1‑byte
  } else if (first < 0x80) {
    final v = ((first & 0x3f) << 8) | data[start + 1];
    return (v, 2); // 2‑byte
  } else if (first < 0xC0) {
    final v =
        ((first & 0x3f) << 24) |
        (data[start + 1] << 16) |
        (data[start + 2] << 8) |
        data[start + 3];
    return (v, 4); // 4‑byte
  } else {
    final v =
        ((first & 0x3f) << 56) |
        (data[start + 1] << 48) |
        (data[start + 2] << 40) |
        (data[start + 3] << 32) |
        (data[start + 4] << 24) |
        (data[start + 5] << 16) |
        (data[start + 6] << 8) |
        data[start + 7];
    return (v, 8); // 8‑byte
  }
}

// --- FIXED coalesced packet splitter ---
List<Uint8List> splitCoalescedPackets(Uint8List buf) {
  final out = <Uint8List>[];
  int i = 0;

  while (i < buf.length) {
    // Need at least 5 bytes for long header
    if (i + 5 > buf.length) break;

    final flags = buf[i];
    final isLong = (flags & 0x80) != 0;

    if (isLong) {
      int p = i + 1;

      // ---- Version (4 bytes) ----
      if (p + 4 > buf.length) break;
      p += 4;

      // ---- DCID ----
      if (p >= buf.length) break;
      final dcidLen = buf[p++];
      if (p + dcidLen > buf.length) break;
      p += dcidLen;

      // ---- SCID ----
      if (p >= buf.length) break;
      final scidLen = buf[p++];
      if (p + scidLen > buf.length) break;
      p += scidLen;

      // ---- Token Length (ONLY Initial packets) ----
      final packetType = (flags >> 4) & 0x03;

      if (packetType == 0x00) {
        // Initial packet → token field present
        final token = readVarInt(buf, p);
        if (token == null) break;

        p += token.byteLength;

        if (p + token.value > buf.length) break;
        p += token.value;
      }

      // ---- Length field (varint) ----
      final lengthField = readVarInt(buf, p);
      if (lengthField == null) break;

      final payloadLen = lengthField.value;
      p += lengthField.byteLength;

      // ---- Bounds check to avoid RangeError ----
      final pktEnd = p + payloadLen;
      if (pktEnd > buf.length) {
        throw RangeError(
          "QUIC long header claims payload length $payloadLen but only "
          "${buf.length - p} bytes remain",
        );
      }

      // ---- Extract packet ----
      out.add(buf.sublist(i, pktEnd));

      // Move to next packet
      i = pktEnd;
      continue;
    }

    // ------------------------------
    // Short header → runs to end of UDP datagram
    // ------------------------------
    out.add(buf.sublist(i));
    break;
  }

  return out;
}

// ================================================================
// Entry
// ================================================================
void main() async {
  final sock = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);

  final dcid = Uint8List.fromList(
    List.generate(8, (i) => math.Random().nextInt(255)),
  ); // 0001020304050607

  QuicClient(
    sock,
    myQuicSession: QUICSession(
      dcid: dcid,
      address: "127.0.0.1",
      port: sock.port,
    ),
    serverAddress: "127.0.0.1",
    serverPort: 4433,
  ).start();
}
