// quic_server_option_b.dart
import 'dart:io';
import 'dart:typed_data';

// QUIC cryptography
import 'package:hex/hex.dart';
import 'package:lemon_tls/quic/packet/payload_parser.dart';
import 'package:lemon_tls/quic/packet/protocol.dart';

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

import 'initialial_aead.dart';
import 'packet/quic_packet.dart';
import 'quic_crypto.dart';
import 'quic_ack.dart';
import 'tls_crypto.dart'; // ✅ NEW
// (initial secrets now handled by quic_crypto.dart)

class QUICSession {
  final Uint8List dcid;
  final String address;
  final int port;
  // State for keys, stream limits, largest PN, etc., would be managed here.

  QUICSession({required this.dcid, required this.address, required this.port});

  // Mock method to simulate processing decrypted frames
  void handleDecryptedPacket(Uint8List plaintext) {
    // In a full implementation, this calls the frame parser and stream handlers.
    print(
      'Session ${HEX.encode(dcid)} received ${plaintext.length} bytes of plaintext.',
    );

    parsePayload(plaintext);
  }
}

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
    socket.listen((ev) {
      if (ev == RawSocketEvent.read) {
        final dg = socket.receive();
        if (dg != null) _onPacket(dg);
      }
    });
  }

  void _receivingQuicPacket(InternetAddress address, int port, Uint8List msg) {
    if (msg.isEmpty) {
      print("empty message");
      return;
    }

    print('\n--- Parsing the QU-IC Initial Packet with Debugging ---');
    final mutablePacket = Uint8List.fromList(msg);
    // final mutablePacket = splitHexString(
    //   "c1000000010008f067a5502a4262b50040750001",
    // );
    final buffer = mutablePacket.buffer;
    int offset = 1 + 4; // Skip first byte and version
    // DEBUG: Print initial state
    print('DEBUG: Starting offset: $offset');

    final dcidLen = mutablePacket[offset];
    offset += 1;
    final dcid = Uint8List.view(buffer, offset, dcidLen);
    offset += dcidLen;
    // DEBUG: Verify the most critical piece of info: the DCID
    print('DEBUG: Parsed DCID Length: $dcidLen');
    print(
      'DEBUG: Parsed DCID (Hex): ${HEX.encode(dcid)}, expeceted: 0001020304050607',
    );
    print('DEBUG: Offset after DCID: $offset');

    final scidLen = mutablePacket[offset];
    offset += 1;
    final scid = Uint8List.view(buffer, offset, scidLen);
    offset += scidLen;
    // DEBUG: Verify the most critical piece of info: the DCID
    print('DEBUG: Parsed SCID Length: $scidLen');
    print('DEBUG: Parsed SCID (Hex): ${HEX.encode(scid)}');
    print('DEBUG: Offset after SCID: $offset');

    final firstByte = msg[0];
    final isLongHeader = (firstByte & 0x80) != 0;

    // Uint8List dcid;
    String dcidHex = HEX.encode(dcid);

    // The complexity of QUIC headers requires careful parsing, especially for Long Headers.
    if (isLongHeader) {
      print(
        'The complexity of QUIC headers requires careful parsing, especially for Long Headers.',
      );
      // Assuming a Long Header: Initial (0xC0-0xC3), R(4 bits) + V(4 bytes) + DCIDL(1 byte) + DCID
      if (msg.length < 7) {
        print('Packet too short for Long Header parsing');
        return;
      }

      // final dcidLen = msg[6];
      // if (dcidLen > 20 || dcidLen == 0) {
      //   print("dcidLen > 20: ${dcidLen > 20}, dcidLen == 0: ${dcidLen == 0}");
      //   return;
      // }
      // // Invalid length

      // dcid = msg.sublist(7, 7 + dcidLen);
      dcidHex = HEX.encode(dcid);

      var quicSession = _quicSessions[dcidHex];

      if (quicSession == null) {
        quicSession = _quicSessions[dcidHex] = QUICSession(
          dcid: dcid,
          address: address.address,
          port: port,
        );
        // Handle new connection (Initial packet)
        if ((firstByte & 0xC0) == 0xC0) {
          final version = ByteData.view(
            msg.buffer,
            msg.offsetInBytes + 1,
            4,
          ).getUint32(0);

          try {
            final (clientSecret, serverSecret) = computeSecrets(
              dcid,
              Version.fromValue(version),
            );
            // expect(clientSecret, equals(tt['expectedClientSecret']));

            final (key, iv, hp) = computeInitialKeyAndIV(
              clientSecret,
              Version.fromValue(version),
            );
            // FIX: Destructure the record returned by quicDeriveInitSecrets
            // final (_, initKeys) = quicDeriveInitSecrets(dcid, version, 'read');
            print("""class QUICKeys {
  key: ${HEX.encode(key)}; // Packet Protection Key
  iv: ${HEX.encode(iv)};
   hp: ${HEX.encode(hp)}; // Header Protection Key""");

            // Decrypt the Initial packet
            final decryptedPacket = decryptQuicPacket(
              mutablePacket,
              key,
              iv,
              hp,
              dcid,
              0, // largestPn for Initial is 0
            );

            if (decryptedPacket != null && decryptedPacket.plaintext != null) {
              print(
                'Successfully decrypted Initial packet. Creating new session.',
              );
              // Session creation and initial handshake response logic goes here.
              // quicSession = QUICSession(
              //   dcid: dcid,
              //   address: address.address,
              //   port: port,
              // );
              // _quicSessions[dcidHex] = quicSession;

              // // Pass the plaintext frames to the session handler
              quicSession!.handleDecryptedPacket(decryptedPacket.plaintext!);
            }
          } catch (e) {
            print('Error processing Initial packet: $e');
            rethrow;
          }
        }
      } else {
        // For existing sessions receiving Handshake/0RTT Long Headers,
        // decryption is required here using the appropriate negotiated keys.
        // For now, we print a warning as the required session state is missing:
        print(
          'WARNING: Received Long Header for existing session. Decryption skipped (missing session key state).',
        );
      }
    } else {
      // Short Header (1RTT)
      // Needs to look up session using the DCID.

      // Placeholder DCID extraction (e.g., assuming first 8 bytes after Type)
      if (msg.length < 9) return;
      // dcid = msg.sublist(1, 9);
      dcidHex = HEX.encode(dcid);

      var quicSession = _quicSessions[dcidHex];
      if (quicSession != null) {
        // FIX: Short Header (1RTT) packets must be decrypted.
        // In a real implementation, the session must provide the 1-RTT read keys and largest PN.
        try {
          // Placeholder keys - Replace with quicSession.oneRttReadKey, etc.
          // Note: These must match the cipher suite lengths (16/12/16 for AES-128-GCM)
          final mockKey = Uint8List(16);
          final mockIv = Uint8List(12);
          final mockHp = Uint8List(16);

          final decryptedPacket = decryptQuicPacket(
            msg,
            mockKey, // Session's current 1-RTT read key
            mockIv, // Session's current 1-RTT read IV
            mockHp, // Session's current 1-RTT read HP key
            dcid,
            0, // Replace with session's largestPn received
          );

          if (decryptedPacket != null && decryptedPacket.plaintext != null) {
            // Pass the plaintext frames to the session handler
            quicSession.handleDecryptedPacket(decryptedPacket.plaintext!);
          } else {
            print('Short Header decryption failed.');
          }
        } catch (e) {
          print('Error processing Short Header packet: $e');
        }
      }
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
