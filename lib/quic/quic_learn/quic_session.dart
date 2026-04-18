import 'dart:io';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:hex/hex.dart';
import 'package:lemon_tls/quic/handshake/server_hello.dart';
import '../cipher/x25519.dart';
import '../frames/quic_frames.dart';
import '../handshake/finished.dart';
import '../handshake/tls_messages.dart';
import '../hash.dart';
import '../quic_ack.dart';
import 'payload_parser.dart';

import '../hkdf.dart';
import '../packet/quic_packet.dart';
import '../utils.dart';

Uint8List buildCryptoFrame(Uint8List data) {
  return Uint8List.fromList([0x06, 0x00, data.length, ...data]);
}

Uint8List _padTo1200(Uint8List pkt) {
  const minInitialSize = 1200;
  if (pkt.length >= minInitialSize) return pkt;
  final out = Uint8List(minInitialSize);
  out.setRange(0, pkt.length, pkt);
  return out;
}

final _bytesEq = const ListEquality<int>();

class AckState {
  final Set<int> received = <int>{};
  int nextPn = 0;

  int allocatePn() => nextPn++;
}

final Map<EncryptionLevel, AckState> ackStates = {
  EncryptionLevel.initial: AckState(),
  EncryptionLevel.handshake: AckState(),
  // 1-RTT can be added later
};

void expectBytesEqual(String name, Uint8List actual, String expectedHex) {
  final expected = Uint8List.fromList(HEX.decode(expectedHex));
  // print("Got $name: ${HEX.encode(actual)}");
  // print("Expected $name: $expectedHex");

  if (!_bytesEq.equals(actual, expected)) {
    throw StateError(
      '$name does not match.\n'
      'Expected: $expectedHex\n'
      'Actual:   ${HEX.encode(actual)}',
    );
  }
}

/// ================================================================
/// Encryption Levels
/// ================================================================
enum EncryptionLevel { initial, handshake, application }

class PacketNumberSpace {
  int largestPn = -1;

  int get referencePn => largestPn < 0 ? 0 : largestPn;

  void onPacketDecrypted(int pn) {
    if (pn > largestPn) {
      largestPn = pn;
    }
  }
}

/// ================================================================
/// QUIC Key Container
/// ================================================================
class QuicKeys {
  final Uint8List key;
  final Uint8List iv;
  final Uint8List hp;

  const QuicKeys({required this.key, required this.iv, required this.hp});

  @override
  String toString() {
    // TODO: implement toString
    return """QuicKeys{
     key: ${HEX.encode(key)};
      iv: ${HEX.encode(iv)};
      hp: ${HEX.encode(hp)};
    }""";
  }
}

class QuicSession {
  Uint8List dcid;

  EncryptionLevel encryptionLevel = EncryptionLevel.initial;

  RawDatagramSocket socket;

  // Keys
  QuicKeys? initialRead, initialWrite;
  QuicKeys? handshakeRead, handshakeWrite;
  QuicKeys? appRead, appWrite;

  /// Packet number spaces
  final _pnSpaces = <EncryptionLevel, PacketNumberSpace>{
    EncryptionLevel.initial: PacketNumberSpace(),
    EncryptionLevel.handshake: PacketNumberSpace(),
    EncryptionLevel.application: PacketNumberSpace(),
  };

  late final Uint8List derivedSecret;

  final peerScid = Uint8List.fromList(HEX.decode("635f636964"));
  final localCid = Uint8List.fromList(HEX.decode("0001020304050607"));
  void sendAck({
    required EncryptionLevel level,
    required String address,
    required int port,
  }) {
    final ackState = ackStates[level];
    if (ackState == null || ackState.received.isEmpty) {
      return;
    }

    final ackFrame = buildAckFromSet(
      ackState.received,
      ackDelayMicros: 0, // Immediate ACK for Initial + Handshake
      ect0: 0,
      ect1: 0,
      ce: 0,
    );

    final ackPayload = ackFrame.encode();
    final pn = ackState.allocatePn();

    // Select correct keys for this encryption level
    final writeKeys = switch (level) {
      EncryptionLevel.initial => initialWrite,
      EncryptionLevel.handshake => handshakeWrite,
      _ => throw StateError("ACK not supported for $level"),
    };

    if (writeKeys == null) {
      throw StateError("Write keys not available for $level");
    }

    // DCID = peer's SCID, SCID = our CID
    final Uint8List dcidToUse = peerScid; // server's CID
    final Uint8List scidToUse = localCid; // our CID

    final rawPacket = encryptQuicPacket(
      level.name,
      ackPayload,
      writeKeys.key,
      writeKeys.iv,
      writeKeys.hp,
      pn,
      dcidToUse,
      scidToUse,
      Uint8List(0), // no tokens
    );

    if (rawPacket == null) {
      print("❌ Failed to encrypt ACK ($level)");
      return;
    }

    final bytesToSend = level == EncryptionLevel.initial
        ? _padTo1200(rawPacket)
        : rawPacket;

    socket.send(bytesToSend, InternetAddress("127.0.0.1"), 4433);

    print(
      "✅ Sent ACK ($level) pn=$pn acked=${ackState.received.toList()..sort()}",
    );
  }

  void sendClientFinished({
    required InternetAddress address,
    required int port,
  }) {
    if (handshakeWrite == null) {
      throw StateError("Handshake write keys not available");
    }

    // =====================================================
    // 1. Compute transcript hash (up to CertificateVerify)
    // =====================================================
    final transcriptHash = createHash(tlsTranscript.toBytes());

    // =====================================================
    // 2. Derive finished_key
    // finished_key =
    // HKDF-Expand-Label(
    //   client_hs_traffic_secret,
    //   "finished",
    //   "",
    //   Hash.length
    // )
    // =====================================================
    final finishedKey = hkdfExpandLabel(
      secret: clientHsTrafficSecret,
      label: "finished",
      context: Uint8List(0),
      length: 32, // SHA-256
    );

    // =====================================================
    // 3. Compute verify_data
    // verify_data = HMAC(finished_key, transcript_hash)
    // =====================================================
    final verifyData = hmacSha256(key: finishedKey, data: transcriptHash);

    // =====================================================
    // 4. Build TLS Finished handshake message
    // HandshakeType.finished = 20 (0x14)
    // =====================================================
    final finishedHandshake = BytesBuilder()
      ..addByte(0x14)
      ..add([
        (verifyData.length >> 16) & 0xff,
        (verifyData.length >> 8) & 0xff,
        verifyData.length & 0xff,
      ])
      ..add(verifyData);

    final finishedBytes = finishedHandshake.toBytes();

    // IMPORTANT: append Finished to transcript AFTER computing verify_data
    // tlsTranscript.add(finishedBytes);

    // =====================================================
    // 5. Wrap in CRYPTO frame (using your helper)
    // =====================================================
    final cryptoPayload = buildCryptoFrame(finishedBytes);

    // =====================================================
    // 6. Allocate packet number (Handshake PN space)
    // =====================================================
    final ackState = ackStates[EncryptionLevel.handshake]!;
    final pn = ackState.allocatePn();

    // =====================================================
    // 7. Encrypt Handshake packet
    // =====================================================
    final rawPacket = encryptQuicPacket(
      "handshake",
      cryptoPayload,
      handshakeWrite!.key,
      handshakeWrite!.iv,
      handshakeWrite!.hp,
      pn,
      peerScid, // DCID = server's CID
      localCid, // SCID = our CID
      Uint8List(0),
    );

    if (rawPacket == null) {
      print("❌ Failed to encrypt Client Finished");
      return;
    }

    // =====================================================
    // 8. Send (NO padding for Handshake packets)
    // =====================================================
    socket.send(rawPacket, address, port);

    print(
      "✅ Sent Client Finished (Handshake) "
      "pn=$pn verify_data=${HEX.encode(verifyData)}",
    );
  }

  /// Traffic keys by level and direction
  final _readKeys = <EncryptionLevel, QuicKeys>{};

  final _writeKeys = <EncryptionLevel, QuicKeys>{};

  final BytesBuilder receivedHandshakeBytes = BytesBuilder();

  late Uint8List clientHsTrafficSecret;

  bool serverFinishedReceived = false;
  bool clientFinishedSent = false;
  bool applicationSecretsDerived = false;

  QuicSession(this.dcid, this.socket) {
    generateSecrets();
    _readKeys[EncryptionLevel.initial] = initialRead!;
  }

  final randomData = Uint8List.fromList(HEX.decode("0001020304050607"));

  List<CryptoFrame> receivedCryptoFrames = [];
  List<TlsHandshakeMessage> receivedTlsMessages = [];

  ServerHello? receivedServello;

  Uint8List privateKeyBytes = Uint8List.fromList(
    HEX.decode(
      "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
    ),
  );

  final Map<EncryptionLevel, Map<int, Uint8List>> cryptoChunksByLevel = {
    EncryptionLevel.initial: <int, Uint8List>{},
    EncryptionLevel.handshake: <int, Uint8List>{},
  };

  final Map<EncryptionLevel, int> cryptoReadOffsetByLevel = {
    EncryptionLevel.initial: 0,
    EncryptionLevel.handshake: 0,
  };

  final BytesBuilder tlsTranscript = BytesBuilder();

  /// Try to assemble contiguous CRYPTO stream bytes.
  /// Returns newly available bytes (may be empty).
  Uint8List assembleCryptoStream(EncryptionLevel level) {
    final chunks = cryptoChunksByLevel[level]!;
    int readOffset = cryptoReadOffsetByLevel[level]!;

    final result = <int>[];

    while (chunks.containsKey(readOffset)) {
      final chunk = chunks.remove(readOffset)!;
      result.addAll(chunk);
      readOffset += chunk.length;
    }

    cryptoReadOffsetByLevel[level] = readOffset;
    return Uint8List.fromList(result);
  }

  void onDecryptedPacket(
    QuicDecryptedPacket decryptedPacket,
    EncryptionLevel level,
    InternetAddress address,
    int port,
  ) {
    // ✅ Track packet number in the correct ACK space
    final ackState = ackStates[level];
    if (ackState == null) {
      return;
    }

    ackState.received.add(decryptedPacket.packetNumber);

    // ✅ Immediate ACK for Initial + Handshake
    if (level == EncryptionLevel.initial ||
        level == EncryptionLevel.handshake) {
      sendAck(level: level, address: address.address, port: port);
    }
  }

  // helloHash: 20df6b6164e17b874575a7636338ac7f178c99c758cd0026697eec31148a3bf8
  // clientHsTrafficSecret: 015fe2b1c2da4eff4395cd48464eefd8d3ca386c6f6910b7581b0e27c78beb9d
  // serverHsTrafficSecret: 4c091e2cc1f05d78a558635e7b4645d3958e0dbaf2d60a118b908471fc75af31

  //0579f5914e897dba7711d43171b38dfd7ef8a11beadec89beefab916aa760b7f
  // Uint8List testHash() {
  //   final clientHello = Uint8List.fromList(
  //     HEX.decode(
  //       "01 00 00 ea 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 00 06 13 01 13 02 13 03 01 00 00 bb 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 08 00 06 00 1d 00 17 00 18 00 10 00 0b 00 09 08 70 69 6e 67 2f 31 2e 30 00 0d 00 14 00 12 04 03 08 04 04 01 05 03 08 05 05 01 08 06 06 01 02 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54 00 2d 00 02 01 01 00 2b 00 03 02 03 04 00 39 00 31 03 04 80 00 ff f7 04 04 80 a0 00 00 05 04 80 10 00 00 06 04 80 10 00 00 07 04 80 10 00 00 08 01 0a 09 01 0a 0a 01 03 0b 01 19 0f 05 63 5f 63 69 64",
  //     ),
  //   );
  //   final serverHello =
  //       receivedTlsMessages.firstWhere((test) => test is ServerHello)
  //           as ServerHello;

  //   final bodyBytes = serverHello.rawBytes!;
  //   final header = Uint8List(4);
  //   header[0] = 0x02; // ✅ ServerHello

  //   // Set 24-bit length (Big Endian)
  //   header[1] = (bodyBytes.length >> 16) & 0xFF;
  //   header[2] = (bodyBytes.length >> 8) & 0xFF;
  //   header[3] = bodyBytes.length & 0xFF;
  //   final data = Uint8List.fromList([
  //     ...clientHello,
  //     // ...header,
  //     ...serverHello.rawBytes!,
  //   ]);

  //   print("Hashing ClientHello + ServerHello: ${HEX.encode(data)}");
  //   final hash = createHash(data);
  //   // expectBytesEqual(
  //   //   "SHA-256 hash of ClientHello + ServerHello",
  //   //   hash,
  //   //   "ff788f9ed09e60d8142ac10a8931cdb6a3726278d3acdba54d9d9ffc7326611b",
  //   // );
  //   print("✅ SHA-256 hash verified");
  //   return hash;
  // }

  Uint8List transcriptThroughServerHandshake() {
    return Uint8List.fromList([
      ...clientHelloBytes,
      ...tlsTranscript.toBytes(),
    ]);
  }

  Uint8List testHash() {
    final transcript = transcriptThroughServerHandshake();

    print("Hashing ClientHello + ServerHello: ${HEX.encode(transcript)}");

    final hash = createHash(transcript);
    print("helloHash: ${HEX.encode(hash)}");
    return hash;
  }

  Uint8List extractServerHelloFromCrypto(Uint8List cryptoStream) {
    if (cryptoStream.length < 4) {
      throw StateError("CRYPTO stream too short for Handshake header");
    }

    final msgType = cryptoStream[0];
    if (msgType != 0x02) {
      throw StateError("First handshake message is not ServerHello");
    }

    final length =
        (cryptoStream[1] << 16) | (cryptoStream[2] << 8) | cryptoStream[3];

    final totalLen = 4 + length;

    if (cryptoStream.length < totalLen) {
      throw StateError("CRYPTO stream truncated ServerHello");
    }

    return cryptoStream.sublist(0, totalLen);
  }

  // QuicDecryptedPacket decryptPacket(Uint8List packet, EncryptionLevel level) {
  //   final keys = _readKeys[level];
  //   if (keys == null) {
  //     throw StateError('No keys for $level');
  //   }

  //   final pnSpace = _pnSpaces[level]!;

  //   // final dcid = level == EncryptionLevel.application ? peerCid : Uint8List(0);

  //   final result = decryptQuicPacketBytes2(
  //     packet,
  //     keys.key,
  //     keys.iv,
  //     keys.hp,
  //     dcid,
  //     pnSpace.referencePn,
  //   );

  //   if (result == null) {
  //     throw StateError('Decryption failed');
  //   }
  //   //24d56a4ce3ecd117af80ebe068f092e1
  //   pnSpace.onPacketDecrypted(result.packetNumber);
  //   return result;
  // }

  QuicDecryptedPacket decryptPacket(Uint8List packet, EncryptionLevel level) {
    final keys = _readKeys[level];
    if (keys == null) {
      throw StateError('No keys for $level');
    }

    if (level == EncryptionLevel.handshake) {
      dcid = Uint8List.fromList(HEX.decode("635f636964"));
    }

    final pnSpace = _pnSpaces[level]!;

    final result = decryptQuicPacketBytes2(
      packet,
      keys.key,
      keys.iv,
      keys.hp,
      dcid,
      pnSpace.largestPn, // ✅ FIX: do not normalize -1 to 0
    );

    if (result == null) {
      throw StateError('Decryption failed');
    }

    // ✅ Update PN space only after successful decryption
    pnSpace.onPacketDecrypted(result.packetNumber);

    return result;
  }

  void generateSecrets() {
    final initial_salt = Uint8List.fromList(
      HEX.decode("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    );

    final initial_random = randomData;

    final initial_secret = hkdfExtract(initial_random, salt: initial_salt);

    final client_secret = hkdfExpandLabel(
      secret: initial_secret,
      label: "client in",
      context: Uint8List(0),
      length: 32,
    );

    final server_secret = hkdfExpandLabel(
      secret: initial_secret,
      label: "server in",
      context: Uint8List(0),
      length: 32,
    );

    final client_key = hkdfExpandLabel(
      secret: client_secret,
      label: "quic key",
      context: Uint8List(0),
      length: 16,
    );

    final client_iv = hkdfExpandLabel(
      secret: client_secret,
      label: "quic iv",
      context: Uint8List(0),
      length: 12,
    );

    final client_hp_key = hkdfExpandLabel(
      secret: client_secret,
      label: "quic hp",
      context: Uint8List(0),
      length: 16,
    );

    final server_key = hkdfExpandLabel(
      secret: server_secret,
      label: "quic key",
      context: Uint8List(0),
      length: 16,
    );

    final server_iv = hkdfExpandLabel(
      secret: server_secret,
      label: "quic iv",
      context: Uint8List(0),
      length: 12,
    );

    final server_hp_key = hkdfExpandLabel(
      secret: server_secret,
      label: "quic hp",
      context: Uint8List(0),
      length: 16,
    );

    // ---- PRINT RESULTS ----

    print("Client initial key: ${HEX.encode(client_key)}");
    print("Client initial IV:  ${HEX.encode(client_iv)}");

    print("Server initial key: ${HEX.encode(server_key)}");
    print("Server initial IV:  ${HEX.encode(server_iv)}");

    print("Client initial header protection key: ${HEX.encode(client_hp_key)}");
    print("Server initial header protection key: ${HEX.encode(server_hp_key)}");

    // ---- OPTIONAL ASSERTIONS AGAINST KNOWN VALUES ----

    // ---- VERIFY AGAINST RFC VALUES ----

    expectBytesEqual(
      "Client initial key",
      client_key,
      "b14b918124fda5c8d79847602fa3520b",
    );

    expectBytesEqual(
      "Client initial IV",
      client_iv,
      "ddbc15dea80925a55686a7df",
    );

    expectBytesEqual(
      "Server initial key",
      server_key,
      "d77fc4056fcfa32bd1302469ee6ebf90",
    );

    expectBytesEqual(
      "Server initial IV",
      server_iv,
      "fcb748e37ff79860faa07477",
    );

    expectBytesEqual(
      "Client initial header protection key",
      client_hp_key,
      "6df4e9d737cdf714711d7c617ee82981",
    );

    expectBytesEqual(
      "Server initial header protection key",
      server_hp_key,
      "440b2725e91dc79b370711ef792faa3d",
    );

    print("✅ QUIC initial secrets verified");
    // initialRead = QuicKeys(key: client_key, iv: client_iv, hp: client_hp_key);
    // initialWrite = QuicKeys(key: server_key, iv: server_iv, hp: server_hp_key);

    initialWrite = QuicKeys(key: client_key, iv: client_iv, hp: client_hp_key);
    initialRead = QuicKeys(key: server_key, iv: server_iv, hp: server_hp_key);
  }

  void handshakeKeyDerivationTest() {
    final sharedSecret = x25519ShareSecret(
      privateKey: privateKeyBytes,
      publicKey: receivedServello!.keyShareEntry!.pub,
    );

    print(
      "Server key_share pub (${receivedServello!.keyShareEntry!.pub.length} bytes): "
      "${HEX.encode(receivedServello!.keyShareEntry!.pub)}",
    );

    final helloHash = testHash();

    final hashLen = 32;
    final zero = Uint8List(hashLen);
    final empty = Uint8List(0);

    // ✅ EARLY SECRET (matches passing test)
    final earlySecret = hkdfExtract(
      zero, // ikm
      salt: empty, // salt
    );

    final emptyHash = createHash(empty);

    // ✅ DERIVED SECRET
    derivedSecret = hkdfExpandLabel(
      secret: earlySecret,
      label: "derived",
      context: emptyHash,
      length: hashLen,
    );

    // ✅ HANDSHAKE SECRET (THIS WAS CORRECT)
    final handshakeSecret = hkdfExtract(
      sharedSecret, // ikm
      salt: derivedSecret, // salt
    );

    clientHsTrafficSecret = hkdfExpandLabel(
      secret: handshakeSecret,
      label: "c hs traffic",
      context: helloHash,
      length: hashLen,
    );

    final serverHsTrafficSecret = hkdfExpandLabel(
      secret: handshakeSecret,
      label: "s hs traffic",
      context: helloHash,
      length: hashLen,
    );

    final clientHandshakeKey = hkdfExpandLabel(
      secret: clientHsTrafficSecret,
      label: "quic key",
      context: empty,
      length: 16,
    );

    final clientHandshakeIV = hkdfExpandLabel(
      secret: clientHsTrafficSecret,
      label: "quic iv",
      context: empty,
      length: 12,
    );

    final clientHandshakeHP = hkdfExpandLabel(
      secret: clientHsTrafficSecret,
      label: "quic hp",
      context: empty,
      length: 16,
    );

    final serverHandshakeKey = hkdfExpandLabel(
      secret: serverHsTrafficSecret,
      label: "quic key",
      context: empty,
      length: 16,
    );

    final serverHandshakeIV = hkdfExpandLabel(
      secret: serverHsTrafficSecret,
      label: "quic iv",
      context: empty,
      length: 12,
    );

    final serverHandshakeHP = hkdfExpandLabel(
      secret: serverHsTrafficSecret,
      label: "quic hp",
      context: empty,
      length: 16,
    );

    handshakeRead = QuicKeys(
      key: serverHandshakeKey,
      iv: serverHandshakeIV,
      hp: serverHandshakeHP,
    );

    handshakeWrite = QuicKeys(
      key: clientHandshakeKey,
      iv: clientHandshakeIV,
      hp: clientHandshakeHP,
    );

    _readKeys[EncryptionLevel.handshake] = handshakeRead!;

    print("handshake read: $handshakeRead");
    print("handshake write: $handshakeWrite");
    print("✅ QUIC/TLS handshake keys derived (spec-correct)");
  }

  void deriveApplicationSecrets() {
    print("🔐 Deriving application (1‑RTT) secrets");

    final hashLen = 32;
    final zero = Uint8List(hashLen);
    final empty = Uint8List(0);

    // --------------------------------------------------
    // Transcript hash THROUGH Finished
    // (Finished already appended to tlsTranscript)
    // --------------------------------------------------
    final transcriptHash = createHash(transcriptThroughServerHandshake());
    ;
    print("Application Transcript Hash: ${HEX.encode(transcriptHash)}");

    // --------------------------------------------------
    // MASTER SECRET
    // master_secret = HKDF‑Extract(derived_secret, zeros)
    //
    // NOTE: hkdfExtract(ikm, salt)
    // TLS: HKDF‑Extract(salt = derived_secret, ikm = zeros)
    // --------------------------------------------------
    final masterSecret = hkdfExtract(
      zero, // ikm
      salt: derivedSecret, // salt
    );

    print("master_secret: ${HEX.encode(masterSecret)}");

    // --------------------------------------------------
    // CLIENT APPLICATION TRAFFIC SECRET 0
    // --------------------------------------------------
    final clientAppTrafficSecret = hkdfExpandLabel(
      secret: masterSecret,
      label: "c ap traffic",
      context: transcriptHash,
      length: hashLen,
    );

    // --------------------------------------------------
    // SERVER APPLICATION TRAFFIC SECRET 0
    // --------------------------------------------------
    final serverAppTrafficSecret = hkdfExpandLabel(
      secret: masterSecret,
      label: "s ap traffic",
      context: transcriptHash,
      length: hashLen,
    );

    print(
      "client_application_traffic_secret_0: "
      "${HEX.encode(clientAppTrafficSecret)}",
    );
    print(
      "server_application_traffic_secret_0: "
      "${HEX.encode(serverAppTrafficSecret)}",
    );

    // --------------------------------------------------
    // QUIC 1‑RTT WRITE KEYS (client → server)
    // --------------------------------------------------
    final clientAppKey = hkdfExpandLabel(
      secret: clientAppTrafficSecret,
      label: "quic key",
      context: empty,
      length: 16,
    );

    final clientAppIV = hkdfExpandLabel(
      secret: clientAppTrafficSecret,
      label: "quic iv",
      context: empty,
      length: 12,
    );

    final clientAppHP = hkdfExpandLabel(
      secret: clientAppTrafficSecret,
      label: "quic hp",
      context: empty,
      length: 16,
    );

    // --------------------------------------------------
    // QUIC 1‑RTT READ KEYS (server → client)
    // --------------------------------------------------
    final serverAppKey = hkdfExpandLabel(
      secret: serverAppTrafficSecret,
      label: "quic key",
      context: empty,
      length: 16,
    );

    final serverAppIV = hkdfExpandLabel(
      secret: serverAppTrafficSecret,
      label: "quic iv",
      context: empty,
      length: 12,
    );

    final serverAppHP = hkdfExpandLabel(
      secret: serverAppTrafficSecret,
      label: "quic hp",
      context: empty,
      length: 16,
    );

    // --------------------------------------------------
    // INSTALL APPLICATION KEYS
    // --------------------------------------------------
    appRead = QuicKeys(key: serverAppKey, iv: serverAppIV, hp: serverAppHP);

    appWrite = QuicKeys(key: clientAppKey, iv: clientAppIV, hp: clientAppHP);

    _readKeys[EncryptionLevel.application] = appRead!;
    _writeKeys[EncryptionLevel.application] = appWrite!;

    encryptionLevel = EncryptionLevel.application;

    print("✅ 1‑RTT application keys installed");
  }

  bool tlsTranscriptContainsFinished() {
    final Uint8List data = tlsTranscript.toBytes();

    int i = 0;
    while (i + 4 <= data.length) {
      final int type = data[i];
      final int len = (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3];

      // Finished (0x14) fully present
      if (type == 0x14 && i + 4 + len <= data.length) {
        return true;
      }

      i += 4 + len;
    }

    return false;
  }

  //   void handleQuicPacket(Uint8List pkt) {
  //     final previousLevel = encryptionLevel;

  //     print("Encryption level: $encryptionLevel");

  //     // 1️⃣ Decrypt packet using current keys
  //     final result = decryptPacket(pkt, encryptionLevel);
  //     onDecryptedPacket(
  //       result,
  //       encryptionLevel,
  //       InternetAddress("127.0.0.1"),
  //       4433,
  //     );

  //     // 2️⃣ Parse QUIC payload (frames + TLS via CRYPTO reassembly)
  //     final parsed = parsePayload(result.plaintext!, this);

  //     // 3️⃣ Collect CRYPTO frames (for logging, debug, retransmission logic, etc.)
  //     if (parsed.cryptoFrames.isNotEmpty) {
  //       receivedCryptoFrames.addAll(parsed.cryptoFrames);
  //     }

  //     // 4️⃣ Collect parsed TLS handshake messages
  //     if (parsed.tlsMessages.isNotEmpty) {
  //       receivedTlsMessages.addAll(parsed.tlsMessages);
  //     }

  //     // 5️⃣ Transition encryption level if handshake progressed
  //     // (e.g., after ServerHello is parsed)
  //     if (encryptionLevel != previousLevel &&
  //         encryptionLevel == EncryptionLevel.handshake) {
  //       handshakeKeyDerivationTest();
  //     }

  //     // --- TLS / QUIC handshake state machine ---

  //     // final gotServerFinished = parsed.tlsMessages.any(
  //     //   (m) => m is FinishedMessage,
  //     // );

  //     final gotServerFinished = tlsTranscriptContainsFinished();

  //     if (gotServerFinished && !serverFinishedReceived) {
  //       serverFinishedReceived = true;
  //       print("🧠 Server Finished processed");
  //     }

  //     // ✅ Send client Finished immediately after server Finished
  //     if (serverFinishedReceived && !clientFinishedSent) {
  //       sendClientFinished(address: InternetAddress("127.0.0.1"), port: 4433);
  //       clientFinishedSent = true;
  //       print("📤 Client Finished sent");
  //     }

  //     // ✅ Derive application secrets only AFTER Finished exchange
  //     if (serverFinishedReceived &&
  //         clientFinishedSent &&
  //         !applicationSecretsDerived) {
  //       deriveApplicationSecrets();
  //       applicationSecretsDerived = true;
  //       print("🔐 Application secrets derived");
  //     }

  //     print("parsed: $parsed");
  //   }
  void handleQuicPacket(Uint8List pkt) {
    final packetLevel = encryptionLevel;
    final previousLevel = encryptionLevel;

    print("Encryption level: $encryptionLevel");

    final result = decryptPacket(pkt, packetLevel);
    onDecryptedPacket(result, packetLevel, InternetAddress("127.0.0.1"), 4433);

    final parsed = parsePayload(result.plaintext!, this, level: packetLevel);

    // 4️⃣ Collect CRYPTO frames (for logging / debugging)
    if (parsed.cryptoFrames.isNotEmpty) {
      receivedCryptoFrames.addAll(parsed.cryptoFrames);
    }

    // 5️⃣ Collect any parsed TLS messages
    if (parsed.tlsMessages.isNotEmpty) {
      receivedTlsMessages.addAll(parsed.tlsMessages);
    }

    // 6️⃣ If ServerHello caused a level transition, derive handshake keys
    if (encryptionLevel != previousLevel &&
        encryptionLevel == EncryptionLevel.handshake) {
      handshakeKeyDerivationTest();
    }

    // ================= TLS / QUIC STATE MACHINE =================

    // Detect whether the received handshake stream now contains a full server Finished
    final bool gotServerFinished = tlsTranscriptContainsFinished();

    if (gotServerFinished && !serverFinishedReceived) {
      serverFinishedReceived = true;
      print("🧠 Server Finished processed");
    }

    // ✅ Derive application secrets BEFORE sending client Finished
    // because your current sendClientFinished() appends the client Finished
    // to tlsTranscript. Application secrets should be derived from the
    // transcript THROUGH server Finished.
    if (serverFinishedReceived && !applicationSecretsDerived) {
      deriveApplicationSecrets();
      applicationSecretsDerived = true;
      print("🔐 Application secrets derived");
    }

    // ✅ Send Client Finished exactly once
    if (serverFinishedReceived && !clientFinishedSent) {
      sendClientFinished(address: InternetAddress("127.0.0.1"), port: 4433);
      clientFinishedSent = true;
      print("📤 Client Finished sent");
    }

    print("parsed: $parsed");
  }
}

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

final clientHelloBytes = Uint8List.fromList(
  HEX.decode(
    "01 00 00 ea 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 00 06 13 01 13 02 13 03 01 00 00 bb 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 08 00 06 00 1d 00 17 00 18 00 10 00 0b 00 09 08 70 69 6e 67 2f 31 2e 30 00 0d 00 14 00 12 04 03 08 04 04 01 05 03 08 05 05 01 08 06 06 01 02 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54 00 2d 00 02 01 01 00 2b 00 03 02 03 04 00 39 00 31 03 04 80 00 ff f7 04 04 80 a0 00 00 05 04 80 10 00 00 06 04 80 10 00 00 07 04 80 10 00 00 08 01 0a 09 01 0a 0a 01 03 0b 01 19 0f 05 63 5f 63 69 64",
  ),
);
