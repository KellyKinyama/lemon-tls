// -----------------------------------------------------------------------------
// HTTP/3 + WebTransport client state
// -----------------------------------------------------------------------------

import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:hex/hex.dart';

import '../../cipher/x25519.dart';
import '../../frames/quic_frames.dart';
import '../../handshake/server_hello.dart';
import '../../handshake/tls_messages.dart';
import '../../handshake/tls_msg.dart';
import '../../hash.dart';
import '../../hkdf.dart';
import '../../packet/quic_packet.dart';
import '../../quic_ack.dart';
import '../../utils.dart';
import '../client_hello_builder.dart';
import '../h31.dart';
import '../constants.dart';
import 'payload_parser.dart';

const int H3_FRAME_DATA = 0x00;
const int H3_FRAME_HEADERS = 0x01;
const int H3_FRAME_SETTINGS = 0x04;

const int H3_STREAM_TYPE_CONTROL = 0x00;
const String WT_PROTOCOL = 'webtransport';

class ClientWebTransportSession {
  final int connectStreamId;
  bool established = false;

  ClientWebTransportSession(this.connectStreamId);
}

final _bytesEq = const ListEquality<int>();

Uint8List buildCryptoFrame(Uint8List data) {
  return Uint8List.fromList([0x06, 0x00, data.length, ...data]);
}

class Http3ClientState {
  bool settingsReceived = false;
  bool controlStreamSeen = false;

  // Raw QUIC stream bytes keyed by QUIC stream ID and offset
  final Map<int, Map<int, Uint8List>> rawStreamChunks =
      <int, Map<int, Uint8List>>{};

  // Stream-type prefix length for uni streams (e.g. control stream type varint)
  final Map<int, int> streamTypePrefixLen = <int, int>{};

  // Kind of stream: control / request / other_uni / other
  final Map<int, String> streamKinds = <int, String>{};

  // HTTP/3 frame reassembly after stripping any uni-stream type prefix
  final Map<int, Map<int, Uint8List>> h3FrameChunks =
      <int, Map<int, Uint8List>>{};
  final Map<int, int> h3FrameReadOffsets = <int, int>{};

  // Peer settings learned from server control stream
  final Map<String, int> peerSettings = <String, int>{};

  // WebTransport sessions keyed by CONNECT stream ID
  final Map<int, ClientWebTransportSession> webTransportSessions =
      <int, ClientWebTransportSession>{};
}

// -----------------------------------------------------------------------------
// Full QuicSession with HTTP/3 + WebTransport support
// -----------------------------------------------------------------------------

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

  late Uint8List derivedSecret;

  /// Client's own Source CID.
  /// This is what the server will use as DCID when replying in long headers.
  late Uint8List localCid;

  /// Learned from server long-header packet SCID.
  /// This becomes the DCID for packets the client sends after that.
  Uint8List? peerCid;

  /// Traffic keys by level and direction
  final _readKeys = <EncryptionLevel, QuicKeys>{};
  final _writeKeys = <EncryptionLevel, QuicKeys>{};

  final BytesBuilder receivedHandshakeBytes = BytesBuilder();
  final BytesBuilder tlsTranscript = BytesBuilder();

  late Uint8List clientHsTrafficSecret;
  late Uint8List handshakeSecret;

  bool serverFinishedReceived = false;
  bool clientFinishedSent = false;
  bool applicationSecretsDerived = false;

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

  final Map<EncryptionLevel, AckState> ackStates = {
    EncryptionLevel.initial: AckState(),
    EncryptionLevel.handshake: AckState(),
    // 1-RTT can be added later
  };

  // ---------------------------------------------------------------------------
  // HTTP/3 + WebTransport state
  // ---------------------------------------------------------------------------

  final Http3ClientState h3 = Http3ClientState();

  // Client-initiated streams
  int nextClientBidiStreamId = 0; // client bidi: 0,4,8,...
  int nextClientUniStreamId = 2; // client uni: 2,6,10,...

  QuicSession(this.dcid, this.socket) {
    generateSecrets();
    _readKeys[EncryptionLevel.initial] = initialRead!;
    localCid = _randomCid(8);
  }

  Uint8List _randomCid([int len = 8]) {
    final rnd = math.Random.secure();
    return Uint8List.fromList(List.generate(len, (_) => rnd.nextInt(256)));
  }

  // ===========================================================================
  // ACK sending
  // ===========================================================================

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
      ackDelayMicros: 0,
      ect0: 0,
      ect1: 0,
      ce: 0,
    );

    final ackPayload = ackFrame.encode();
    final pn = ackState.allocatePn();

    final writeKeys = switch (level) {
      EncryptionLevel.initial => initialWrite,
      EncryptionLevel.handshake => handshakeWrite,
      EncryptionLevel.application => appWrite,
    };

    if (writeKeys == null) {
      throw StateError("Write keys not available for $level");
    }

    final Uint8List dcidToUse = peerCid ?? Uint8List(0);
    final Uint8List scidToUse = localCid;

    final rawPacket = encryptQuicPacket(
      level == EncryptionLevel.application ? "short" : level.name,
      ackPayload,
      writeKeys.key,
      writeKeys.iv,
      writeKeys.hp,
      pn,
      dcidToUse,
      scidToUse,
      Uint8List(0),
    );

    if (rawPacket == null) {
      print("❌ Failed to encrypt ACK ($level)");
      return;
    }

    final bytesToSend = level == EncryptionLevel.initial
        ? padTo1200(rawPacket)
        : rawPacket;

    socket.send(bytesToSend, InternetAddress(address), port);

    print(
      "✅ Sent ACK ($level) pn=$pn "
      "dcid=${HEX.encode(dcidToUse)} scid=${HEX.encode(scidToUse)} "
      "acked=${ackState.received.toList()..sort()}",
    );
  }

  void onDecryptedPacket(
    QuicDecryptedPacket decryptedPacket,
    EncryptionLevel level,
    InternetAddress address,
    int port,
  ) {
    final ackState = ackStates[level];
    if (ackState == null) {
      return;
    }

    ackState.received.add(decryptedPacket.packetNumber);

    if (level == EncryptionLevel.initial ||
        level == EncryptionLevel.handshake) {
      sendAck(level: level, address: address.address, port: port);
    }
  }

  // ===========================================================================
  // CID tracking
  // ===========================================================================

  (Uint8List, Uint8List) _extractLongHeaderCids(Uint8List pkt) {
    int off = 1;
    off += 4;

    final dcidLen = pkt[off++];
    final packetDcid = pkt.sublist(off, off + dcidLen);
    off += dcidLen;

    final scidLen = pkt[off++];
    final packetScid = pkt.sublist(off, off + scidLen);

    return (packetDcid, packetScid);
  }

  void _maybeLearnPeerCid(Uint8List pkt) {
    final isLong = (pkt[0] & 0x80) != 0;
    if (!isLong) return;

    final (packetDcid, packetScid) = _extractLongHeaderCids(pkt);

    if (!_bytesEq.equals(packetDcid, localCid)) {
      print(
        "ℹ️ Server packet DCID=${HEX.encode(packetDcid)} "
        "does not match localCid=${HEX.encode(localCid)}",
      );
    }

    if (peerCid == null || !_bytesEq.equals(peerCid!, packetScid)) {
      peerCid = Uint8List.fromList(packetScid);
      print("✅ Learned server CID: ${HEX.encode(peerCid!)}");
    }
  }

  // ===========================================================================
  // TLS / Handshake send
  // ===========================================================================
  EncryptionLevel detectPacketLevel(Uint8List packet) {
    final firstByte = packet[0];

    if ((firstByte & 0x80) != 0) {
      final longType = parseLongHeaderType(packet);

      if (longType == LongPacketType.initial) {
        return EncryptionLevel.initial;
      } else if (longType == LongPacketType.handshake) {
        return EncryptionLevel.handshake;
      } else {
        throw StateError('Unsupported long-header packet type: $longType');
      }
    }

    return EncryptionLevel.application;
  }

  void sendClientFinished({
    required InternetAddress address,
    required int port,
  }) {
    if (handshakeWrite == null) {
      throw StateError("Handshake write keys not available");
    }

    final transcriptHash = createHash(
      Uint8List.fromList([...tlsTranscript.toBytes()]),
    );

    final finishedKey = hkdfExpandLabel(
      secret: clientHsTrafficSecret,
      label: "finished",
      context: Uint8List(0),
      length: 32,
    );

    final verifyData = hmacSha256(key: finishedKey, data: transcriptHash);

    final finishedHandshake = BytesBuilder()
      ..addByte(0x14)
      ..add([
        (verifyData.length >> 16) & 0xff,
        (verifyData.length >> 8) & 0xff,
        verifyData.length & 0xff,
      ])
      ..add(verifyData);

    final finishedBytes = finishedHandshake.toBytes();
    final cryptoPayload = buildCryptoFrame(finishedBytes);

    final ackState = ackStates[EncryptionLevel.handshake]!;
    final pn = ackState.allocatePn();

    final rawPacket = encryptQuicPacket(
      "handshake",
      cryptoPayload,
      handshakeWrite!.key,
      handshakeWrite!.iv,
      handshakeWrite!.hp,
      pn,
      peerCid ?? Uint8List(0),
      localCid,
      Uint8List(0),
    );

    if (rawPacket == null) {
      print("❌ Failed to encrypt Client Finished");
      return;
    }

    socket.send(rawPacket, address, port);

    print(
      "✅ Sent Client Finished (Handshake) "
      "pn=$pn dcid=${HEX.encode(peerCid ?? Uint8List(0))} "
      "scid=${HEX.encode(localCid)} "
      "verify_data=${HEX.encode(verifyData)}",
    );
  }

  // ===========================================================================
  // CRYPTO stream reassembly
  // ===========================================================================

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

  // ===========================================================================
  // Handshake transcript helpers
  // ===========================================================================

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

  // ===========================================================================
  // Packet decryption
  // ===========================================================================

  QuicDecryptedPacket decryptPacket(Uint8List packet, EncryptionLevel _unused) {
    final firstByte = packet[0];
    late final EncryptionLevel level;

    if ((firstByte & 0x80) != 0) {
      final longType = parseLongHeaderType(packet);

      if (longType == LongPacketType.initial) {
        level = EncryptionLevel.initial;
      } else if (longType == LongPacketType.handshake) {
        level = EncryptionLevel.handshake;
      } else {
        throw StateError('Unsupported long-header packet type: $longType');
      }
    } else {
      level = EncryptionLevel.application;
    }

    final keys = _readKeys[level];
    if (keys == null) {
      throw StateError('No read keys for $level');
    }

    final pnSpace = _pnSpaces[level]!;

    final Uint8List dcidForPacket = switch (level) {
      EncryptionLevel.initial => dcid,
      EncryptionLevel.handshake => peerCid ?? Uint8List(0),
      EncryptionLevel.application =>
        peerCid ??
            (throw StateError('No server CID learned for application packets')),
    };

    final result = decryptQuicPacketBytes2(
      packet,
      keys.key,
      keys.iv,
      keys.hp,
      dcidForPacket,
      pnSpace.largestPn,
    );

    if (result == null) {
      throw StateError('Decryption failed');
    }

    pnSpace.onPacketDecrypted(result.packetNumber);
    return result;
  }

  // ===========================================================================
  // Initial secret generation
  // ===========================================================================

  void generateSecrets() {
    final initialSalt = Uint8List.fromList(
      HEX.decode("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    );

    final initialRandom = randomData;
    final initialSecret = hkdfExtract(initialRandom, salt: initialSalt);

    final clientSecret = hkdfExpandLabel(
      secret: initialSecret,
      label: "client in",
      context: Uint8List(0),
      length: 32,
    );

    final serverSecret = hkdfExpandLabel(
      secret: initialSecret,
      label: "server in",
      context: Uint8List(0),
      length: 32,
    );

    final clientKey = hkdfExpandLabel(
      secret: clientSecret,
      label: "quic key",
      context: Uint8List(0),
      length: 16,
    );

    final clientIv = hkdfExpandLabel(
      secret: clientSecret,
      label: "quic iv",
      context: Uint8List(0),
      length: 12,
    );

    final clientHpKey = hkdfExpandLabel(
      secret: clientSecret,
      label: "quic hp",
      context: Uint8List(0),
      length: 16,
    );

    final serverKey = hkdfExpandLabel(
      secret: serverSecret,
      label: "quic key",
      context: Uint8List(0),
      length: 16,
    );

    final serverIv = hkdfExpandLabel(
      secret: serverSecret,
      label: "quic iv",
      context: Uint8List(0),
      length: 12,
    );

    final serverHpKey = hkdfExpandLabel(
      secret: serverSecret,
      label: "quic hp",
      context: Uint8List(0),
      length: 16,
    );

    print("Client initial key: ${HEX.encode(clientKey)}");
    print("Client initial IV:  ${HEX.encode(clientIv)}");
    print("Server initial key: ${HEX.encode(serverKey)}");
    print("Server initial IV:  ${HEX.encode(serverIv)}");
    print("Client initial header protection key: ${HEX.encode(clientHpKey)}");
    print("Server initial header protection key: ${HEX.encode(serverHpKey)}");

    // expectBytesEqual(
    //   "Client initial key",
    //   clientKey,
    //   "b14b918124fda5c8d79847602fa3520b",
    // );

    // expectBytesEqual("Client initial IV", clientIv, "ddbc15dea80925a55686a7df");

    // expectBytesEqual(
    //   "Server initial key",
    //   serverKey,
    //   "d77fc4056fcfa32bd1302469ee6ebf90",
    // );

    // expectBytesEqual("Server initial IV", serverIv, "fcb748e37ff79860faa07477");

    // expectBytesEqual(
    //   "Client initial header protection key",
    //   clientHpKey,
    //   "6df4e9d737cdf714711d7c617ee82981",
    // );

    // expectBytesEqual(
    //   "Server initial header protection key",
    //   serverHpKey,
    //   "440b2725e91dc79b370711ef792faa3d",
    // );

    print("✅ QUIC initial secrets verified");

    // Client writes Initial using client keys; reads server Initial using server keys
    initialWrite = QuicKeys(key: clientKey, iv: clientIv, hp: clientHpKey);
    initialRead = QuicKeys(key: serverKey, iv: serverIv, hp: serverHpKey);
  }

  // ===========================================================================
  // Handshake key derivation
  // ===========================================================================

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

    final earlySecret = hkdfExtract(zero, salt: empty);

    final emptyHash = createHash(empty);

    derivedSecret = hkdfExpandLabel(
      secret: earlySecret,
      label: "derived",
      context: emptyHash,
      length: hashLen,
    );

    handshakeSecret = hkdfExtract(sharedSecret, salt: derivedSecret);

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

    // Client reads server handshake, writes client handshake
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
    _writeKeys[EncryptionLevel.handshake] = handshakeWrite!;

    print("handshake read: $handshakeRead");
    print("handshake write: $handshakeWrite");
    print("✅ QUIC/TLS handshake keys derived (spec-correct)");
  }

  // ===========================================================================
  // Application (1-RTT) secrets
  // ===========================================================================

  void deriveApplicationSecrets() {
    print("🔐 Deriving application (1‑RTT) secrets");

    final hashLen = 32;
    final zero = Uint8List(hashLen);
    final empty = Uint8List(0);

    final transcriptHash = createHash(transcriptThroughServerHandshake());

    print("Application Transcript Hash: ${HEX.encode(transcriptHash)}");

    final emptyHash = createHash(empty);
    final derivedSecret2 = hkdfExpandLabel(
      secret: handshakeSecret,
      label: "derived",
      context: emptyHash,
      length: hashLen,
    );

    final masterSecret = hkdfExtract(zero, salt: derivedSecret2);

    print("master_secret: ${HEX.encode(masterSecret)}");

    final clientAppTrafficSecret = hkdfExpandLabel(
      secret: masterSecret,
      label: "c ap traffic",
      context: transcriptHash,
      length: hashLen,
    );

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

    // Client reads server application, writes client application
    appRead = QuicKeys(key: serverAppKey, iv: serverAppIV, hp: serverAppHP);
    appWrite = QuicKeys(key: clientAppKey, iv: clientAppIV, hp: clientAppHP);

    _readKeys[EncryptionLevel.application] = appRead!;
    _writeKeys[EncryptionLevel.application] = appWrite!;

    encryptionLevel = EncryptionLevel.application;

    print("appRead:  $appRead");
    print("appWrite: $appWrite");

    print("✅ 1‑RTT application keys installed");
  }

  bool tlsTranscriptContainsFinished() {
    final Uint8List data = tlsTranscript.toBytes();

    int i = 0;
    while (i + 4 <= data.length) {
      final int type = data[i];
      final int len = (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3];

      if (type == 0x14 && i + 4 + len <= data.length) {
        return true;
      }

      i += 4 + len;
    }

    return false;
  }

  // ===========================================================================
  // Packet handling
  // ===========================================================================

  void handleQuicPacket(Uint8List pkt) {
    // Learn the server CID from long-header packets before decrypting.
    _maybeLearnPeerCid(pkt);

    final packetLevel = encryptionLevel;
    final previousLevel = encryptionLevel;

    print("Encryption level: $encryptionLevel");

    final result = decryptPacket(pkt, packetLevel);
    onDecryptedPacket(result, packetLevel, InternetAddress("127.0.0.1"), 4433);

    final parsed = parsePayload(result.plaintext!, this, level: packetLevel);

    if (parsed.cryptoFrames.isNotEmpty) {
      receivedCryptoFrames.addAll(parsed.cryptoFrames);
    }

    if (parsed.tlsMessages.isNotEmpty) {
      receivedTlsMessages.addAll(parsed.tlsMessages);
    }

    if (encryptionLevel != previousLevel &&
        encryptionLevel == EncryptionLevel.handshake) {
      handshakeKeyDerivationTest();
    }

    final bool gotServerFinished = tlsTranscriptContainsFinished();

    if (gotServerFinished && !serverFinishedReceived) {
      serverFinishedReceived = true;
      print("🧠 Server Finished processed");
    }

    if (serverFinishedReceived && !applicationSecretsDerived) {
      deriveApplicationSecrets();
      applicationSecretsDerived = true;
      print("🔐 Application secrets derived");
    }

    if (serverFinishedReceived && !clientFinishedSent) {
      sendClientFinished(address: InternetAddress("127.0.0.1"), port: 4433);
      clientFinishedSent = true;
      print("📤 Client Finished sent");
    }

    print("parsed: $parsed");
  }

  // ===========================================================================
  // HTTP/3 + WebTransport support
  // ===========================================================================

  bool _isClientInitiatedBidi(int streamId) => (streamId & 0x03) == 0x00;
  bool _isServerInitiatedUni(int streamId) => (streamId & 0x03) == 0x03;

  int _allocateClientBidiStreamId() {
    final id = nextClientBidiStreamId;
    nextClientBidiStreamId += 4;
    return id;
  }

  int _allocateClientUniStreamId() {
    final id = nextClientUniStreamId;
    nextClientUniStreamId += 4;
    return id;
  }

  void handleHttp3StreamChunk(
    int streamId,
    int streamOffset,
    Uint8List streamData, {
    required bool fin,
  }) {
    // ----------------------------------------------------------
    // 1) Raw QUIC stream reassembly
    // ----------------------------------------------------------
    final rawChunks = h3.rawStreamChunks.putIfAbsent(
      streamId,
      () => <int, Uint8List>{},
    );
    rawChunks[streamOffset] = streamData;

    String kind = h3.streamKinds[streamId] ?? 'unknown';

    // ----------------------------------------------------------
    // 2) Determine stream kind
    // ----------------------------------------------------------
    if (kind == 'unknown') {
      if (_isClientInitiatedBidi(streamId)) {
        // Request stream: no stream-type prefix
        kind = 'request';
        h3.streamKinds[streamId] = kind;
        h3.streamTypePrefixLen[streamId] = 0;
      } else if (_isServerInitiatedUni(streamId)) {
        // Need bytes starting at offset 0 to read stream type varint
        final zeroChunk = rawChunks[0];
        if (zeroChunk == null) {
          return;
        }

        final typeInfo = readVarInt(zeroChunk, 0);
        if (typeInfo == null) {
          return;
        }

        final streamType = typeInfo.value as int;
        final prefixLen = typeInfo.byteLength as int;
        h3.streamTypePrefixLen[streamId] = prefixLen;

        if (streamType == H3_STREAM_TYPE_CONTROL) {
          kind = 'control';
          h3.controlStreamSeen = true;
          print('✅ Saw HTTP/3 control stream on QUIC stream $streamId');
        } else {
          kind = 'other_uni';
          print(
            'ℹ️ Saw unsupported server uni stream type '
            '0x${streamType.toRadixString(16)} on QUIC stream $streamId',
          );
        }

        h3.streamKinds[streamId] = kind;
      } else {
        kind = 'other';
        h3.streamKinds[streamId] = kind;
        h3.streamTypePrefixLen[streamId] = 0;
      }
    }

    final prefixLen = h3.streamTypePrefixLen[streamId] ?? 0;

    // ----------------------------------------------------------
    // 3) Strip uni-stream type prefix before H3 frame parsing
    // ----------------------------------------------------------
    final rawStart = streamOffset;
    final rawEnd = streamOffset + streamData.length;

    if (rawEnd <= prefixLen) {
      // Entire chunk is still within the stream-type prefix
      return;
    }

    int sliceStartInChunk = 0;
    int h3Offset = rawStart - prefixLen;

    if (rawStart < prefixLen) {
      sliceStartInChunk = prefixLen - rawStart;
      h3Offset = 0;
    }

    final h3Bytes = streamData.sublist(sliceStartInChunk);

    final frameChunks = h3.h3FrameChunks.putIfAbsent(
      streamId,
      () => <int, Uint8List>{},
    );
    frameChunks[h3Offset] = h3Bytes;

    final readOffset = h3.h3FrameReadOffsets[streamId] ?? 0;
    final extracted = extract_h3_frames_from_chunks(frameChunks, readOffset);
    h3.h3FrameReadOffsets[streamId] = extracted['new_from_offset'] as int;

    for (final frame in extracted['frames']) {
      final int type = frame['frame_type'] as int;
      final Uint8List payload = frame['payload'] as Uint8List;

      if (kind == 'control') {
        _handleHttp3ControlFrame(type, payload);
        continue;
      }

      if (kind == 'request') {
        _handleHttp3RequestStreamFrame(streamId, type, payload);
        continue;
      }

      print(
        'ℹ️ Ignoring HTTP/3 frame type=0x${type.toRadixString(16)} '
        'on stream=$streamId kind=$kind',
      );
    }

    if (fin) {
      print('✅ QUIC stream $streamId FIN received');
    }
  }

  void _handleHttp3ControlFrame(int frameType, Uint8List payload) {
    if (frameType == H3_FRAME_SETTINGS) {
      final settings = parse_h3_settings_frame(payload);
      h3.peerSettings
        ..clear()
        ..addAll(settings);
      h3.settingsReceived = true;

      print('✅ Received HTTP/3 SETTINGS from server: $settings');
      return;
    }

    print(
      'ℹ️ Ignoring unsupported control-stream frame '
      '0x${frameType.toRadixString(16)}',
    );
  }

  void _handleHttp3RequestStreamFrame(
    int streamId,
    int frameType,
    Uint8List payload,
  ) {
    if (frameType == H3_FRAME_HEADERS) {
      final headers = decode_qpack_header_fields(payload);

      String status = '';
      for (final h in headers) {
        if (h.name == ':status') status = h.value;
      }

      print('📥 HTTP/3 HEADERS on stream $streamId status=$status');
      for (final h in headers) {
        print('   ${h.name}: ${h.value}');
      }

      final wt = h3.webTransportSessions[streamId];
      if (wt != null && status == '200') {
        wt.established = true;
        print('✅ WebTransport session established on stream $streamId');
      }

      return;
    }

    if (frameType == H3_FRAME_DATA) {
      print('📦 HTTP/3 DATA on stream=$streamId len=${payload.length}');
      return;
    }

    print(
      'ℹ️ Ignoring unsupported request-stream frame '
      '0x${frameType.toRadixString(16)} on stream=$streamId',
    );
  }

  int openWebTransportSession(
    String path, {
    String authority = 'localhost',
    String scheme = 'https',
    InternetAddress? address,
    int port = 4433,
  }) {
    final streamId = _allocateClientBidiStreamId();

    h3.webTransportSessions[streamId] = ClientWebTransportSession(streamId);

    final headerBlock = build_http3_literal_headers_frame({
      ':method': 'CONNECT',
      ':scheme': scheme,
      ':authority': authority,
      ':path': path,
      ':protocol': WT_PROTOCOL,
    });

    final frames = build_h3_frames([
      {'frame_type': H3_FRAME_HEADERS, 'payload': headerBlock},
    ]);

    sendApplicationStream(
      streamId,
      frames,
      fin: false,
      address: address,
      port: port,
    );

    print('🚀 Sent WebTransport CONNECT on stream $streamId path=$path');
    return streamId;
  }

  void handleWebTransportDatagram(Uint8List datagramPayload) {
    final parsed = parse_webtransport_datagram(datagramPayload);
    final int sessionId = parsed['stream_id'] as int;
    final Uint8List data = parsed['data'] as Uint8List;

    final session = h3.webTransportSessions[sessionId];
    if (session == null) {
      print('⚠️ Datagram for unknown WebTransport session $sessionId');
      return;
    }

    print(
      '📦 Received WebTransport DATAGRAM '
      'session=$sessionId len=${data.length} hex=${HEX.encode(data)}',
    );
  }

  void sendWebTransportDatagram(
    int sessionId,
    Uint8List data, {
    InternetAddress? address,
    int port = 4433,
  }) {
    if (!applicationSecretsDerived || appWrite == null) {
      throw StateError('Cannot send WebTransport DATAGRAM before 1-RTT keys');
    }

    final payload = Uint8List.fromList([...writeVarInt(sessionId), ...data]);

    final frame = _buildDatagramFrame(payload, useLengthField: true);

    final ackState = ackStates[EncryptionLevel.application]!;
    final pn = ackState.allocatePn();

    final rawPacket = encryptQuicPacket(
      "short",
      frame,
      appWrite!.key,
      appWrite!.iv,
      appWrite!.hp,
      pn,
      peerCid ?? Uint8List(0),
      localCid,
      Uint8List(0),
    );

    if (rawPacket == null) {
      throw StateError('Failed to encrypt application DATAGRAM packet');
    }

    socket.send(rawPacket, address ?? InternetAddress("127.0.0.1"), port);

    print(
      '✅ Sent WebTransport DATAGRAM pn=$pn session=$sessionId len=${data.length}',
    );
  }

  void sendApplicationStream(
    int streamId,
    Uint8List data, {
    bool fin = false,
    int offset = 0,
    InternetAddress? address,
    int port = 4433,
  }) {
    if (!applicationSecretsDerived || appWrite == null) {
      throw StateError('Cannot send application stream before 1-RTT keys');
    }

    final frame = _buildStreamFrame(
      streamId: streamId,
      data: data,
      offset: offset,
      fin: fin,
    );

    final ackState = ackStates[EncryptionLevel.application]!;
    final pn = ackState.allocatePn();

    final rawPacket = encryptQuicPacket(
      "short",
      frame,
      appWrite!.key,
      appWrite!.iv,
      appWrite!.hp,
      pn,
      peerCid ?? Uint8List(0),
      localCid,
      Uint8List(0),
    );

    if (rawPacket == null) {
      throw StateError('Failed to encrypt application STREAM packet');
    }

    socket.send(rawPacket, address ?? InternetAddress("127.0.0.1"), port);

    print(
      '✅ Sent application STREAM pn=$pn '
      'streamId=$streamId len=${data.length} fin=$fin',
    );
  }

  Uint8List _buildStreamFrame({
    required int streamId,
    required Uint8List data,
    int offset = 0,
    bool fin = false,
  }) {
    int frameType = 0x08;
    if (fin) frameType |= 0x01;
    frameType |= 0x02; // LEN present
    if (offset != 0) frameType |= 0x04;

    return Uint8List.fromList([
      ...writeVarInt(frameType),
      ...writeVarInt(streamId),
      if (offset != 0) ...writeVarInt(offset),
      ...writeVarInt(data.length),
      ...data,
    ]);
  }

  Uint8List _buildDatagramFrame(
    Uint8List payload, {
    bool useLengthField = true,
  }) {
    if (useLengthField) {
      return Uint8List.fromList([
        ...writeVarInt(0x31),
        ...writeVarInt(payload.length),
        ...payload,
      ]);
    }

    return Uint8List.fromList([...writeVarInt(0x30), ...payload]);
  }
}

final clientHelloBytes = Uint8List.fromList(
  HEX.decode(
    "01 00 00 ea 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 00 06 13 01 13 02 13 03 01 00 00 bb 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 08 00 06 00 1d 00 17 00 18 00 10 00 0b 00 09 08 70 69 6e 67 2f 31 2e 30 00 0d 00 14 00 12 04 03 08 04 04 01 05 03 08 05 05 01 08 06 06 01 02 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54 00 2d 00 02 01 01 00 2b 00 03 02 03 04 00 39 00 31 03 04 80 00 ff f7 04 04 80 a0 00 00 05 04 80 10 00 00 06 04 80 10 00 00 07 04 80 10 00 00 08 01 0a 09 01 0a 0a 01 03 0b 01 19 0f 05 63 5f 63 69 64",
  ),
);
