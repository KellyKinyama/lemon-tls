import 'dart:io';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:hex/hex.dart';

import '../buffer.dart';
import '../frames/quic_frames.dart';
import '../hash.dart';
import '../hkdf.dart';
import '../packet/quic_packet.dart';
import '../quic_ack.dart';
import '../utils.dart';
import '../cipher/x25519.dart';

Uint8List _padTo1200(Uint8List pkt) {
  const minInitialSize = 1200;
  if (pkt.length >= minInitialSize) return pkt;
  final out = Uint8List(minInitialSize);
  out.setRange(0, pkt.length, pkt);
  return out;
}

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

enum EncryptionLevel { initial, handshake, application }

class QuicKeys {
  final Uint8List key;
  final Uint8List iv;
  final Uint8List hp;

  const QuicKeys({required this.key, required this.iv, required this.hp});

  @override
  String toString() {
    return """QuicKeys{
  key: ${HEX.encode(key)};
  iv:  ${HEX.encode(iv)};
  hp:  ${HEX.encode(hp)};
}""";
  }
}

class PacketNumberSpace {
  int largestPn = -1;

  void onPacketDecrypted(int pn) {
    if (pn > largestPn) {
      largestPn = pn;
    }
  }
}

class AckState {
  final Set<int> received = <int>{};
}

class ServerHandshakeFlight {
  /// Full TLS handshake message bytes (type + 3-byte length + body)
  final Uint8List serverHello;
  final Uint8List encryptedExtensions;
  final Uint8List certificate;
  final Uint8List certificateVerify;

  const ServerHandshakeFlight({
    required this.serverHello,
    required this.encryptedExtensions,
    required this.certificate,
    required this.certificateVerify,
  });

  Uint8List bytesBeforeFinished() {
    return Uint8List.fromList([
      ...serverHello,
      ...encryptedExtensions,
      ...certificate,
      ...certificateVerify,
    ]);
  }
}

class QuicServerSession {
  final RawDatagramSocket socket;
  final InternetAddress peerAddress;
  final int peerPort;

  /// This is the server CID that your current client expects to see as DCID
  /// on packets from the server.
  final Uint8List serverCid = Uint8List.fromList(HEX.decode("635f636964"));

  /// This becomes the client’s original Initial DCID (000102... in your tests)
  late Uint8List clientOrigDcid;

  /// The client currently hardcodes this exact ClientHello.
  final Uint8List clientHelloBytes = Uint8List.fromList(
    HEX.decode(
      "01 00 00 ea 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f "
      "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 00 06 13 01 13 02 "
      "13 03 01 00 00 bb 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e "
      "75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 08 00 06 00 1d 00 17 00 18 "
      "00 10 00 0b 00 09 08 70 69 6e 67 2f 31 2e 30 00 0d 00 14 00 12 04 03 "
      "08 04 04 01 05 03 08 05 05 01 08 06 06 01 02 01 00 33 00 26 00 24 00 "
      "1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 "
      "a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54 00 2d 00 02 01 01 00 2b 00 03 02 "
      "03 04 00 39 00 31 03 04 80 00 ff f7 04 04 80 a0 00 00 05 04 80 10 00 "
      "00 06 04 80 10 00 00 07 04 80 10 00 00 08 01 0a 09 01 0a 0a 01 03 0b "
      "01 19 0f 05 63 5f 63 69 64",
    ),
  );

  /// Same fixed client X25519 public key embedded in the hardcoded ClientHello
  final Uint8List clientPublicKey = Uint8List.fromList(
    HEX.decode(
      "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254",
    ),
  );

  /// Deterministic server X25519 keypair (you can replace with your own)
  final Uint8List serverPrivateKeyBytes = Uint8List.fromList(
    HEX.decode(
      "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
    ),
  );

  final Uint8List serverPublicKeyBytes = Uint8List.fromList(
    HEX.decode(
      // Public key corresponding to the private key above
      "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a",
    ),
  );

  final ServerHandshakeFlight flight;

  EncryptionLevel encryptionLevel = EncryptionLevel.initial;

  QuicKeys? initialRead, initialWrite;
  QuicKeys? handshakeRead, handshakeWrite;
  QuicKeys? appRead, appWrite;

  late Uint8List derivedSecret;
  late Uint8List clientHsTrafficSecret;
  late Uint8List serverHsTrafficSecret;

  Uint8List? serverFinishedBytes;
  Uint8List? transcriptThroughServerFinishedBytes;

  final Map<EncryptionLevel, PacketNumberSpace> recvPnSpaces = {
    EncryptionLevel.initial: PacketNumberSpace(),
    EncryptionLevel.handshake: PacketNumberSpace(),
    EncryptionLevel.application: PacketNumberSpace(),
  };

  final Map<EncryptionLevel, int> nextSendPn = {
    EncryptionLevel.initial: 0,
    EncryptionLevel.handshake: 1, // start handshake pn at 1 to mirror your logs
    EncryptionLevel.application: 0,
  };

  final Map<EncryptionLevel, AckState> ackStates = {
    EncryptionLevel.initial: AckState(),
    EncryptionLevel.handshake: AckState(),
    EncryptionLevel.application: AckState(),
  };

  final Map<EncryptionLevel, Map<int, Uint8List>> cryptoChunksByLevel = {
    EncryptionLevel.initial: <int, Uint8List>{},
    EncryptionLevel.handshake: <int, Uint8List>{},
    EncryptionLevel.application: <int, Uint8List>{},
  };

  final Map<EncryptionLevel, int> cryptoReadOffsetByLevel = {
    EncryptionLevel.initial: 0,
    EncryptionLevel.handshake: 0,
    EncryptionLevel.application: 0,
  };

  final Map<EncryptionLevel, BytesBuilder> receivedHandshakeByLevel = {
    EncryptionLevel.initial: BytesBuilder(),
    EncryptionLevel.handshake: BytesBuilder(),
    EncryptionLevel.application: BytesBuilder(),
  };

  bool initialKeysReady = false;
  bool handshakeKeysReady = false;
  bool serverFlightSent = false;
  bool clientFinishedVerified = false;
  bool applicationSecretsDerived = false;

  final peerScid = Uint8List.fromList(HEX.decode("635f636964"));
  final localCid = Uint8List.fromList(HEX.decode("0001020304050607"));

  QuicServerSession({
    required this.socket,
    required this.peerAddress,
    required this.peerPort,
    required this.flight,
  });

  // QuicServerSession(this.dcid, this.socket);

  // ============================================================
  // Public entry point
  // ============================================================

  void handleDatagram(Uint8List pkt) {
    final packetLevel = detectPacketLevel(pkt);
    print("📥 Server received packet level=$packetLevel len=${pkt.length}");

    if (!initialKeysReady) {
      _deriveInitialKeysFromFirstPacket(pkt);
    }

    final decrypted = decryptPacket(pkt, packetLevel);
    _onDecryptedPacket(decrypted, packetLevel);

    _parsePayload(decrypted.plaintext!, packetLevel);
  }

  // ============================================================
  // Level detection
  // ============================================================

  EncryptionLevel detectPacketLevel(Uint8List pkt) {
    final firstByte = pkt[0];
    final isLong = (firstByte & 0x80) != 0;

    if (!isLong) {
      return EncryptionLevel.application; // short header = 1-RTT
    }

    final typeBits = (firstByte >> 4) & 0x03;
    switch (typeBits) {
      case 0x00:
        return EncryptionLevel.initial;
      case 0x02:
        return EncryptionLevel.handshake;
      default:
        throw StateError(
          "Unsupported long-header packet type: 0x${typeBits.toRadixString(16)}",
        );
    }
  }

  // ============================================================
  // Initial secrets
  // ============================================================

  void _deriveInitialKeysFromFirstPacket(Uint8List pkt) {
    final cids = _extractLongHeaderCids(pkt);
    clientOrigDcid = cids.$1;

    final initialSalt = Uint8List.fromList(
      HEX.decode("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    );

    final initialSecret = hkdfExtract(
      clientOrigDcid, // ikm
      salt: initialSalt,
    );

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
    final clientHp = hkdfExpandLabel(
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
    final serverHp = hkdfExpandLabel(
      secret: serverSecret,
      label: "quic hp",
      context: Uint8List(0),
      length: 16,
    );

    // Server reads client Initial, writes server Initial
    initialRead = QuicKeys(key: clientKey, iv: clientIv, hp: clientHp);
    initialWrite = QuicKeys(key: serverKey, iv: serverIv, hp: serverHp);

    initialKeysReady = true;

    print("✅ Server Initial keys ready");
    print("  initialRead : $initialRead");
    print("  initialWrite: $initialWrite");
  }

  (Uint8List, Uint8List) _extractLongHeaderCids(Uint8List pkt) {
    int off = 1; // first byte
    off += 4; // version

    final dcidLen = pkt[off++];
    final dcid = pkt.sublist(off, off + dcidLen);
    off += dcidLen;

    final scidLen = pkt[off++];
    final scid = pkt.sublist(off, off + scidLen);

    return (dcid, scid);
  }

  // ============================================================
  // Packet decryption
  // ============================================================

  QuicDecryptedPacket decryptPacket(Uint8List packet, EncryptionLevel level) {
    final keys = switch (level) {
      EncryptionLevel.initial => initialRead,
      EncryptionLevel.handshake => handshakeRead,
      EncryptionLevel.application => appRead,
    };

    if (keys == null) {
      throw StateError("No read keys for $level");
    }

    final dcidForLevel = switch (level) {
      EncryptionLevel.initial => clientOrigDcid,
      EncryptionLevel.handshake => serverCid,
      EncryptionLevel.application => serverCid,
    };

    final pnSpace = recvPnSpaces[level]!;

    final result = decryptQuicPacketBytes2(
      packet,
      keys.key,
      keys.iv,
      keys.hp,
      dcidForLevel,
      pnSpace.largestPn,
    );

    if (result == null) {
      throw StateError("Decryption failed for $level");
    }

    pnSpace.onPacketDecrypted(result.packetNumber);
    return result;
  }

  // ============================================================
  // ACK handling
  // ============================================================

  void _onDecryptedPacket(QuicDecryptedPacket pkt, EncryptionLevel level) {
    ackStates[level]!.received.add(pkt.packetNumber);

    if (level == EncryptionLevel.initial ||
        level == EncryptionLevel.handshake) {
      sendAck(level: level);
    }
  }

  int _allocateSendPn(EncryptionLevel level) {
    final pn = nextSendPn[level]!;
    nextSendPn[level] = pn + 1;
    return pn;
  }

  void sendAck({required EncryptionLevel level}) {
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

    Uint8List ackPayload = ackFrame.encode();

    // ✅ Use the server's packet-number allocator
    final pn = _allocateSendPn(level);

    final writeKeys = switch (level) {
      EncryptionLevel.initial => initialWrite,
      EncryptionLevel.handshake => handshakeWrite,
      _ => throw StateError("ACK not supported for $level"),
    };

    if (writeKeys == null) {
      throw StateError("Write keys not available for $level");
    }

    final Uint8List dcidToUse = peerScid;
    final Uint8List scidToUse = localCid;

    Uint8List? rawPacket;

    if (level == EncryptionLevel.initial) {
      while (true) {
        rawPacket = encryptQuicPacket(
          "initial",
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

        if (rawPacket.length >= 1200) {
          break;
        }

        final deficit = 1200 - rawPacket.length;

        // Add QUIC PADDING frames (0x00) to the payload
        ackPayload = Uint8List.fromList([...ackPayload, ...Uint8List(deficit)]);
      }
    } else {
      rawPacket = encryptQuicPacket(
        "handshake",
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
    }

    socket.send(rawPacket, peerAddress, peerPort);

    print(
      "✅ Sent ACK ($level) pn=$pn acked=${ackState.received.toList()..sort()}",
    );
  }
  // ============================================================
  // Payload / CRYPTO parsing
  // ============================================================

  void _parsePayload(Uint8List plaintext, EncryptionLevel level) {
    print('--- Parsing Decrypted QUIC Payload (server) ---');

    final buffer = QuicBuffer(data: plaintext);

    try {
      while (!buffer.eof && buffer.byteData.getUint8(buffer.readOffset) != 0) {
        final frameType = buffer.pullVarInt();

        // CRYPTO
        if (frameType == 0x06) {
          final offset = buffer.pullVarInt();
          final length = buffer.pullVarInt();
          final data = buffer.pullBytes(length);

          print("✅ Server parsed CRYPTO frame offset=$offset len=$length");

          cryptoChunksByLevel[level]![offset] = data;
          final assembled = assembleCryptoStream(level);

          if (assembled.isNotEmpty) {
            receivedHandshakeByLevel[level]!.add(assembled);

            if (level == EncryptionLevel.initial) {
              _maybeHandleClientHello();
            } else if (level == EncryptionLevel.handshake) {
              _maybeHandleClientFinished();
            }
          }
        }
        // ACK
        else if (frameType == 0x02) {
          final hasEcn = (frameType & 0x01) == 0x01;
          final largest = buffer.pullVarInt();
          final delay = buffer.pullVarInt();
          final rangeCount = buffer.pullVarInt();
          final firstRange = buffer.pullVarInt();

          for (int i = 0; i < rangeCount; i++) {
            buffer.pullVarInt(); // gap
            buffer.pullVarInt(); // len
          }

          if (hasEcn) {
            buffer.pullVarInt();
            buffer.pullVarInt();
            buffer.pullVarInt();
          }

          print(
            "✅ Server parsed ACK largest=$largest delay=$delay firstRange=$firstRange",
          );
        } else {
          print(
            "ℹ️ Server skipping frame type 0x${frameType.toRadixString(16)}",
          );
        }
      }
    } catch (e, st) {
      print("🛑 Server payload parse error: $e\n$st");
    }

    print("🎉 Server payload parsing complete.");
  }

  Uint8List assembleCryptoStream(EncryptionLevel level) {
    final chunks = cryptoChunksByLevel[level]!;
    int readOffset = cryptoReadOffsetByLevel[level]!;

    final out = <int>[];
    while (chunks.containsKey(readOffset)) {
      final chunk = chunks.remove(readOffset)!;
      out.addAll(chunk);
      readOffset += chunk.length;
    }

    cryptoReadOffsetByLevel[level] = readOffset;
    return Uint8List.fromList(out);
  }

  bool _streamContainsHandshakeType(BytesBuilder bb, int expectedType) {
    final data = bb.toBytes();
    int i = 0;

    while (i + 4 <= data.length) {
      final type = data[i];
      final len = (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3];

      if (i + 4 + len > data.length) {
        break; // incomplete message
      }

      if (type == expectedType) {
        return true;
      }

      i += 4 + len;
    }

    return false;
  }

  Uint8List? _extractHandshakeMessage(BytesBuilder bb, int expectedType) {
    final data = bb.toBytes();
    int i = 0;

    while (i + 4 <= data.length) {
      final type = data[i];
      final len = (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3];

      if (i + 4 + len > data.length) {
        break;
      }

      if (type == expectedType) {
        return data.sublist(i, i + 4 + len);
      }

      i += 4 + len;
    }

    return null;
  }

  // ============================================================
  // ClientHello handling → derive handshake keys → send flight
  // ============================================================

  void _maybeHandleClientHello() {
    if (serverFlightSent) return;

    final stream = receivedHandshakeByLevel[EncryptionLevel.initial]!;
    final fullClientHello = _extractHandshakeMessage(stream, 0x01);
    if (fullClientHello == null) {
      return;
    }

    print("✅ Server has full ClientHello");

    _deriveHandshakeKeys();
    _sendServerHandshakeFlight();

    serverFlightSent = true;
  }

  void _deriveHandshakeKeys() {
    final sharedSecret = x25519ShareSecret(
      privateKey: serverPrivateKeyBytes,
      publicKey: clientPublicKey,
    );

    final helloTranscript = Uint8List.fromList([
      ...clientHelloBytes,
      ...flight.serverHello,
    ]);

    final helloHash = createHash(helloTranscript);

    final hashLen = 32;
    final zero = Uint8List(hashLen);
    final empty = Uint8List(0);
    final emptyHash = createHash(empty);

    final earlySecret = hkdfExtract(
      zero, // ikm
      salt: empty, // salt
    );

    derivedSecret = hkdfExpandLabel(
      secret: earlySecret,
      label: "derived",
      context: emptyHash,
      length: hashLen,
    );

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

    serverHsTrafficSecret = hkdfExpandLabel(
      secret: handshakeSecret,
      label: "s hs traffic",
      context: helloHash,
      length: hashLen,
    );

    final clientKey = hkdfExpandLabel(
      secret: clientHsTrafficSecret,
      label: "quic key",
      context: empty,
      length: 16,
    );
    final clientIv = hkdfExpandLabel(
      secret: clientHsTrafficSecret,
      label: "quic iv",
      context: empty,
      length: 12,
    );
    final clientHp = hkdfExpandLabel(
      secret: clientHsTrafficSecret,
      label: "quic hp",
      context: empty,
      length: 16,
    );

    final serverKey = hkdfExpandLabel(
      secret: serverHsTrafficSecret,
      label: "quic key",
      context: empty,
      length: 16,
    );
    final serverIv = hkdfExpandLabel(
      secret: serverHsTrafficSecret,
      label: "quic iv",
      context: empty,
      length: 12,
    );
    final serverHp = hkdfExpandLabel(
      secret: serverHsTrafficSecret,
      label: "quic hp",
      context: empty,
      length: 16,
    );

    // Server reads client handshake, writes server handshake
    handshakeRead = QuicKeys(key: clientKey, iv: clientIv, hp: clientHp);
    handshakeWrite = QuicKeys(key: serverKey, iv: serverIv, hp: serverHp);

    handshakeKeysReady = true;

    print("✅ Server handshake keys ready");
    print("  handshakeRead : $handshakeRead");
    print("  handshakeWrite: $handshakeWrite");
  }

  void _sendServerHandshakeFlight() {
    if (handshakeWrite == null) {
      throw StateError("Handshake write keys not ready");
    }

    final beforeFinished = Uint8List.fromList([
      ...clientHelloBytes,
      ...flight.bytesBeforeFinished(),
    ]);

    final transcriptHash = createHash(beforeFinished);

    final serverFinishedKey = hkdfExpandLabel(
      secret: serverHsTrafficSecret,
      label: "finished",
      context: Uint8List(0),
      length: 32,
    );

    final verifyData = hmacSha256(key: serverFinishedKey, data: transcriptHash);

    serverFinishedBytes = Uint8List.fromList([
      0x14,
      0x00,
      0x00,
      verifyData.length,
      ...verifyData,
    ]);

    final fullFlight = Uint8List.fromList([
      ...flight.bytesBeforeFinished(),
      ...serverFinishedBytes!,
    ]);

    transcriptThroughServerFinishedBytes = Uint8List.fromList([
      ...clientHelloBytes,
      ...fullFlight,
    ]);

    print("✅ Server built Finished verify_data=${HEX.encode(verifyData)}");

    // Fragment flight into CRYPTO frames
    const maxChunk = 1000;
    int offset = 0;

    while (offset < fullFlight.length) {
      final end = (offset + maxChunk < fullFlight.length)
          ? offset + maxChunk
          : fullFlight.length;

      final chunk = fullFlight.sublist(offset, end);
      final cryptoPayload = buildCryptoFrameAt(offset, chunk);
      final pn = _allocateSendPn(EncryptionLevel.handshake);

      final raw = encryptQuicPacket(
        "handshake",
        cryptoPayload,
        handshakeWrite!.key,
        handshakeWrite!.iv,
        handshakeWrite!.hp,
        pn,
        serverCid,
        clientOrigDcid,
        Uint8List(0),
      );

      if (raw == null) {
        throw StateError("Failed to encrypt server handshake flight packet");
      }

      socket.send(raw, peerAddress, peerPort);

      print(
        "✅ Server sent Handshake packet pn=$pn offset=$offset len=${chunk.length}",
      );

      offset = end;
    }
  }

  // ============================================================
  // Client Finished handling
  // ============================================================

  void _maybeHandleClientFinished() {
    if (clientFinishedVerified) return;

    final stream = receivedHandshakeByLevel[EncryptionLevel.handshake]!;
    final fullFinished = _extractHandshakeMessage(stream, 0x14);
    if (fullFinished == null) {
      return;
    }

    if (transcriptThroughServerFinishedBytes == null) {
      throw StateError("Server transcript through Finished not prepared");
    }

    final transcriptHash = createHash(transcriptThroughServerFinishedBytes!);

    final clientFinishedKey = hkdfExpandLabel(
      secret: clientHsTrafficSecret,
      label: "finished",
      context: Uint8List(0),
      length: 32,
    );

    final expectedVerifyData = hmacSha256(
      key: clientFinishedKey,
      data: transcriptHash,
    );

    final receivedVerifyData = fullFinished.sublist(4); // skip handshake header

    final ok = const ListEquality<int>().equals(
      expectedVerifyData,
      receivedVerifyData,
    );

    print("✅ Server received Client Finished");
    print("  expected: ${HEX.encode(expectedVerifyData)}");
    print("  actual  : ${HEX.encode(receivedVerifyData)}");

    if (!ok) {
      throw StateError("Client Finished verify_data mismatch");
    }

    clientFinishedVerified = true;
    print("✅ Client Finished verified");

    _deriveApplicationSecrets();
  }

  // ============================================================
  // Application (1-RTT) secrets
  // ============================================================

  void _deriveApplicationSecrets() {
    if (applicationSecretsDerived) return;

    final hashLen = 32;
    final zero = Uint8List(hashLen);
    final empty = Uint8List(0);

    if (transcriptThroughServerFinishedBytes == null) {
      throw StateError("Server transcript through Finished not prepared");
    }

    final transcriptHash = createHash(transcriptThroughServerFinishedBytes!);

    final masterSecret = hkdfExtract(
      zero, // ikm
      salt: derivedSecret, // salt
    );

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

    final clientKey = hkdfExpandLabel(
      secret: clientAppTrafficSecret,
      label: "quic key",
      context: empty,
      length: 16,
    );
    final clientIv = hkdfExpandLabel(
      secret: clientAppTrafficSecret,
      label: "quic iv",
      context: empty,
      length: 12,
    );
    final clientHp = hkdfExpandLabel(
      secret: clientAppTrafficSecret,
      label: "quic hp",
      context: empty,
      length: 16,
    );

    final serverKey = hkdfExpandLabel(
      secret: serverAppTrafficSecret,
      label: "quic key",
      context: empty,
      length: 16,
    );
    final serverIv = hkdfExpandLabel(
      secret: serverAppTrafficSecret,
      label: "quic iv",
      context: empty,
      length: 12,
    );
    final serverHp = hkdfExpandLabel(
      secret: serverAppTrafficSecret,
      label: "quic hp",
      context: empty,
      length: 16,
    );

    // Server reads client application, writes server application
    appRead = QuicKeys(key: clientKey, iv: clientIv, hp: clientHp);
    appWrite = QuicKeys(key: serverKey, iv: serverIv, hp: serverHp);

    applicationSecretsDerived = true;
    encryptionLevel = EncryptionLevel.application;

    print("✅ Server 1-RTT keys installed");
    print("  appRead : $appRead");
    print("  appWrite: $appWrite");
  }
}

// ============================================================
// Helpers
// ============================================================

Uint8List buildCryptoFrameAt(int offset, Uint8List data) {
  return Uint8List.fromList([
    0x06,
    ...encodeVarInt(offset),
    ...encodeVarInt(data.length),
    ...data,
  ]);
}

List<int> encodeVarInt(int value) {
  if (value < 0x40) {
    return [value];
  } else if (value < 0x4000) {
    return [0x40 | ((value >> 8) & 0x3f), value & 0xff];
  } else if (value < 0x40000000) {
    return [
      0x80 | ((value >> 24) & 0x3f),
      (value >> 16) & 0xff,
      (value >> 8) & 0xff,
      value & 0xff,
    ];
  } else {
    throw ArgumentError("varint too large for this helper: $value");
  }
}
