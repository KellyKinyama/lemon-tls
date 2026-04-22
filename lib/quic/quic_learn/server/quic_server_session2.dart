import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:hex/hex.dart';
import '../fingerprint.dart';

import '../../buffer.dart';
// import '../frames/quic_frames.dart';
import '../../handshake/client_hello.dart';
import '../../handshake/server_hello.dart';
import '../../hash.dart';
import '../../hkdf.dart';
import '../../packet/quic_packet.dart';
import '../../quic_ack.dart';
import '../../utils.dart';
import '../../cipher/x25519.dart';

import 'package:x25519/x25519.dart' as ecdhe;

import '../cert_utils.dart';
import '../../handshake/tls_server_builder.dart';
// import '../h3.dart';
import '../h31.dart';
import 'constants.dart';

class KeyPair {
  final Uint8List _privateKey;

  KeyPair._(this._privateKey);

  /// Raw 32-byte X25519 public key.
  /// Raw 32-byte X25519 public key.
  Uint8List get publicKeyBytes {
    // Public key = X25519(privateKey, basePoint)
    final pub = ecdhe.X25519(_privateKey, ecdhe.basePoint);
    return Uint8List.fromList(pub);
  }

  /// Raw 32-byte X25519 private key.
  Uint8List get privateKeyBytes => Uint8List.fromList(_privateKey);

  static KeyPair generate() {
    final seed = Uint8List(32);
    final rnd = math.Random.secure();
    for (var i = 0; i < seed.length; i++) {
      seed[i] = rnd.nextInt(256);
    }
    return KeyPair._(seed);
  }
}

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

// enum EncryptionLevel { initial, handshake, application }

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
  late final InternetAddress peerAddress;
  late final int peerPort;

  /// This is the server CID that your current client expects to see as DCID
  /// on packets from the server.
  // final Uint8List serverCid = Uint8List.fromList(HEX.decode("635f636964"));

  /// This becomes the client’s original Initial DCID (000102... in your tests)
  // late Uint8List clientOrigDcid;

  /// The client currently hardcodes this exact ClientHello.

  EncryptionLevel encryptionLevel = EncryptionLevel.initial;

  QuicKeys? initialRead, initialWrite;
  QuicKeys? handshakeRead, handshakeWrite;
  QuicKeys? appRead, appWrite;

  late Uint8List derivedSecret;
  late Uint8List clientHsTrafficSecret;
  late Uint8List serverHsTrafficSecret;

  Uint8List? serverFinishedBytes;
  Uint8List? transcriptThroughServerFinishedBytes;

  late Uint8List encryptedExtensions; // built earlier
  late Uint8List certificate; // built earlier
  late Uint8List certificateVerify; // built earlier

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

  // final peerScid = Uint8List.fromList(HEX.decode("635f636964"));
  // final localCid = Uint8List.fromList(HEX.decode("0001020304050607"));

  EcdsaCert serverCert = generateSelfSignedCertificate();
  KeyPair keyPair = KeyPair.generate();

  late ClientHello ch;

  // Full TLS ClientHello handshake message (type + len + body)
  Uint8List? fullClientHelloBytes;

  // Full TLS ServerHello handshake message (type + len + body)
  Uint8List? serverHelloBytes;

  // Full TLS ClientHello handshake message (type + 3-byte length + body)
  Uint8List? clientHelloMsg;

  // Full TLS ServerHello handshake message (type + 3-byte length + body)
  Uint8List? serverHelloMsg;

  QuicServerSession({
    required this.socket,
    // required this.peerAddress,
    // required this.peerPort,
  }) {
    print("Server certificate hash: ${fingerprint(serverCert.fingerPrint)}");
    localCid = _randomCid(8);
  }

  Uint8List _randomCid([int len = 8]) {
    final rnd = math.Random.secure();
    return Uint8List.fromList(List.generate(len, (_) => rnd.nextInt(256)));
  }

  // QuicServerSession(this.dcid, this.socket);

  // ============================================================
  // Public entry point
  // ============================================================

  // void handleDatagram(Uint8List pkt) {
  //   final packetLevel = detectPacketLevel(pkt);
  //   print("📥 Server received packet level=$packetLevel len=${pkt.length}");

  //   if (!initialKeysReady) {
  //     _deriveInitialKeysFromFirstPacket(pkt);
  //   }

  //   final decrypted = decryptPacket(pkt, packetLevel);
  //   _onDecryptedPacket(decrypted, packetLevel);

  //   _parsePayload(decrypted.plaintext!, packetLevel);
  // }

  void handleDatagram(Uint8List pkt) {
    final packetLevel = detectPacketLevel(pkt);
    print("📥 Server received packet level=$packetLevel len=${pkt.length}");

    // --------------------------------------------------
    // 1. Initial keys must ONLY be derived from Initial packets
    // --------------------------------------------------
    if (!initialKeysReady) {
      if (packetLevel != EncryptionLevel.initial) {
        print("ℹ️ Ignoring non-Initial packet before initial keys are ready");
        return;
      }
      _deriveInitialKeysFromFirstPacket(pkt);
    }

    // --------------------------------------------------
    // 2. QUIC tolerance: ignore packets we cannot yet decrypt
    // --------------------------------------------------
    if (packetLevel == EncryptionLevel.handshake && handshakeRead == null) {
      print("ℹ️ Ignoring early Handshake packet (handshake keys not ready)");
      return;
    }

    if (packetLevel == EncryptionLevel.application &&
        !applicationSecretsDerived) {
      print("ℹ️ Ignoring early Application packet (1-RTT keys not ready)");
      return;
    }

    // --------------------------------------------------
    // 3. Decrypt packet
    // --------------------------------------------------
    final decrypted = decryptPacket(pkt, packetLevel);

    // --------------------------------------------------
    // 4. Parse payload and decide if packet is ack-eliciting
    // --------------------------------------------------
    final ackEliciting = _parsePayload(decrypted.plaintext!, packetLevel);

    // --------------------------------------------------
    // 5. ACK scheduling happens in ONE place only
    // --------------------------------------------------
    _onDecryptedPacket(decrypted, packetLevel, ackEliciting);
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

  // void _deriveInitialKeysFromFirstPacket(Uint8List pkt) {
  //   final cids = _extractLongHeaderCids(pkt);
  //   clientOrigDcid = cids.$1;

  //   final initialSalt = Uint8List.fromList(
  //     HEX.decode("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
  //   );

  //   final initialSecret = hkdfExtract(
  //     clientOrigDcid, // ikm
  //     salt: initialSalt,
  //   );

  //   final clientSecret = hkdfExpandLabel(
  //     secret: initialSecret,
  //     label: "client in",
  //     context: Uint8List(0),
  //     length: 32,
  //   );

  //   final serverSecret = hkdfExpandLabel(
  //     secret: initialSecret,
  //     label: "server in",
  //     context: Uint8List(0),
  //     length: 32,
  //   );

  //   final clientKey = hkdfExpandLabel(
  //     secret: clientSecret,
  //     label: "quic key",
  //     context: Uint8List(0),
  //     length: 16,
  //   );
  //   final clientIv = hkdfExpandLabel(
  //     secret: clientSecret,
  //     label: "quic iv",
  //     context: Uint8List(0),
  //     length: 12,
  //   );
  //   final clientHp = hkdfExpandLabel(
  //     secret: clientSecret,
  //     label: "quic hp",
  //     context: Uint8List(0),
  //     length: 16,
  //   );

  //   final serverKey = hkdfExpandLabel(
  //     secret: serverSecret,
  //     label: "quic key",
  //     context: Uint8List(0),
  //     length: 16,
  //   );
  //   final serverIv = hkdfExpandLabel(
  //     secret: serverSecret,
  //     label: "quic iv",
  //     context: Uint8List(0),
  //     length: 12,
  //   );
  //   final serverHp = hkdfExpandLabel(
  //     secret: serverSecret,
  //     label: "quic hp",
  //     context: Uint8List(0),
  //     length: 16,
  //   );

  //   // Server reads client Initial, writes server Initial
  //   initialRead = QuicKeys(key: clientKey, iv: clientIv, hp: clientHp);
  //   initialWrite = QuicKeys(key: serverKey, iv: serverIv, hp: serverHp);

  //   initialKeysReady = true;

  //   print("✅ Server Initial keys ready");
  //   print("  initialRead : $initialRead");
  //   print("  initialWrite: $initialWrite");
  // }

  void _deriveInitialKeysFromFirstPacket(Uint8List pkt) {
    final cids = _extractLongHeaderCids(pkt);

    // Client's Original Destination CID (used for Initial secrets)
    clientOrigDcid = cids.$1;

    // Client's Source CID (used as DCID on packets we send back)
    peerScid = cids.$2;

    final initialSalt = Uint8List.fromList(
      HEX.decode("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    );

    final initialSecret = hkdfExtract(clientOrigDcid, salt: initialSalt);

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
    print("  clientOrigDcid: ${HEX.encode(clientOrigDcid)}");
    print("  peerScid      : ${HEX.encode(peerScid)}");
    print("  localCid      : ${HEX.encode(localCid)}");
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

    // ============================================================
    // QUIC DCID selection for packet decryption
    // ============================================================
    // Initial:
    //   Use the client's Original Destination CID
    //   (this is what Initial secrets are derived from)
    //
    // Handshake / Application:
    //   Use the server's own chosen CID (localCid),
    //   because the client now sends packets addressed to the server CID.
    // ============================================================
    final dcidForLevel = switch (level) {
      EncryptionLevel.initial => clientOrigDcid,
      EncryptionLevel.handshake => localCid,
      EncryptionLevel.application => localCid,
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

    // Update packet number space only after successful decryption
    pnSpace.onPacketDecrypted(result.packetNumber);

    return result;
  }

  // ============================================================
  // ACK handling
  // ============================================================

  void _onDecryptedPacket(
    QuicDecryptedPacket pkt,
    EncryptionLevel level,
    bool ackEliciting,
  ) {
    // Track all received packet numbers in that PN space
    ackStates[level]!.received.add(pkt.packetNumber);

    // ACK only if the packet was ack-eliciting
    if (!ackEliciting) {
      return;
    }

    // After handshake completion, all ACKs must be sent at application level
    if (handshakeComplete) {
      sendAck(level: EncryptionLevel.application);
      return;
    }

    // Before handshake completion, ACK in the same level/space
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

    final pn = _allocateSendPn(level);

    final writeKeys = switch (level) {
      EncryptionLevel.initial => initialWrite,
      EncryptionLevel.handshake => handshakeWrite,
      EncryptionLevel.application => appWrite,
      _ => throw StateError("ACK not supported for $level"),
    };

    if (writeKeys == null) {
      throw StateError("Write keys not available for $level");
    }

    final Uint8List dcidToUse = peerScid;
    final Uint8List scidToUse = localCid;

    Uint8List? rawPacket;

    if (level == EncryptionLevel.initial) {
      // Initial packets MUST be padded to >= 1200 bytes
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

        if (rawPacket.length >= 1200) break;

        final deficit = 1200 - rawPacket.length;
        ackPayload = Uint8List.fromList([...ackPayload, ...Uint8List(deficit)]);
      }
    } else if (level == EncryptionLevel.handshake) {
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
    } else {
      // ✅ Application ACKs MUST use short-header packets
      rawPacket = encryptQuicPacket(
        "short",
        ackPayload,
        writeKeys.key,
        writeKeys.iv,
        writeKeys.hp,
        pn,
        dcidToUse,
        scidToUse,
        Uint8List(0),
      );
    }

    if (handshakeComplete && level != EncryptionLevel.application) {
      throw StateError("BUG: non-application ACK after handshake");
    }

    if (rawPacket == null) {
      print("❌ Failed to encrypt ACK ($level)");
      return;
    }

    socket.send(rawPacket, peerAddress, peerPort);

    print(
      "✅ Sent ACK ($level) pn=$pn acked=${ackState.received.toList()..sort()}",
    );
  }

  late Uint8List peerScid; // client's source CID (from first Initial)
  late Uint8List localCid; // server's chosen CID
  late Uint8List clientOrigDcid;

  // ============================================================
  // Payload / CRYPTO parsing
  // ============================================================

  /// =============================================================
  /// Hardened server-side QUIC payload parser
  ///  - Exhaustion-driven (no sentinel bytes)
  ///  - Correct ACK (0x02) and ACK+ECN (0x03) handling
  ///  - Correctly identifies ack-eliciting packets
  ///  - Prevents ACK-of-ACK loops
  /// =============================================================

  // bool _parsePayload(Uint8List plaintext, EncryptionLevel level) {
  //   print('--- Parsing Decrypted QUIC Payload (server) ---');

  //   final buffer = QuicBuffer(data: plaintext);
  //   bool ackEliciting = false;

  //   try {
  //     while (buffer.remaining > 0) {
  //       final frameType = buffer.pullVarInt();

  //       // =========================================================
  //       // PADDING (0x00) — single byte, not ack-eliciting
  //       // =========================================================
  //       if (frameType == 0x00) {
  //         continue;
  //       }

  //       // =========================================================
  //       // PING (0x01) — ack-eliciting
  //       // =========================================================
  //       if (frameType == 0x01) {
  //         print('✅ Server parsed PING');
  //         ackEliciting = true;
  //         continue;
  //       }

  //       // =========================================================
  //       // CRYPTO (0x06) — ack-eliciting
  //       // =========================================================
  //       if (frameType == 0x06) {
  //         if (buffer.remaining == 0) break;
  //         final offset = buffer.pullVarInt();

  //         if (buffer.remaining == 0) break;
  //         final length = buffer.pullVarInt();

  //         if (buffer.remaining < length) {
  //           print(
  //             '🛑 Server CRYPTO frame truncated: need $length, have ${buffer.remaining}',
  //           );
  //           break;
  //         }

  //         final data = buffer.pullBytes(length);

  //         print('✅ Server parsed CRYPTO frame offset=$offset len=$length');
  //         ackEliciting = true;

  //         cryptoChunksByLevel[level]![offset] = data;
  //         final assembled = assembleCryptoStream(level);

  //         if (assembled.isNotEmpty) {
  //           receivedHandshakeByLevel[level]!.add(assembled);

  //           if (level == EncryptionLevel.initial) {
  //             _maybeHandleClientHello();
  //           } else if (level == EncryptionLevel.handshake) {
  //             _maybeHandleClientFinished();
  //           }
  //         }
  //         continue;
  //       }

  //       // =========================================================
  //       // ACK (0x02) / ACK + ECN (0x03) — NOT ack-eliciting
  //       // =========================================================
  //       if (frameType == 0x02 || frameType == 0x03) {
  //         final hasEcn = (frameType & 0x01) == 0x01;

  //         if (buffer.remaining == 0) break;
  //         final largest = buffer.pullVarInt();

  //         if (buffer.remaining == 0) break;
  //         final delay = buffer.pullVarInt();

  //         if (buffer.remaining == 0) break;
  //         final rangeCount = buffer.pullVarInt();

  //         if (buffer.remaining == 0) break;
  //         final firstRange = buffer.pullVarInt();

  //         for (int i = 0; i < rangeCount; i++) {
  //           if (buffer.remaining == 0) break;
  //           buffer.pullVarInt(); // gap

  //           if (buffer.remaining == 0) break;
  //           buffer.pullVarInt(); // len
  //         }

  //         if (hasEcn) {
  //           if (buffer.remaining == 0) break;
  //           buffer.pullVarInt(); // ect0

  //           if (buffer.remaining == 0) break;
  //           buffer.pullVarInt(); // ect1

  //           if (buffer.remaining == 0) break;
  //           buffer.pullVarInt(); // ce
  //         }

  //         print(
  //           '✅ Server parsed ACK largest=$largest delay=$delay firstRange=$firstRange',
  //         );
  //         continue;
  //       }

  //       // =========================================================
  //       // CONNECTION_CLOSE (transport: 0x1c, application: 0x1d)
  //       // =========================================================
  //       if (frameType == 0x1c || frameType == 0x1d) {
  //         if (buffer.remaining == 0) break;
  //         final errorCode = buffer.pullVarInt();

  //         int? offendingFrameType;
  //         if (frameType == 0x1c) {
  //           if (buffer.remaining == 0) break;
  //           offendingFrameType = buffer.pullVarInt();
  //         }

  //         if (buffer.remaining == 0) break;
  //         final reasonLen = buffer.pullVarInt();

  //         if (buffer.remaining < reasonLen) {
  //           print(
  //             '🛑 Server CONNECTION_CLOSE reason truncated: need $reasonLen, have ${buffer.remaining}',
  //           );
  //           break;
  //         }

  //         final reasonBytes = reasonLen > 0
  //             ? buffer.pullBytes(reasonLen)
  //             : Uint8List(0);

  //         final reason = utf8.decode(reasonBytes, allowMalformed: true);

  //         print(
  //           '🛑 Server parsed CONNECTION_CLOSE '
  //           'frameType=0x${frameType.toRadixString(16)} '
  //           'errorCode=0x${errorCode.toRadixString(16)} '
  //           '${offendingFrameType != null ? 'offendingFrameType=0x${offendingFrameType.toRadixString(16)} ' : ''}'
  //           'reason="$reason"',
  //         );
  //         break;
  //       }

  //       // =========================================================
  //       // Unknown / unsupported frame — stop safely
  //       // =========================================================
  //       print(
  //         'ℹ️ Server stopping on unsupported frame type 0x${frameType.toRadixString(16)}',
  //       );
  //       break;
  //     }
  //   } catch (e, st) {
  //     print('🛑 Server payload parse error: $e\n$st');
  //   }

  //   print('🎉 Server payload parsing complete.');
  //   return ackEliciting;
  // }

  // ============================================================
  // HTTP/3 + WebTransport state
  // ============================================================

  final Http3State h3 = Http3State();

  // QUIC stream ID allocation (server side)
  int nextServerBidiStreamId = 1; // server-initiated bidirectional
  int nextServerUniStreamId = 3; // server-initiated unidirectional

  void sendHttp3ControlStream() {
    if (h3.controlStreamSent) return;
    if (!applicationSecretsDerived || appWrite == null) {
      throw StateError('Cannot send HTTP/3 control stream before 1-RTT keys');
    }

    final settingsPayload = build_settings_frame({
      'SETTINGS_QPACK_MAX_TABLE_CAPACITY': 0,
      'SETTINGS_QPACK_BLOCKED_STREAMS': 0,
      'SETTINGS_ENABLE_CONNECT_PROTOCOL': 1,
      'SETTINGS_ENABLE_WEBTRANSPORT': 1,
      'SETTINGS_H3_DATAGRAM': 1,
    });

    final controlStreamBytes = Uint8List.fromList([
      ...writeVarInt(H3_STREAM_TYPE_CONTROL),
      ...writeVarInt(H3_FRAME_SETTINGS),
      ...writeVarInt(settingsPayload.length),
      ...settingsPayload,
    ]);

    sendApplicationUnidirectionalStream(controlStreamBytes, fin: false);

    h3.controlStreamSent = true;
    print('✅ HTTP/3 control stream sent');
  }

  void handleHttp3StreamChunk(
    int streamId,
    int streamOffset,
    Uint8List streamData, {
    required bool fin,
  }) {
    final chunks = h3.streamChunks.putIfAbsent(
      streamId,
      () => <int, Uint8List>{},
    );
    final readOffset = h3.streamReadOffsets[streamId] ?? 0;

    // IMPORTANT: store by QUIC stream offset, not arrival order
    chunks[streamOffset] = streamData;

    final extracted = extract_h3_frames_from_chunks(chunks, readOffset);
    h3.streamReadOffsets[streamId] = extracted['new_from_offset'] as int;

    for (final frame in extracted['frames']) {
      final int type = frame['frame_type'] as int;
      final Uint8List payload = frame['payload'] as Uint8List;

      if (type == H3_FRAME_HEADERS) {
        _handleHttp3HeadersFrame(streamId, payload);
        continue;
      }

      if (type == H3_FRAME_DATA) {
        print('📦 HTTP/3 DATA on stream=$streamId len=${payload.length}');
        // Add request-body handling here later if needed
        continue;
      }

      if (type == H3_FRAME_SETTINGS) {
        print('ℹ️ Ignoring unexpected SETTINGS on stream=$streamId');
        continue;
      }

      print(
        'ℹ️ Ignoring unsupported HTTP/3 frame type '
        '0x${type.toRadixString(16)} on stream=$streamId',
      );
    }

    if (fin) {
      print('✅ QUIC stream $streamId FIN received');
    }
  }

  void _acceptWebTransportSession(int streamId) {
    if (h3.webTransportSessions.containsKey(streamId)) {
      print('ℹ️ WebTransport session already exists on stream $streamId');
      return;
    }

    print('✅ WebTransport session accepted on stream $streamId');

    h3.webTransportSessions[streamId] = WebTransportSession(streamId);

    final responseHeaderBlock = build_http3_literal_headers_frame({
      ':status': '200',
      'sec-webtransport-http3-draft': 'draft02',
    });

    final frames = build_h3_frames([
      {'frame_type': H3_FRAME_HEADERS, 'payload': responseHeaderBlock},
    ]);

    sendApplicationStream(streamId, frames, fin: false);
  }

  void _handleHttp3HeadersFrame(int streamId, Uint8List headerBlock) {
    final headers = decode_qpack_header_fields(headerBlock);

    String method = '';
    String path = '';
    String protocol = '';

    for (final h in headers) {
      if (h.name == ':method') method = h.value;
      if (h.name == ':path') path = h.value;
      if (h.name == ':protocol') protocol = h.value;
    }

    // ----------------------------------------------------------
    // WebTransport CONNECT
    // ----------------------------------------------------------
    if (method == 'CONNECT' && protocol == WT_PROTOCOL) {
      _acceptWebTransportSession(streamId);
      return;
    }

    // ----------------------------------------------------------
    // Normal HTTP/3 request
    // ----------------------------------------------------------
    print('📥 HTTP/3 request on stream $streamId: $method $path');

    final body = Uint8List.fromList(utf8.encode('hello from http/3'));

    final responseHeaderBlock = build_http3_literal_headers_frame({
      ':status': '200',
      'content-type': 'text/plain; charset=utf-8',
      'content-length': body.length,
    });

    final responseFrames = build_h3_frames([
      {'frame_type': H3_FRAME_HEADERS, 'payload': responseHeaderBlock},
      {'frame_type': H3_FRAME_DATA, 'payload': body},
    ]);

    sendApplicationStream(streamId, responseFrames, fin: true);
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

    print('📦 WebTransport datagram session=$sessionId len=${data.length}');

    // Echo example
    sendWebTransportDatagram(sessionId, data);
  }

  void sendApplicationStream(
    int streamId,
    Uint8List data, {
    bool fin = false,
    int offset = 0,
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

    final pn = _allocateSendPn(EncryptionLevel.application);

    final raw = encryptQuicPacket(
      'short',
      frame,
      appWrite!.key,
      appWrite!.iv,
      appWrite!.hp,
      pn,
      peerScid, // DCID = peer/client CID
      localCid, // SCID = our/server CID
      Uint8List(0),
    );

    if (raw == null) {
      throw StateError('Failed to encrypt application STREAM packet');
    }

    socket.send(raw, peerAddress, peerPort);

    print(
      '✅ Sent application STREAM pn=$pn streamId=$streamId '
      'len=${data.length} fin=$fin',
    );
  }

  int _allocateServerUniStreamId() {
    final id = nextServerUniStreamId;
    nextServerUniStreamId += 4;
    return id;
  }

  void sendApplicationUnidirectionalStream(Uint8List data, {bool fin = false}) {
    final streamId = _allocateServerUniStreamId();
    sendApplicationStream(streamId, data, fin: fin, offset: 0);
  }

  void sendWebTransportDatagram(int sessionId, Uint8List data) {
    if (!applicationSecretsDerived || appWrite == null) {
      throw StateError('Cannot send WebTransport DATAGRAM before 1-RTT keys');
    }

    final payload = Uint8List.fromList([...writeVarInt(sessionId), ...data]);

    final frame = _buildDatagramFrame(payload, useLengthField: true);

    final pn = _allocateSendPn(EncryptionLevel.application);

    final raw = encryptQuicPacket(
      'short',
      frame,
      appWrite!.key,
      appWrite!.iv,
      appWrite!.hp,
      pn,
      peerScid,
      localCid,
      Uint8List(0),
    );

    if (raw == null) {
      throw StateError('Failed to encrypt DATAGRAM packet');
    }

    socket.send(raw, peerAddress, peerPort);

    print(
      '✅ Sent WebTransport DATAGRAM pn=$pn session=$sessionId len=${data.length}',
    );
  }

  Uint8List _buildStreamFrame({
    required int streamId,
    required Uint8List data,
    int offset = 0,
    bool fin = false,
  }) {
    // STREAM frame type bits:
    // 0x08 base
    // 0x01 FIN
    // 0x02 LEN present
    // 0x04 OFF present
    int frameType = 0x08;

    if (fin) frameType |= 0x01;
    frameType |= 0x02; // always include LEN
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
      // 0x31 = DATAGRAM with explicit length
      return Uint8List.fromList([
        ...writeVarInt(0x31),
        ...writeVarInt(payload.length),
        ...payload,
      ]);
    }

    // 0x30 = DATAGRAM to end-of-packet
    return Uint8List.fromList([...writeVarInt(0x30), ...payload]);
  }

  bool _parsePayload(Uint8List plaintext, EncryptionLevel level) {
    print('--- Parsing Decrypted QUIC Payload (server) ---');

    final buffer = QuicBuffer(data: plaintext);
    bool ackEliciting = false;

    try {
      while (buffer.remaining > 0) {
        final frameType = buffer.pullVarInt();

        // =========================================================
        // PADDING (0x00) — single byte, not ack-eliciting
        // =========================================================
        if (frameType == 0x00) {
          continue;
        }

        // =========================================================
        // PING (0x01) — ack-eliciting
        // =========================================================
        if (frameType == 0x01) {
          print('✅ Server parsed PING');
          ackEliciting = true;
          continue;
        }

        // =========================================================
        // ACK (0x02) / ACK + ECN (0x03) — NOT ack-eliciting
        // =========================================================
        if (frameType == 0x02 || frameType == 0x03) {
          final hasEcn = (frameType & 0x01) == 0x01;

          if (buffer.remaining == 0) break;
          final largest = buffer.pullVarInt();

          if (buffer.remaining == 0) break;
          final delay = buffer.pullVarInt();

          if (buffer.remaining == 0) break;
          final rangeCount = buffer.pullVarInt();

          if (buffer.remaining == 0) break;
          final firstRange = buffer.pullVarInt();

          for (int i = 0; i < rangeCount; i++) {
            if (buffer.remaining == 0) break;
            buffer.pullVarInt(); // gap

            if (buffer.remaining == 0) break;
            buffer.pullVarInt(); // range length
          }

          if (hasEcn) {
            if (buffer.remaining == 0) break;
            buffer.pullVarInt(); // ect0

            if (buffer.remaining == 0) break;
            buffer.pullVarInt(); // ect1

            if (buffer.remaining == 0) break;
            buffer.pullVarInt(); // ce
          }

          print(
            '✅ Server parsed ACK largest=$largest delay=$delay firstRange=$firstRange',
          );
          continue;
        }

        // =========================================================
        // CRYPTO (0x06) — ack-eliciting
        // =========================================================
        if (frameType == 0x06) {
          if (buffer.remaining == 0) break;
          final offset = buffer.pullVarInt();

          if (buffer.remaining == 0) break;
          final length = buffer.pullVarInt();

          if (buffer.remaining < length) {
            print(
              '🛑 Server CRYPTO frame truncated: need $length, have ${buffer.remaining}',
            );
            break;
          }

          final data = buffer.pullBytes(length);

          print('✅ Server parsed CRYPTO frame offset=$offset len=$length');
          ackEliciting = true;

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
          continue;
        }

        // =========================================================
        // STREAM frames (0x08..0x0f) — ack-eliciting
        // =========================================================
        if ((frameType & 0xF8) == 0x08) {
          final fin = (frameType & 0x01) != 0;
          final hasLen = (frameType & 0x02) != 0;
          final hasOff = (frameType & 0x04) != 0;

          if (buffer.remaining == 0) break;
          final streamId = buffer.pullVarInt();

          final streamOffset = hasOff ? buffer.pullVarInt() : 0;

          final dataLen = hasLen ? buffer.pullVarInt() : buffer.remaining;

          if (buffer.remaining < dataLen) {
            print(
              '🛑 Server STREAM frame truncated: need $dataLen, have ${buffer.remaining}',
            );
            break;
          }

          final data = buffer.pullBytes(dataLen);

          print(
            '✅ Server parsed STREAM '
            'streamId=$streamId offset=$streamOffset len=$dataLen fin=$fin',
          );

          ackEliciting = true;

          // Only application-level streams are HTTP/3 / WebTransport
          if (level == EncryptionLevel.application) {
            handleHttp3StreamChunk(
              // this,
              streamId,
              streamOffset,
              data,
              fin: fin,
            );
          } else {
            print('ℹ️ Ignoring non-application STREAM frame on level=$level');
          }

          continue;
        }

        // =========================================================
        // DATAGRAM (0x30 no length, 0x31 with length) — ack-eliciting
        // =========================================================
        if (frameType == 0x30 || frameType == 0x31) {
          final hasLen = frameType == 0x31;

          final datagramLen = hasLen ? buffer.pullVarInt() : buffer.remaining;

          if (buffer.remaining < datagramLen) {
            print(
              '🛑 Server DATAGRAM frame truncated: need $datagramLen, have ${buffer.remaining}',
            );
            break;
          }

          final payload = buffer.pullBytes(datagramLen);

          print('✅ Server parsed DATAGRAM len=${payload.length}');
          ackEliciting = true;

          if (level == EncryptionLevel.application) {
            handleWebTransportDatagram(payload);
          } else {
            print('ℹ️ Ignoring non-application DATAGRAM frame on level=$level');
          }

          continue;
        }

        // =========================================================
        // HANDSHAKE_DONE (0x1e) — ack-eliciting
        // =========================================================
        if (frameType == 0x1e) {
          print('✅ Server parsed HANDSHAKE_DONE');
          ackEliciting = true;
          continue;
        }

        // =========================================================
        // CONNECTION_CLOSE (transport: 0x1c, application: 0x1d)
        // =========================================================
        if (frameType == 0x1c || frameType == 0x1d) {
          if (buffer.remaining == 0) break;
          final errorCode = buffer.pullVarInt();

          int? offendingFrameType;
          if (frameType == 0x1c) {
            if (buffer.remaining == 0) break;
            offendingFrameType = buffer.pullVarInt();
          }

          if (buffer.remaining == 0) break;
          final reasonLen = buffer.pullVarInt();

          if (buffer.remaining < reasonLen) {
            print(
              '🛑 Server CONNECTION_CLOSE reason truncated: need $reasonLen, have ${buffer.remaining}',
            );
            break;
          }

          final reasonBytes = reasonLen > 0
              ? buffer.pullBytes(reasonLen)
              : Uint8List(0);

          final reason = utf8.decode(reasonBytes, allowMalformed: true);

          print(
            '🛑 Server parsed CONNECTION_CLOSE '
            'frameType=0x${frameType.toRadixString(16)} '
            'errorCode=0x${errorCode.toRadixString(16)} '
            '${offendingFrameType != null ? 'offendingFrameType=0x${offendingFrameType.toRadixString(16)} ' : ''}'
            'reason="$reason"',
          );
          break;
        }

        // =========================================================
        // Unknown / unsupported frame — stop safely
        // =========================================================
        print(
          'ℹ️ Server stopping on unsupported frame type 0x${frameType.toRadixString(16)}',
        );
        break;
      }
    } catch (e, st) {
      print('🛑 Server payload parse error: $e\n$st');
    }

    print('🎉 Server payload parsing complete.');
    return ackEliciting;
  }

  /// =============================================================
  /// IMPORTANT CALLER-SIDE RULE
  /// Only send ACKs for ack-eliciting packets
  /// =============================================================
  ///
  /// final ackEliciting = _parsePayload(plaintext, level);
  /// if (ackEliciting) {
  ///   sendAck(level: level);
  /// }

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
  late final Uint8List serverRandom = Uint8List.fromList(
    List.generate(32, (_) => math.Random.secure().nextInt(256)),
  );

  void _maybeHandleClientHello() {
    if (serverFlightSent) return;

    // --------------------------------------------------
    // 1. Access Initial CRYPTO stream
    // --------------------------------------------------
    final BytesBuilder stream =
        receivedHandshakeByLevel[EncryptionLevel.initial]!;

    final Uint8List? msg = _extractHandshakeMessage(stream, 0x01);
    if (msg == null) {
      return;
    }

    // --------------------------------------------------
    // 2. Store raw ClientHello handshake bytes
    // --------------------------------------------------
    clientHelloMsg = msg;

    // --------------------------------------------------
    // 3. Parse ClientHello
    // --------------------------------------------------
    final ClientHello clientHello = ClientHello.parse_tls_client_hello(
      msg.sublist(4), // strip handshake header
    );

    print("✅ Server has full ClientHello");

    // --------------------------------------------------
    // 4. Select ALPN
    // --------------------------------------------------
    // If the parser exposes ALPNs, choose from what the client offered.
    // Otherwise fall back to the quic-go example protocol.
    final List<String> clientOfferedAlpns = clientHello.alpnProtocols.isEmpty
        ? <String>[]
        : clientHello.alpnProtocols;

    final String selectedAlpn = clientOfferedAlpns.isEmpty
        ? alpnQuicEchoExample
        : chooseServerAlpn(clientOfferedAlpns);

    print("✅ Client offered ALPNs: $clientOfferedAlpns");
    print("✅ Server selected ALPN: $selectedAlpn");

    // --------------------------------------------------
    // 5. Derive handshake keys and build ServerHello
    //    (sets serverHelloMsg)
    // --------------------------------------------------
    _deriveHandshakeKeys(clientHello);

    if (serverHelloMsg == null) {
      throw StateError("serverHelloMsg not initialized");
    }

    // --------------------------------------------------
    // 6. Build server handshake artifacts
    //    ✅ IMPORTANT:
    //    transcript prefix = CH || SH
    //    builder appends EE || Certificate before CertificateVerify
    // --------------------------------------------------
    final ServerHandshakeArtifacts artifacts = buildServerHandshakeArtifacts(
      serverRandom: serverRandom,
      serverPublicKey: keyPair.publicKeyBytes,
      serverCert: serverCert,

      transcriptPrefixBeforeCertVerify: Uint8List.fromList([
        ...clientHelloMsg!,
        ...serverHelloMsg!,
      ]),

      alpnProtocol: selectedAlpn,

      // REQUIRED QUIC transport parameters
      originalDestinationConnectionId: clientOrigDcid,
      initialSourceConnectionId: localCid,
    );

    // --------------------------------------------------
    // 7. STORE late handshake variables (CRITICAL)
    // --------------------------------------------------
    _storeServerHandshakeArtifacts(artifacts);

    // --------------------------------------------------
    // 8. Send server handshake flight
    // --------------------------------------------------
    _sendServerHandshakeFlight();

    serverFlightSent = true;
  }

  late Uint8List handshakeSecret;

  void _deriveHandshakeKeys(ClientHello clientHello) {
    // ✅ Extract X25519 key share from parsed object
    final keyShare = clientHello.keyShares!.firstWhere(
      (ks) => ks.group == 0x001d,
      orElse: () => throw StateError("No X25519 key_share"),
    );

    // --------------------------------------------------
    // 2. Compute ECDHE shared secret (SERVER SIDE)
    // --------------------------------------------------

    final sharedSecret = x25519ShareSecret(
      privateKey: keyPair.privateKeyBytes, // ✅ server private key
      publicKey: keyShare.pub, // ✅ client public key
    );

    // ✅ Build ServerHello ONCE and store raw bytes
    serverHelloMsg = buildServerHello(
      serverRandom: serverRandom,
      publicKey: keyPair.publicKeyBytes, // ✅ from KeyPai
      sessionId: Uint8List(0),
      cipherSuite: 0x1301,
      group: keyShare.group,
    );

    // ✅ Transcript = raw ClientHello || raw ServerHello
    final helloTranscript = Uint8List.fromList([
      ...clientHelloMsg!,
      ...serverHelloMsg!,
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

    handshakeSecret = hkdfExtract(
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

  void _storeServerHandshakeArtifacts(ServerHandshakeArtifacts artifacts) {
    encryptedExtensions = artifacts.encryptedExtensions;
    certificate = artifacts.certificate;
    certificateVerify = artifacts.certificateVerify;

    print("✅ Server handshake artifacts stored");
    print("  encryptedExtensions: ${encryptedExtensions.length} bytes");
    print("  certificate        : ${certificate.length} bytes");
    print("  certificateVerify  : ${certificateVerify.length} bytes");
  }

  bool serverHandshakeFinished = false;

  void _sendServerHandshakeFlight() {
    // --------------------------------------------------
    // Preconditions
    // --------------------------------------------------
    if (initialWrite == null) {
      throw StateError("Initial write keys not ready");
    }
    if (handshakeWrite == null) {
      throw StateError("Handshake write keys not ready");
    }
    if (clientHelloMsg == null || serverHelloMsg == null) {
      throw StateError("Handshake transcript not initialized");
    }

    // --------------------------------------------------
    // 1. Build TLS Finished (RFC 8446 §4.4.4)
    // --------------------------------------------------
    final handshakeBeforeFinished = Uint8List.fromList([
      ...clientHelloMsg!,
      ...serverHelloMsg!,
      ...encryptedExtensions,
      ...certificate,
      ...certificateVerify,
    ]);

    final transcriptHash = createHash(handshakeBeforeFinished);

    final serverFinishedKey = hkdfExpandLabel(
      secret: serverHsTrafficSecret,
      label: "finished",
      context: Uint8List(0),
      length: 32,
    );

    final verifyData = hmacSha256(key: serverFinishedKey, data: transcriptHash);

    serverFinishedBytes = Uint8List.fromList([
      0x14, // HandshakeType.finished
      0x00,
      0x00,
      verifyData.length,
      ...verifyData,
    ]);

    transcriptThroughServerFinishedBytes = Uint8List.fromList([
      ...clientHelloMsg!,
      ...serverHelloMsg!,
      ...encryptedExtensions,
      ...certificate,
      ...certificateVerify,
      ...serverFinishedBytes!,
    ]);

    serverHandshakeFinished = true;

    print("✅ Server built Finished verify_data=${HEX.encode(verifyData)}");

    // --------------------------------------------------
    // 2. Send ServerHello in INITIAL packet
    //    Initial CRYPTO stream offset = 0
    //
    // QUIC CID rules:
    //   DCID = client's SCID from the Initial packet (peerScid)
    //   SCID = server's chosen CID (localCid)
    // --------------------------------------------------
    {
      final crypto = buildCryptoFrameAt(0, serverHelloMsg!);
      final pn = _allocateSendPn(EncryptionLevel.initial);

      final raw = encryptQuicPacket(
        "initial",
        crypto,
        initialWrite!.key,
        initialWrite!.iv,
        initialWrite!.hp,
        pn,
        peerScid, // ✅ DCID = client's SCID (may be empty)
        localCid, // ✅ SCID = server CID
        Uint8List(0),
      );

      if (raw == null) {
        throw StateError("Failed to encrypt Initial ServerHello");
      }

      socket.send(raw, peerAddress, peerPort);
      print(
        "✅ Server sent Initial(ServerHello) pn=$pn "
        "dcid=${HEX.encode(peerScid)} scid=${HEX.encode(localCid)}",
      );
    }

    // --------------------------------------------------
    // 3. Send remaining handshake messages
    //    Handshake CRYPTO stream starts at offset 0
    //
    // Same CID rule:
    //   DCID = peerScid
    //   SCID = localCid
    // --------------------------------------------------
    int offset = 0;

    void sendHandshake(Uint8List msg) {
      final crypto = buildCryptoFrameAt(offset, msg);
      final pn = _allocateSendPn(EncryptionLevel.handshake);

      final raw = encryptQuicPacket(
        "handshake",
        crypto,
        handshakeWrite!.key,
        handshakeWrite!.iv,
        handshakeWrite!.hp,
        pn,
        peerScid, // ✅ DCID = client's SCID
        localCid, // ✅ SCID = server CID
        Uint8List(0),
      );

      if (raw == null) {
        throw StateError("Failed to encrypt Handshake packet");
      }

      socket.send(raw, peerAddress, peerPort);
      print(
        "✅ Server sent Handshake pn=$pn offset=$offset len=${msg.length} "
        "dcid=${HEX.encode(peerScid)} scid=${HEX.encode(localCid)}",
      );

      offset += msg.length;
    }

    // EncryptedExtensions
    sendHandshake(encryptedExtensions);

    // Certificate
    sendHandshake(certificate);

    // CertificateVerify
    sendHandshake(certificateVerify);

    // Finished
    sendHandshake(serverFinishedBytes!);
  }
  // ============================================================
  // Client Finished handling
  // ============================================================

  // void _maybeHandleClientFinished() {
  //   if (clientFinishedVerified) return;

  //   final stream = receivedHandshakeByLevel[EncryptionLevel.handshake]!;
  //   final fullFinished = _extractHandshakeMessage(stream, 0x14);
  //   if (fullFinished == null) {
  //     return;
  //   }

  //   if (transcriptThroughServerFinishedBytes == null) {
  //     throw StateError("Server transcript through Finished not prepared");
  //   }

  //   final transcriptHash = createHash(transcriptThroughServerFinishedBytes!);

  //   final clientFinishedKey = hkdfExpandLabel(
  //     secret: clientHsTrafficSecret,
  //     label: "finished",
  //     context: Uint8List(0),
  //     length: 32,
  //   );

  //   final expectedVerifyData = hmacSha256(
  //     key: clientFinishedKey,
  //     data: transcriptHash,
  //   );

  //   final receivedVerifyData = fullFinished.sublist(4); // skip handshake header

  //   final ok = const ListEquality<int>().equals(
  //     expectedVerifyData,
  //     receivedVerifyData,
  //   );

  //   print("✅ Server received Client Finished");
  //   print("  expected: ${HEX.encode(expectedVerifyData)}");
  //   print("  actual  : ${HEX.encode(receivedVerifyData)}");

  //   if (!ok) {
  //     throw StateError("Client Finished verify_data mismatch");
  //   }

  //   clientFinishedVerified = true;
  //   print("✅ Client Finished verified");

  //   _deriveApplicationSecrets();
  // }
  bool handshakeComplete = false;

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

    // ✅ CRITICAL: mark handshake complete BEFORE switching protection
    handshakeComplete = true;

    print("✅ Client Finished verified");

    // ✅ Install 1-RTT keys; all future ACKs must be application-level
    _deriveApplicationSecrets();

    // ✅ Start HTTP/3 immediately after 1-RTT is ready
    sendHttp3ControlStream();
  }

  // void _deriveApplicationSecrets() {
  //     if (applicationSecretsDerived) return;

  //     final hashLen = 32;
  //     final zero = Uint8List(hashLen);
  //     final empty = Uint8List(0);

  //     if (transcriptThroughServerFinishedBytes == null) {
  //       throw StateError("Server transcript through Finished not prepared");
  //     }

  //     final transcriptHash = createHash(transcriptThroughServerFinishedBytes!);

  //     final masterSecret = hkdfExtract(
  //       zero, // ikm
  //       salt: derivedSecret, // salt
  //     );

  //     final clientAppTrafficSecret = hkdfExpandLabel(
  //       secret: masterSecret,
  //       label: "c ap traffic",
  //       context: transcriptHash,
  //       length: hashLen,
  //     );

  //     final serverAppTrafficSecret = hkdfExpandLabel(
  //       secret: masterSecret,
  //       label: "s ap traffic",
  //       context: transcriptHash,
  //       length: hashLen,
  //     );

  //     final clientKey = hkdfExpandLabel(
  //       secret: clientAppTrafficSecret,
  //       label: "quic key",
  //       context: empty,
  //       length: 16,
  //     );
  //     final clientIv = hkdfExpandLabel(
  //       secret: clientAppTrafficSecret,
  //       label: "quic iv",
  //       context: empty,
  //       length: 12,
  //     );
  //     final clientHp = hkdfExpandLabel(
  //       secret: clientAppTrafficSecret,
  //       label: "quic hp",
  //       context: empty,
  //       length: 16,
  //     );

  //     final serverKey = hkdfExpandLabel(
  //       secret: serverAppTrafficSecret,
  //       label: "quic key",
  //       context: empty,
  //       length: 16,
  //     );
  //     final serverIv = hkdfExpandLabel(
  //       secret: serverAppTrafficSecret,
  //       label: "quic iv",
  //       context: empty,
  //       length: 12,
  //     );
  //     final serverHp = hkdfExpandLabel(
  //       secret: serverAppTrafficSecret,
  //       label: "quic hp",
  //       context: empty,
  //       length: 16,
  //     );

  //     // Server reads client application, writes server application
  //     appRead = QuicKeys(key: clientKey, iv: clientIv, hp: clientHp);
  //     appWrite = QuicKeys(key: serverKey, iv: serverIv, hp: serverHp);

  //     applicationSecretsDerived = true;
  //     encryptionLevel = EncryptionLevel.application;

  //     print("✅ Server 1-RTT keys installed");
  //     print("  appRead : $appRead");
  //     print("  appWrite: $appWrite");
  //   }
  // }

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

    //     empty_hash = SHA256("")
    // derived_secret = HKDF-Expand-Label(key: handshake_secret, label: "derived", ctx: empty_hash, len: 32)
    // master_secret = HKDF-Extract(salt: derived_secret, key: 00...)
    // client_secret = HKDF-Expand-Label(key: master_secret, label: "c ap traffic", ctx: handshake_hash, len: 32)
    // server_secret = HKDF-Expand-Label(key: master_secret, label: "s ap traffic", ctx: handshake_hash, len: 32)
    // client_key = HKDF-Expand-Label(key: client_secret, label: "quic key", ctx: "", len: 16)
    // server_key = HKDF-Expand-Label(key: server_secret, label: "quic key", ctx: "", len: 16)
    // client_iv = HKDF-Expand-Label(key: client_secret, label: "quic iv", ctx: "", len: 12)
    // server_iv = HKDF-Expand-Label(key: server_secret, label: "quic iv", ctx: "", len: 12)
    // client_hp_key = HKDF-Expand-Label(key: client_secret, label: "quic hp", ctx: "", len: 16)
    // server_hp_key = HKDF-Expand-Label(key: server_secret, label: "quic hp", ctx: "", len: 16)
    final transcriptHash = createHash(transcriptThroughServerFinishedBytes!);
    final empty_hash = createHash(Uint8List(0));
    final derived_secret = hkdfExpandLabel(
      secret: handshakeSecret,
      label: "derived",
      context: empty_hash,
      length: hashLen,
    );
    final masterSecret = hkdfExtract(
      zero, // ikm
      salt: derived_secret, // salt
    );

    // final masterSecret = hkdfExtract(
    //   zero, // ikm
    //   salt: handshakeSecret, // salt
    // );

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
