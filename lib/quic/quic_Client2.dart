import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:hex/hex.dart';

import 'crypto.dart';
import 'handshake/client_hello.dart';
import 'handshake/keyshare.dart';
import 'aead.dart';
import 'packet/protocol.dart';
import 'quic_crypto.dart';
import 'initialial_aead.dart';

// ================================================================
// UTIL
// ================================================================
Uint8List _concat(List<Uint8List> xs) {
  int total = xs.fold(0, (a, b) => a + b.length);
  final out = Uint8List(total);
  int o = 0;
  for (final x in xs) {
    out.setRange(o, o + x.length, x);
    o += x.length;
  }
  return out;
}

Uint8List buildCryptoFrame(Uint8List data) =>
    Uint8List.fromList([0x06, 0x00, data.length, ...data]);

Uint8List buildInitialPacket({
  required Uint8List dcid,
  required Uint8List scid,
  required int pn,
  required Uint8List payload,
}) {
  return Uint8List.fromList([
    0xC3, // Initial, PN len = 1, QUIC v1
    0x00, 0x00, 0x00, 0x01,
    dcid.length, ...dcid,
    scid.length, ...scid,
    0x00, // token length
    payload.length + 1,
    pn,
    ...payload,
  ]);
}

// ================================================================
// MAIN CLIENT
// ================================================================
void main() async {
  // Connect to local server
  final server = InternetAddress.loopbackIPv4;
  const port = 4433;

  final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
  print("✅ QUIC client running on UDP ${socket.port}");

  // --------------------------------------------------------------
  // 1) Build ClientHello (using your libs)
  // --------------------------------------------------------------
  // Generate X25519 keypair (QUIC client keyshare)
  final kp = QuicKeyPair.generate();

  final ch = ClientHello.forQuic(
    x25519: kp.publicKey,
    groups: [0x001D, 0x0017], // X25519, P-256
  );

  final chBytes = ch.serialize();
  print("✅ ClientHello size = ${chBytes.length}");

  // --------------------------------------------------------------
  // 2) Wrap ClientHello in CRYPTO frame
  // --------------------------------------------------------------
  final crypto = buildCryptoFrame(chBytes);

  // --------------------------------------------------------------
  // 3) Initial keys from server DCID
  // --------------------------------------------------------------
  final dcid = Uint8List.fromList(
    List.generate(8, (_) => Random.secure().nextInt(256)),
  );
  print("✅ Client DCID = ${HEX.encode(dcid)}");

  final (clientSecret, serverSecret) = computeSecrets(dcid, Version.v1);

  final (writeKey, writeIv, writeHp) = computeInitialKeyAndIV(
    clientSecret,
    Version.v1,
  );

  // AEAD
  final aead = InitialAEAD(key: writeKey, iv: writeIv, hp: writeHp);

  final encrypted = quicAeadEncrypt(
    key: writeKey,
    iv: writeIv,
    packetNumber: 0,
    plaintext: crypto,
    aad: Uint8List(0),
  );

  if (encrypted == null) {
    print("❌ Failed to encrypt ClientHello");
    return;
  }

  // --------------------------------------------------------------
  // 4) Build Initial packet
  // --------------------------------------------------------------
  final initialPacket = buildInitialPacket(
    dcid: dcid,
    scid: Uint8List(0),
    pn: 0,
    payload: encrypted,
  );

  print("✅ Sending Client Initial (PN=0, ${initialPacket.length} bytes)");
  socket.send(initialPacket, server, port);

  // --------------------------------------------------------------
  // 5) Listen for server packets
  // --------------------------------------------------------------
  socket.listen((ev) {
    if (ev == RawSocketEvent.read) {
      final dg = socket.receive();
      if (dg == null) return;

      final data = dg.data;
      print("\n⬅️  Received ${data.length} bytes from server");

      // For now just print them:
      print(HEX.encode(data));
    }
  });
}
