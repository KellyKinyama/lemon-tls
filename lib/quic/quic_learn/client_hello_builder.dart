import 'dart:typed_data';

import 'package:hex/hex.dart';

import 'dart:math' as math;
import 'dart:typed_data';

import '../buffer.dart';
import '../handshake/client_hello.dart';
import '../handshake/tls_msg.dart';

// import '../../buffer.dart';
// import '../../handshake/client_hello.dart';

final originalWire = Uint8List.fromList(
  HEX.decode(
    "01 00 00 ea 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 00 06 13 01 13 02 13 03 01 00 00 bb 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 08 00 06 00 1d 00 17 00 18 00 10 00 0b 00 09 08 70 69 6e 67 2f 31 2e 30 00 0d 00 14 00 12 04 03 08 04 04 01 05 03 08 05 05 01 08 06 06 01 02 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54 00 2d 00 02 01 01 00 2b 00 03 02 03 04 00 39 00 31 03 04 80 00 ff f7 04 04 80 a0 00 00 05 04 80 10 00 00 06 04 80 10 00 00 07 04 80 10 00 00 08 01 0a 09 01 0a 0a 01 03 0b 01 19 0f 05 63 5f 63 69 64"
        .replaceAll(" ", ""),
  ),
);

ClientHello buildInitialClientHello({
  required String hostname,
  required Uint8List x25519PublicKey,
  required Uint8List localCid,
  List<String> alpns = const ['h3'],
}) {
  final rnd = math.Random.secure();
  final random = Uint8List.fromList(List.generate(32, (_) => rnd.nextInt(256)));

  final extensions = <TlsExtension>[];

  TlsExtension makeExt(int type, QuicBuffer buf) {
    final bytes = buf.toBytes();
    return TlsExtension(type: type, length: bytes.length, data: bytes);
  }

  // SNI
  final hostBytes = Uint8List.fromList(hostname.codeUnits);
  final sniBuf = QuicBuffer()
    ..pushUint16(hostBytes.length + 3)
    ..pushUint8(0x00)
    ..pushUint16(hostBytes.length)
    ..pushBytes(hostBytes);
  extensions.add(makeExt(0x0000, sniBuf));

  // Supported groups
  final groupsBuf = QuicBuffer()
    ..pushUint16(6)
    ..pushUint16(0x001d) // x25519
    ..pushUint16(0x0017) // secp256r1
    ..pushUint16(0x0018); // secp384r1 if you want to match old CH
  extensions.add(makeExt(0x000a, groupsBuf));

  // ALPN = h3
  final alpnProto = Uint8List.fromList(alpns.first.codeUnits);
  final alpnBuf = QuicBuffer()
    ..pushUint16(alpnProto.length + 1)
    ..pushUint8(alpnProto.length)
    ..pushBytes(alpnProto);
  extensions.add(makeExt(0x0010, alpnBuf));

  // Signature algorithms (match your old list later if needed)
  final sigBuf = QuicBuffer()
    ..pushUint16(4)
    ..pushUint16(0x0403)
    ..pushUint16(0x0804);
  extensions.add(makeExt(0x000d, sigBuf));

  // Key share
  final keyShareEntry = QuicBuffer()
    ..pushUint16(0x001d)
    ..pushUint16(x25519PublicKey.length)
    ..pushBytes(x25519PublicKey);

  final keyShareBuf = QuicBuffer()
    ..pushUint16(keyShareEntry.writeIndex)
    ..pushBytes(keyShareEntry.toBytes());
  extensions.add(makeExt(0x0033, keyShareBuf));

  // PSK key exchange modes
  final pskBuf = QuicBuffer()
    ..pushUint8(1)
    ..pushUint8(1);
  extensions.add(makeExt(0x002d, pskBuf));

  // Supported versions = TLS 1.3
  final versionsBuf = QuicBuffer()
    ..pushUint8(2)
    ..pushUint8(0x03)
    ..pushUint8(0x04);
  extensions.add(makeExt(0x002b, versionsBuf));

  // QUIC transport params
  final tpBuf = QuicBuffer();

  tpBuf.pushVarint(0x01); // max_idle_timeout
  tpBuf.pushVarint(2);
  tpBuf.pushUint16(30000);

  tpBuf.pushVarint(0x04); // initial_max_data
  tpBuf.pushVarint(4);
  tpBuf.pushUint32(0x100000);

  // initial_source_connection_id
  tpBuf.pushVarint(0x0f);
  tpBuf.pushVarint(localCid.length);
  tpBuf.pushBytes(localCid);

  extensions.add(makeExt(0x0039, tpBuf));

  return ClientHello(
    type: 'client_hello',
    legacyVersion: 0x0303,
    random: random,
    sessionId: Uint8List(0),
    cipherSuites: const [0x1301, 0x1302, 0x1303],
    compressionMethods: Uint8List.fromList([0x00]),
    extensions: extensions,
    rawData: Uint8List(0),
  );
}
