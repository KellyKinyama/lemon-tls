import 'dart:typed_data';
import 'dart:convert';
import 'package:crypto/crypto.dart';

import '../hkdf.dart';

void main() {
  handshakeKeyDerivationTest();
}

/* ===========================
 *  Server test vectors
 * =========================== */

// From server log
final sharedSecret = hex(
  "21dccf197abee0ab8d28f44e3144113aba36f6a7549780798213d4f5d0b3e60b",
);

final transcriptHash = hex(
  "0c6d9cf7b7e4063371d251b4c8c9a97c2f572d1ed9b33e2f101b348661c1c7c4",
);

// SHA-256("")
final emptyHash = hex(
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
);

// Expected outputs (server)
const expected = {
  "early_secret":
      "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a",
  "derived_secret":
      "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba",
  "handshake_secret":
      "c7c99bf29345140072536d1ce21e4878f0c62dca4632444febf085dea284b866",
  "client_hs":
      "9f14a6df50341a9210613d3f555552e5198da0754164cf0ae5f2b09325f88fb1",
  "server_hs":
      "7a83d0bdc0d0d4051369eba84791501caccbc694856735232410590c8d16721e",
  "server_key": "a1bd3e5c60a4ab42e71f4452a5f998ba",
  "server_iv": "d6d5dada86080833985c5e42",
  "server_hp": "45cca778925c780362c2eace53d6ac26",
};

/* ===========================
 *  Test harness
 * =========================== */

void handshakeKeyDerivationTest() {
  print("== TLS 1.3 Handshake Key Schedule Test ==\n");

  final hashLen = 32;
  final zero = Uint8List(hashLen);
  final empty = Uint8List(0);

  // early_secret = HKDF-Extract(zeros, empty)
  // final earlySecret = hkdfExtract(empty, salt: zero);
  // printCheck("early_secret", earlySecret);

  // derived_secret = HKDF-Expand-Label(early_secret, "derived", Hash(""))
  // final derivedSecret = hkdfExpandLabel(
  //   secret: earlySecret,
  //   label: "derived",
  //   context: emptyHash,
  //   length: 32,
  // );

  // early_secret = HKDF-Extract(zeros, empty)
  final earlySecret = hkdfExtract(
    zero, // ikm  (TLS salt)
    salt: empty, // key  (TLS IKM)
  );
  printCheck("early_secret", earlySecret);

  // derived_secret = HKDF-Expand-Label(early_secret, "derived", Hash(""))
  final derivedSecret = hkdfExpandLabel(
    secret: earlySecret,
    label: "derived",
    context: emptyHash,
    length: 32,
  );
  printCheck("derived_secret", derivedSecret);

  // ✅ FIXED: handshake_secret = HKDF-Extract(derived_secret, shared_secret)
  // final handshakeSecret = hkdfExtract(
  //   sharedSecret, // IKM
  //   salt: derivedSecret, // SALT
  // );

  printCheck("derived_secret", derivedSecret);

  // handshake_secret = HKDF-Extract(derived_secret, shared_secret)
  // final handshakeSecret = hkdfExtract(
  //   derivedSecret, // ikm  (TLS salt)
  //   salt: sharedSecret, // key  (TLS IKM)
  // );
  final handshakeSecret = hkdfExtract(
    sharedSecret, // ikm  (data)
    salt: derivedSecret, // salt (key)
  );

  printCheck("handshake_secret", handshakeSecret);
  printCheck("handshake_secret", handshakeSecret);
  // traffic secrets
  final clientHs = hkdfExpandLabel(
    secret: handshakeSecret,
    label: "c hs traffic",
    context: transcriptHash,
    length: 32,
  );
  printCheck("client_hs", clientHs);

  final serverHs = hkdfExpandLabel(
    secret: handshakeSecret,
    label: "s hs traffic",
    context: transcriptHash,
    length: 32,
  );
  printCheck("server_hs", serverHs);

  // QUIC handshake keys (server side)
  final serverKey = hkdfExpandLabel(
    secret: serverHs,
    label: "quic key",
    context: empty,
    length: 16,
  );
  printCheck("server_key", serverKey);

  final serverIv = hkdfExpandLabel(
    secret: serverHs,
    label: "quic iv",
    context: empty,
    length: 12,
  );
  printCheck("server_iv", serverIv);

  final serverHp = hkdfExpandLabel(
    secret: serverHs,
    label: "quic hp",
    context: empty,
    length: 16,
  );
  printCheck("server_hp", serverHp);

  print("\n✅ Test complete");
}

/* ===========================
 *  HKDF helpers
 * =========================== */

// Uint8List hkdfExtract(Uint8List ikm, Uint8List salt) {
//   final hmac = Hmac(sha256, salt);
//   return Uint8List.fromList(hmac.convert(ikm).bytes);
// }

// Uint8List hkdfExpandLabel({
//   required Uint8List secret,
//   required String label,
//   required Uint8List context,
//   required int length,
// }) {
//   final fullLabel = utf8.encode("tls13 $label");

//   final info = BytesBuilder()
//     ..add(_u16(length))
//     ..add(_u8(fullLabel.length))
//     ..add(fullLabel)
//     ..add(_u8(context.length))
//     ..add(context);

//   return hkdfExpand(secret, info.toBytes(), length);
// }

// Uint8List hkdfExpand(Uint8List prk, Uint8List info, int length) {
//   final hmac = Hmac(sha256, prk);
//   final out = BytesBuilder();

//   Uint8List previous = Uint8List(0);
//   int counter = 1;

//   while (out.length < length) {
//     final data = BytesBuilder()
//       ..add(previous)
//       ..add(info)
//       ..add([counter++]);

//     previous = Uint8List.fromList(hmac.convert(data.toBytes()).bytes);

//     out.add(previous);
//   }

//   return out.takeBytes().sublist(0, length);
// }

/* ===========================
 *  Utilities
 * =========================== */

Uint8List hex(String s) => Uint8List.fromList(
  List<int>.generate(
    s.length ~/ 2,
    (i) => int.parse(s.substring(i * 2, i * 2 + 2), radix: 16),
  ),
);

List<int> _u8(int n) => [n & 0xff];
List<int> _u16(int n) => [(n >> 8) & 0xff, n & 0xff];

void printCheck(String name, Uint8List actual) {
  final actualHex = hexEncode(actual);
  final expectedHex = expected[name];

  print("$name:");
  print("  actual  = $actualHex");

  if (expectedHex != null) {
    print("  expect  = $expectedHex");
    print(actualHex == expectedHex ? "  ✅ MATCH\n" : "  ❌ MISMATCH\n");
  } else {
    print("");
  }
}

String hexEncode(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, "0")).join();
