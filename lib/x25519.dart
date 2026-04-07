import 'dart:math';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:hex/hex.dart';
import 'package:x25519/x25519.dart';

class X25519Secret {
  /// GenerateKey generates a public/private key pair using entropy from secure random.
  KeyPair getPublicKey(Uint8List local_key_share_private) {
    var private = List<int>.generate(
      ScalarSize,
      (i) => local_key_share_private[i],
    );
    var public = List<int>.filled(32, 0);

    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;

    ScalarBaseMult(public, private);

    return KeyPair(privateKey: private, publicKey: Uint8List.fromList(public));
  }
}

void genKeyAndX25519() {
  var aliceKeyPair = generateKeyPair();
  var bobKeyPair = generateKeyPair();

  var aliceSharedKey = X25519(aliceKeyPair.privateKey, bobKeyPair.publicKey);
  var bobSharedKey = X25519(bobKeyPair.privateKey, aliceKeyPair.publicKey);

  assert(ListEquality().equals(aliceSharedKey, bobSharedKey));
}

// void genKeyAndX25519() {
//   var aliceKeyPair = generateKeyPair();
//   var bobKeyPair = generateKeyPair();

//   var aliceSharedKey = X25519(aliceKeyPair.privateKey, bobKeyPair.publicKey);
//   var bobSharedKey = X25519(bobKeyPair.privateKey, aliceKeyPair.publicKey);

//   assert(ListEquality().equals(aliceSharedKey, bobSharedKey));
// }

void useX25519() {
  const expectedHex =
      '89161fde887b2b53de549af483940106ecc114d6982daa98256de23bdf77661a';
  var x = List<int>.filled(32, 0);
  x[0] = 1;

  for (var i = 0; i < 200; i++) {
    x = X25519(x, basePoint);
  }
  assert(HEX.encode(x) == expectedHex);
}

void main() {
  genKeyAndX25519();
}
