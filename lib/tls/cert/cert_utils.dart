// import 'dart:convert';
// import 'dart:typed_data';

// import 'package:crypto/crypto.dart';
// import 'package:basic_utils/basic_utils.dart';

// import 'fingerprint.dart';

// Uint8List decodePemToDer(String pem) {
//   final cleaned = pem
//       .replaceAll(RegExp(r'-----BEGIN .*?-----'), '')
//       .replaceAll(RegExp(r'-----END .*?-----'), '')
//       .replaceAll('\n', '')
//       .replaceAll('\r', '');

//   return Uint8List.fromList(base64.decode(cleaned));
// }

// class EcdsaCert {
//   final Uint8List privateKey;   // raw 32-byte scalar
//   final Uint8List publicKey;    // uncompressed EC point (0x04 + X + Y)
//   final Uint8List cert;         // DER
//   final Uint8List fingerprint;

//   EcdsaCert({
//     required this.privateKey,
//     required this.publicKey,
//     required this.cert,
//     required this.fingerprint,
//   });
// }

// EcdsaCert generateSelfSignedCertificate() {
//   final pair = CryptoUtils.generateEcKeyPair();
//   final priv = pair.privateKey as ECPrivateKey;
//   final pub = pair.publicKey as ECPublicKey;

//   final csrPem =
//       X509Utils.generateEccCsrPem({'CN': 'Self-Signed'}, priv, pub);

//   final certPem =
//       X509Utils.generateSelfSignedCertificate(priv, csrPem, 365);

//   final certDer = decodePemToDer(certPem);

//   final rawPriv = _encodePrivateKey(priv);
//   final rawPub = _encodePublicKey(pub);

//   final fp = Uint8List.fromList(base64.decode(fingerprint(certDer)));

//   return EcdsaCert(
//     privateKey: rawPriv,
//     publicKey: rawPub,
//     cert: certDer,
//     fingerprint: fp,
//   );
// }

// Uint8List _encodePublicKey(ECPublicKey pubKey) {
//   final x = _bigIntToFixed(pubKey.Q!.x!.toBigInteger()!);
//   final y = _bigIntToFixed(pubKey.Q!.y!.toBigInteger()!);
//   return Uint8List.fromList([0x04, ...x, ...y]);
// }

// Uint8List _encodePrivateKey(ECPrivateKey key) {
//   final d = _bigIntToFixed(key.d!);
//   return Uint8List.fromList(d);
// }

// Uint8List _bigIntToFixed(BigInt i) {
//   final bytes = i.toUnsigned(256).toRadixString(16).padLeft(64, '0');
//   return Uint8List.fromList(
//       List<int>.generate(32, (i) => int.parse(bytes.substring(i * 2, i * 2 + 2), radix: 16)));
// }