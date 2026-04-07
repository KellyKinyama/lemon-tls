import 'dart:convert';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:hex/hex.dart';
import 'package:pointycastle/export.dart';

Uint8List _pad32(Uint8List bytes) {
  if (bytes.length == 32) return bytes;
  final out = Uint8List(32);
  out.setRange(32 - bytes.length, 32, bytes);
  return out;
}

Uint8List _bigIntTo32(BigInt i) {
  final b = i.toRadixString(16).padLeft(64, '0');
  return Uint8List.fromList(HEX.decode(b));
}

Uint8List _encodePublicKeyRaw(ECPublicKey pub) {
  final x = _bigIntTo32(pub.Q!.x!.toBigInteger()!);
  final y = _bigIntTo32(pub.Q!.y!.toBigInteger()!);
  return Uint8List.fromList([0x04, ...x, ...y]);
}

Uint8List _encodePrivateKeyRaw(ECPrivateKey priv) {
  // d is the private scalar; encode it as a fixed-width 32-byte big-endian value
  return _bigIntTo32(priv.d!);
}

Uint8List decodePemToDer(String pem) {
  return Uint8List.fromList(
    base64.decode(
      pem.replaceAll(RegExp(r'-----.*?-----'), '').replaceAll('\n', ''),
    ),
  );
}

String sha256Fingerprint(Uint8List der) {
  final digest = crypto.sha256.convert(der).bytes;
  return digest.map((b) => b.toRadixString(16).padLeft(2, '0')).join(':');
}

class EcdsaCert {
  Uint8List cert; // DER certificate
  Uint8List privateKey; // 32 bytes raw scalar
  Uint8List publicKey; // 65 bytes uncompressed
  String fingerprint;

  EcdsaCert({
    required this.cert,
    required this.privateKey,
    required this.publicKey,
    required this.fingerprint,
  });
}

/// ============================================================================
/// ✅ Generate P‑256 Self‑Signed Certificate (fully compatible with TLS 1.3)
/// ============================================================================
EcdsaCert generateSelfSignedCertificate() {
  // Generate EC P‑256 keypair
  final pair = CryptoUtils.generateEcKeyPair();
  final priv = pair.privateKey as ECPrivateKey;
  final pub = pair.publicKey as ECPublicKey;

  // Distinguished Name
  final dn = {"CN": "Dart TLS13 Self Signed"};

  // Self‑signed certificate
  final pem = X509Utils.generateSelfSignedCertificate(
    priv,
    X509Utils.generateEccCsrPem(dn, priv, pub),
    365,
  );

  final der = decodePemToDer(pem);

  // Raw keys
  final rawPriv = _encodePrivateKeyRaw(priv);
  final rawPub = _encodePublicKeyRaw(pub);

  final fp = sha256Fingerprint(der);

  return EcdsaCert(
    cert: der,
    privateKey: rawPriv,
    publicKey: rawPub,
    fingerprint: fp,
  );
}
