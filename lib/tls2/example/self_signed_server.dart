import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:pointycastle/export.dart';

import '../tls13_tcp_server2.dart';
import '../tls_extensions.dart';

// ======================================================================
// Helpers for raw P‑256 keys
// ======================================================================

Uint8List _bigIntTo32(BigInt i) {
  final hexStr = i.toRadixString(16).padLeft(64, '0');
  return Uint8List.fromList(
    List<int>.generate(
      32,
      (j) => int.parse(hexStr.substring(j * 2, j * 2 + 2), radix: 16),
    ),
  );
}

Uint8List _encodePublicKeyRaw(ECPublicKey pub) {
  final x = _bigIntTo32(pub.Q!.x!.toBigInteger()!);
  final y = _bigIntTo32(pub.Q!.y!.toBigInteger()!);
  return Uint8List.fromList([0x04, ...x, ...y]); // SEC1 uncompressed
}

Uint8List _encodePrivateKeyRaw(ECPrivateKey priv) {
  return _bigIntTo32(priv.d!);
}

Uint8List decodePemToDer(String pem) {
  return Uint8List.fromList(
    base64.decode(
      pem
          .replaceAll(RegExp(r'-----.*?-----'), '')
          .replaceAll('\n', '')
          .replaceAll('\r', ''),
    ),
  );
}

String fingerprintSHA256(Uint8List der) {
  final digest = crypto.sha256.convert(der).bytes;
  return digest.map((b) => b.toRadixString(16).padLeft(2, '0')).join(':');
}

// ======================================================================
// ✅ Generate Self‑Signed Certificate for TLS 1.3
// ======================================================================
Future<Map<String, Uint8List>> generateSelfSignedCert() async {
  // Generate EC keypair (prime256v1)
  final pair = CryptoUtils.generateEcKeyPair();
  final priv = pair.privateKey as ECPrivateKey;
  final pub = pair.publicKey as ECPublicKey;

  final dn = {"CN": "Dart TLS 1.3 Server"};

  // Generate CSR → Self‑Signed certificate
  final csrPem = X509Utils.generateEccCsrPem(dn, priv, pub);
  final certPem = X509Utils.generateSelfSignedCertificate(priv, csrPem, 365);

  final certDer = decodePemToDer(certPem);
  final rawPriv = _encodePrivateKeyRaw(priv);
  final rawPub = _encodePublicKeyRaw(pub);

  final fp = fingerprintSHA256(certDer);
  print("✅ Generated Self-Signed TLS 1.3 Certificate");
  print("   Fingerprint (SHA256): $fp");
  print("   Public Key (raw): ${rawPub.length} bytes");
  print("   Private Key (raw): ${rawPriv.length} bytes");
  print("   Certificate (DER): ${certDer.length} bytes\n");

  return {"cert": certDer, "priv": rawPriv, "pub": rawPub};
}

// ======================================================================
// ✅ MAIN — Generate certificate and start the TLS 1.3 server
// ======================================================================
Future<void> main() async {
  initTls13Extensions(); // REQUIRED
  print("🔧 Generating self-signed certificate...");
  final generated = await generateSelfSignedCert();

  // Save cert + key
  File("cert.der").writeAsBytesSync(generated["cert"]!);
  File("privkey.bin").writeAsBytesSync(generated["priv"]!);

  print("💾 Saved cert.der and privkey.bin\n");

  // Start TLS 1.3 Server
  final server = Tls13TcpServer(
    port: 4433,
    serverCertificate: generated["cert"]!,
    serverPrivateKey: generated["priv"]!,
  );

  print("🚀 Starting TLS 1.3 Server on port 4433 ...");
  await server.start();
}
