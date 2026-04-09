// ============================================================================
// TLS 1.3 TOY SERVER (compatible with your TLS13Session client)
// Idiomatic Dart — minimal subset of RFC 8446
// ============================================================================

import 'dart:io';
import 'dart:typed_data';
import 'dart:convert';

import 'tls_constants.dart';
import 'tls_hello.dart';
import 'tls_extensions.dart';
import 'tls_certificate.dart';
import 'tls_certificate_verify.dart';
import 'tls_keyshare.dart';
import 'tls_record_layer.dart';
import 'tls13_keyshcedule.dart';

import '../hkdf.dart';
import '../hash.dart';
import '../crypto.dart';

// ============================================================================
// Utility: NOT cryptographically secure random
// ============================================================================
Uint8List _rand(int n) {
  final out = Uint8List(n);
  final t = DateTime.now().microsecondsSinceEpoch;
  for (int i = 0; i < n; i++) {
    out[i] = (t >> (i % 8)) & 0xFF;
  }
  return out;
}

Uint8List _hs(int type, Uint8List body) {
  final L = body.length;
  return Uint8List.fromList([
    type,
    (L >> 16) & 0xFF,
    (L >> 8) & 0xFF,
    L & 0xFF,
    ...body
  ]);
}

// ============================================================================
// PARSED CLIENTHELLO STRUCT (minimal)
// ============================================================================
class ParsedCH {
  final Uint8List random;
  final Uint8List keyShare;
  final int group;

  ParsedCH(this.random, this.keyShare, this.group);
}

// ============================================================================
// TLS 1.3 SERVER SESSION
// ============================================================================

class Tls13ServerSession {
  final Uint8List serverCert;     // DER
  final Uint8List serverPrivKey;  // Raw EC private key

  // Transcript nodes
  late Uint8List h1;
  late Uint8List h2;
  late Uint8List h3;
  late Uint8List h4;

  late Uint8List clientHelloHS;
  late Uint8List serverHelloHS;

  late Tls13KeySchedule ks;
  late TlsRecordLayer record;

  late Uint8List sharedSecret;

  bool handshakeDone = false;

  Tls13ServerSession({
    required this.serverCert,
    required this.serverPrivKey,
  });

  // ==========================================================================
  // STEP 1 — PARSE CLIENTHELLO
  // ==========================================================================

  ParsedCH parseClientHello(ByteReader r) {
    // record header already removed by socket handler
    final hh = HandshakeHeader.deserialize(r.readBytes(4));
    if (hh.messageType != HandshakeType.clientHello) {
      throw Exception("Expected ClientHello");
    }

    final body = r.readBytes(hh.size);
    clientHelloHS = _hs(HandshakeType.clientHello, body);

    final ch = parseHello(TLSMessageType.CLIENT_HELLO, body);
    final exts = ch["extensions"] as List;

    // Random
    final random = body.sublist(2, 34);

    // KeyShare
    final ksExt = exts.firstWhere((e) => e["type"] == TLSExt.KEY_SHARE);
    final entries = ksExt["value"] as List;
    final entry = entries.first;
    final group = entry["group"];
    final clientPub = entry["key_exchange"] as Uint8List;

    print("🔍 Parsed ClientHello: group=$group, pub=${clientPub.length} bytes");

    return ParsedCH(random, clientPub, group);
  }

  // ==========================================================================
  // STEP 2 — BUILD SERVERHELLO
  // ==========================================================================

  Uint8List buildServerHello(ParsedCH ch) {
    // Generate server key share
    final sk = Tls13KeyShare.generate(
      group: ch.group,
      clientPublicKey: ch.keyShare,
    );

    sharedSecret = sk.sharedSecret;

    final helloBody = buildHello(
      "server",
      {
        "random": _rand(32),
        "cipher_suite": CipherSuite.tlsAes128GcmSha256,
        "session_id": Uint8List(0),
        "extensions": [
          {"type": TLSExt.SUPPORTED_VERSIONS, "value": TLSVersion.TLS1_3},
          {
            "type": TLSExt.KEY_SHARE,
            "value": {"group": ch.group, "key_exchange": sk.publicKey}
          }
        ]
      },
    );

    serverHelloHS = _hs(HandshakeType.serverHello, helloBody);

    // Transcript hash h1 = CH + SH
    h1 = createHash(Uint8List.fromList([
      ...clientHelloHS,
      ...serverHelloHS,
    ]));

    print("📘 Built ServerHello (CipherSuite=0x1301)");

    // KeySchedule
    ks = Tls13KeySchedule();
    ks.computeHandshakeSecrets(sharedSecret: sharedSecret, helloHash: h1);

    record = TlsRecordLayer();
    record.setHandshakeKeys(
      clientKey: ks.clientHandshakeKey,
      clientIV: ks.clientHandshakeIV,
      serverKey: ks.serverHandshakeKey,
      serverIV: ks.serverHandshakeIV,
    );

    return serverHelloHS;
  }

  // ==========================================================================
  // STEP 3 — ENCRYPTED EXTENSIONS
  // ==========================================================================
  Uint8List buildEncryptedExtensions() {
    final body = buildExtensions([]);
    final hs = _hs(HandshakeType.encryptedExtensions, body);

    h2 = createHash(Uint8List.fromList([...h1, ...hs]));

    print("📘 Built EncryptedExtensions");

    return record.encrypt(hs);
  }

  // ==========================================================================
  // STEP 4 — CERTIFICATE
  // ==========================================================================
  Uint8List buildCertificate() {
    final body = buildCertificateMessage({
      "request_context": Uint8List(0),
      "entries": [
        {"cert": serverCert, "extensions": []},
      ]
    });

    final hs = _hs(HandshakeType.certificate, body);
    h3 = createHash(Uint8List.fromList([...h2, ...hs]));

    print("📘 Built Certificate");

    return record.encrypt(hs);
  }

  // ==========================================================================
  // STEP 5 — CERTIFICATEVERIFY
  // ==========================================================================
  Uint8List buildCertificateVerify() {
    final body = buildCertificateVerifyMessage(
      privateKey: serverPrivKey,
      transcriptHash: h3,
    );

    final hs = _hs(HandshakeType.certificateVerify, body);
    h4 = createHash(Uint8List.fromList([...h3, ...hs]));

    print("📘 Built CertificateVerify");

    return record.encrypt(hs);
  }

  // ==========================================================================
  // STEP 6 — FINISHED
  // ==========================================================================
  Uint8List buildFinished() {
    final finishedKey = hkdfExpandLabel(
      ks.serverHandshakeTrafficSecret,
      Uint8List(0),
      "finished",
      32,
    );

    final verifyData = hmacSha256(finishedKey, h4);
    final hs = _hs(HandshakeType.finished, verifyData);

    final appHash =
        createHash(Uint8List.fromList([...h4, ...hs])); // TH4 for app keys
    ks.computeApplicationSecrets(appHash);

    handshakeDone = true;

    print("📘 Built Finished");

    return record.encrypt(hs);
  }
}

// ============================================================================
// SERVER LOOP (TCP)
// ============================================================================

class Tls13Server {
  final int port;
  final Uint8List cert;
  final Uint8List privKey;

  Tls13Server(this.port, this.cert, this.privKey);

  Future<void> start() async {
    final server = await ServerSocket.bind(InternetAddress.anyIPv4, port);
    print("🚀 TLS 1.3 Toy Server running on port $port");

    await for (final sock in server) {
      _handle(sock);
    }
  }

  Future<void> _handle(Socket sock) async {
    print("🔗 Client connected: ${sock.remoteAddress.address}");

    final session = Tls13ServerSession(
      certificate: cert,
      privateKey: privKey,
    );

    // STEP 1: Receive ClientHello record
    final firstRecord = await sock.first;
    print("📥 Got ClientHello record (${firstRecord.length} bytes)");

    final reader = ByteReader(firstRecord);
    final recHeader = RecordHeader.deserialize(reader.readBytes(5));
    final recBody = reader.readBytes(recHeader.size);

    final ch = session.parseClientHello(ByteReader(recBody));

    // STEP 2: Send ServerHello
    final sh = session.buildServerHello(ch);
    sock.add(sh);

    // STEP 3: EncryptedExtensions
    sock.add(session.buildEncryptedExtensions());

    // STEP 4: Certificate
    sock.add(session.buildCertificate());

    // STEP 5: CertificateVerify
    sock.add(session.buildCertificateVerify());

    // STEP 6: Finished
    sock.add(session.buildFinished());
    await sock.flush();
    print("✅ Handshake complete.");

    // ======================================================================
    // APPLICATION DATA PHASE
    // ======================================================================

    while (true) {
      try {
        final rec = await sock.first;
        final msg = session.record.decryptApp(
          rec,
          session.ks.serverAppKey,
          session.ks.serverAppIV,
        );

        print("📩 Received app data: ${utf8.decode(msg)}");

        final reply = utf8.encode("OK") as Uint8List;
        final out = session.record.encryptApp(
          reply,
          session.ks.clientAppKey,
          session.ks.clientAppIV,
        );
        sock.add(out);
        await sock.flush();
      } catch (e) {
        print("❌ App data error: $e");
        break;
      }
    }

    await sock.close();
  }
}