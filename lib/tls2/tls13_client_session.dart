// ============================================================================
// TLS 1.3 CLIENT SESSION — RFC 8446 (Interop with your custom server)
// ============================================================================

import 'dart:typed_data';

import '../hash.dart';
import '../hkdf.dart';
import 'tls13_keyshcedule.dart';
import 'tls_constants.dart';
import 'tls_hello.dart';
import 'tls_certificate.dart';
import 'tls_certificate_verify.dart';
import 'tls_keyshare.dart';
import 'tls_record_layer.dart';

// ============================================================================
// Helper
// ============================================================================

Uint8List _handshake(int type, Uint8List body) {
  final len = body.length;
  return Uint8List.fromList([
    type,
    (len >> 16) & 0xff,
    (len >> 8) & 0xff,
    len & 0xff,
    ...body,
  ]);
}

// ============================================================================

class Tls13ClientSession {
  final Uint8List certificate;
  final Uint8List privateKey;

  late Tls13KeySchedule keySchedule;
  late TlsRecordLayer recordLayer;

  final transcript = BytesBuilder(copy: false);

  late int negotiatedGroup;
  late Uint8List clientPublicKey;
  late Uint8List sharedSecret;

  Tls13ClientSession({required this.certificate, required this.privateKey});

  // ==========================================================================
  // Process ServerHello
  // ==========================================================================

  void handleServerHello(Uint8List serverHelloHandshake) {
    // Add ServerHello to transcript
    transcript.add(serverHelloHandshake);

    final body = serverHelloHandshake.sublist(4);

    // Parse legacy_version
    int off = 2;

    // Random
    off += 32;

    // session_id
    final sidLen = body[off++];
    off += sidLen;

    // cipher_suite
    off += 2;

    // compression
    off += 1;

    // extensions
    final extLen = (body[off] << 8) | body[off + 1];
    off += 2;

    final extEnd = off + extLen;

    Uint8List serverKeyShare = Uint8List(0);

    while (off < extEnd) {
      final type = (body[off] << 8) | body[off + 1];
      final len = (body[off + 2] << 8) | body[off + 3];
      off += 4;

      if (type == TLSExt.KEY_SHARE) {
        negotiatedGroup = (body[off] << 8) | body[off + 1];
        final kxLen = (body[off + 2] << 8) | body[off + 3];
        serverKeyShare = body.sublist(off + 4, off + 4 + kxLen);
      }

      off += len;
    }

    // Generate shared secret
    final kx = Tls13KeyShare.generate(
      group: negotiatedGroup,
      clientPublicKey: serverKeyShare,
    );

    sharedSecret = kx.sharedSecret;

    // Derive handshake secrets
    keySchedule = Tls13KeySchedule();
    keySchedule.computeHandshakeSecrets(
      sharedSecret: sharedSecret,
      helloHash: createHash(transcript.toBytes()),
    );

    recordLayer = TlsRecordLayer();
    // recordLayer.setHandshakeKeys(
    //   clientKey: keySchedule.clientHandshakeKey,
    //   clientIV: keySchedule.clientHandshakeIV,
    //   serverKey: keySchedule.serverHandshakeKey,
    //   serverIV: keySchedule.serverHandshakeIV,
    // );

    recordLayer.setHandshakeKeys(
      // client READS server → client records with server secrets
      clientKey: keySchedule.serverHandshakeKey,
      clientIV: keySchedule.serverHandshakeIV,

      // client WRITES client → server records with client secrets
      serverKey: keySchedule.clientHandshakeKey,
      serverIV: keySchedule.clientHandshakeIV,
    );
  }

  // ==========================================================================
  // Decrypt handshake messages
  // ==========================================================================

  Uint8List decryptHandshake(Uint8List record) {
    final plaintext = recordLayer.decrypt(record);
    transcript.add(plaintext);
    return plaintext;
  }

  // ==========================================================================
  // Send Client Finished
  // ==========================================================================

  Uint8List buildClientFinished() {
    final finishedKey = hkdfExpandLabel(
      keySchedule.clientHandshakeTrafficSecret,
      Uint8List(0),
      'finished',
      32,
    );

    final verifyData = hmacSha256(
      finishedKey,
      createHash(transcript.toBytes()),
    );

    final hs = _handshake(HandshakeType.finished, verifyData);
    transcript.add(hs);

    final rec = recordLayer.encrypt(hs);

    keySchedule.computeApplicationSecrets(createHash(transcript.toBytes()));

    return rec;
  }
}

// ============================================================================
// Constants
// ============================================================================

class HandshakeType {
  static const int clientHello = 1;
  static const int serverHello = 2;
  static const int encryptedExtensions = 8;
  static const int certificate = 11;
  static const int certificateVerify = 15;
  static const int finished = 20;
}

class CipherSuite {
  static const int tlsAes128GcmSha256 = 0x1301;
}
