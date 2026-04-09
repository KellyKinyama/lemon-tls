import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:async/async.dart';

import 'client_hello.dart';
import 'server_hello.dart';
import 'record_header.dart';
import 'wrapper.dart';
import 'change_cipher_suite.dart';
import 'handshake_headers.dart';
import 'crypto.dart';
import 'hkdf.dart';
import 'hash.dart';
import 'aead.dart';

class HandshakeFinishedHandshakePayload {
  /// HandshakeType.finished
  int get defaultHType => 0x14;

  final Uint8List verifyData;

  HandshakeFinishedHandshakePayload(Uint8List payload) : verifyData = payload;

  /// Computes the Finished verify_data = HMAC(finished_key, transcript_hash).
  ///
  /// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
  static HandshakeFinishedHandshakePayload generate({
    required Uint8List clientHandshakeTrafficSecret,
    required Uint8List helloHash,
  }) {
    final hashLen = 32; // SHA-256
    final finishedKey = hkdfExpandLabel(
      secret: clientHandshakeTrafficSecret,
      label: 'finished',
      context: Uint8List(0),
      length: hashLen,
    );

    final verifyData = hmacSha256(key: finishedKey, data: helloHash);
    return HandshakeFinishedHandshakePayload(verifyData);
  }
}

/// -----------------------------------------------------------
/// PYTHON‑STYLE TLS 1.3 CLIENT (NOT RFC COMPLETE)
/// -----------------------------------------------------------
class TLS13Session {
  Socket? _socket;
  StreamQueue<Uint8List>? _queue;

  final Uint8List host;
  final int port;

  final BytesBuilder transcript = BytesBuilder();

  KeyPair keyPair;

  HandshakeKeys? handshakeKeys;
  ApplicationKeys? applicationKeys;

  late final Aead _aead;

  int hsSend = 0;
  int hsRecv = 0;
  int appSend = 0;
  int appRecv = 0;

  TLS13Session({required this.host, required this.port, KeyPair? keyPair})
    : keyPair = keyPair ?? KeyPair.generate() {
    _aead = Aead(CipherSuite.aes128gcm);
  }

  /// -----------------------------------------------------------
  /// CONNECT
  /// -----------------------------------------------------------
  Future<void> connect() async {
    _socket = await Socket.connect(utf8.decode(host), port);
    _queue = StreamQueue(_socket!);

    // ---- send ClientHello ----
    await _sendClientHello();

    // ---- receive first flight ----
    final buf = PeekableBuffer();
    buf.append(await _recv());

    final sh = await _recvServerHello(buf);

    // ---- Key Share ----
    final serverKeyShare = sh.extensions.whereType<ServerHelloKeyShare>().first;
    final sharedSecret = keyPair.exchange(serverKeyShare.keyExchange);

    // ---- derive handshake keys (Python-style) ----
    handshakeKeys = keyPair.derive(sharedSecret, sha256(transcript.toBytes()));

    // ---- OPTIONAL CCS ----
    await _tryOptionalCCS(buf);

    // ---- Receive EncryptedExtensions, Certificate, CertVerify, Finished ----
    final handshakePlain = await _recvEncryptedHandshake(buf);

    // ---- Python-style transcript ----
    transcript.add(handshakePlain);

    final th = sha256(transcript.toBytes());

    // ---- derive application keys ----
    applicationKeys = keyPair.deriveApplicationKeys(
      handshakeKeys!.handshakeSecret,
      th,
    );

    // ---- send Client Finished ----
    await _sendFinished(th);

    print("✅ TLS 1.3 handshake complete (Python-style)");
  }

  /// ---------------- RECEIVE ----------------
  Future<Uint8List> recv() async {
    final buf = PeekableBuffer();
    buf.append(await _recv());

    final w = await _recvWrapper(buf);

    final plain = _aead.decrypt(
      key: applicationKeys!.serverKey,
      nonce: xorIv(applicationKeys!.serverIv, appRecv),
      aad: w.recordHeader.serialize(),
      ciphertext: w.payload,
    );

    appRecv++;

    return plain.sublist(0, plain.length - 1);
  }

  /// ---------------- INTERNAL ----------------
  // Future<Uint8List> _recv() async {
  //   return Uint8List.fromList(await _queue!.next);
  // }

  /// -----------------------------------------------------------
  /// SEND CLIENTHELLO
  /// -----------------------------------------------------------
  Future<void> _sendClientHello() async {
    final ch = ClientHello(
      domain: host,
      publicKeyBytes: keyPair.publicKeyBytes,
    );

    final bytes = ch.serialize();
    transcript.add(bytes.sublist(5)); // python-style transcript
    _socket!.add(bytes);
    await _socket!.flush();
  }

  /// -----------------------------------------------------------
  /// RECEIVE SERVERHELLO
  /// -----------------------------------------------------------
  Future<ServerHello> _recvServerHello(PeekableBuffer buf) async {
    await _ensure(buf, 5);
    final rh = RecordHeader.deserialize(buf.peek(5));

    await _ensure(buf, 5 + rh.size);
    final bytes = buf.read(5 + rh.size);

    final sh = ServerHello.deserialize(ByteReader(bytes));
    transcript.add(bytes.sublist(5)); // python-style
    return sh;
  }

  /// -----------------------------------------------------------
  /// OPTIONAL CCS (same as Python)
  /// -----------------------------------------------------------
  Future<void> _tryOptionalCCS(PeekableBuffer buf) async {
    try {
      await _ensure(buf, 5);
      final header = buf.peek(5);
      if (header[0] == 0x14) {
        final ccs = await _recvChangeCipherSuite(buf);
      }
    } catch (_) {
      // no CCS
    }
  }

  Future<void> close() async {
    await _socket?.close();
  }

  /// -----------------------------------------------------------
  /// RECEIVE ENCRYPTED HANDSHAKE (Python‑style)
  /// -----------------------------------------------------------
  Future<Uint8List> _recvEncryptedHandshake(PeekableBuffer buf) async {
    final out = BytesBuilder();

    while (true) {
      final w = await _recvWrapper(buf);

      final plain = _aead.decrypt(
        key: handshakeKeys!.serverKey,
        nonce: xorIv(handshakeKeys!.serverIv, hsRecv),
        aad: w.recordHeader.serialize(),
        ciphertext: w.payload,
      );

      hsRecv++;

      // strip TLSInnerPlaintext.content_type
      final data = plain.sublist(0, plain.length - 1);
      out.add(data);

      // detect FINISHED the same way Python does
      final p = PeekableBuffer()..append(out.toBytes());

      if (p.length >= 4) {
        final hh = HandshakeHeader.deserialize(p.peek(4));
        if (p.length >= 4 + hh.size && hh.messageType == 0x14) {
          return out.toBytes();
        }
      }
    }
  }

  /// -----------------------------------------------------------
  /// SEND CLIENT FINISHED (python-style)
  /// -----------------------------------------------------------
  Future<void> _sendFinished(Uint8List transcriptHash) async {
    final payload = HandshakeFinishedHandshakePayload.generate(
      clientHandshakeTrafficSecret: handshakeKeys!.clientHandshakeTrafficSecret,
      helloHash: transcriptHash,
    );

    final header = HandshakeHeader(
      messageType: payload.defaultHType,
      size: payload.verifyData.length,
    );

    final handshakeMsg = Uint8List.fromList([
      ...header.serialize(),
      ...payload.verifyData,
    ]);

    transcript.add(handshakeMsg);

    final plain = Uint8List.fromList([...handshakeMsg, 0x16]);

    final record = RecordHeader(rtype: 0x17, size: plain.length + 16);

    final ct = _aead.encrypt(
      key: handshakeKeys!.clientKey,
      nonce: xorIv(handshakeKeys!.clientIv, hsSend),
      aad: record.serialize(),
      plaintext: plain,
    );

    hsSend++;

    final w = Wrapper(recordHeader: record, payload: ct);
    _socket!.add(w.serialize());
    await _socket!.flush();

    print("✅ Client Finished sent");
  }

  /// -----------------------------------------------------------
  /// SEND APPLICATION DATA (Python-style)
  /// -----------------------------------------------------------
  Future<void> send(Uint8List data) async {
    final plain = Uint8List.fromList([...data, 0x17]);

    final record = RecordHeader(rtype: 0x17, size: plain.length + 16);

    final ct = _aead.encrypt(
      key: applicationKeys!.clientKey,
      nonce: xorIv(applicationKeys!.clientIv, appSend),
      aad: record.serialize(),
      plaintext: plain,
    );

    appSend++;

    final w = Wrapper(recordHeader: record, payload: ct);
    _socket!.add(w.serialize());
    await _socket!.flush();
  }

  /// -----------------------------------------------------------
  /// INTERNAL HELPERS
  /// -----------------------------------------------------------
  Future<Uint8List> _recv() async {
    return Uint8List.fromList(await _queue!.next);
  }

  Future<void> _ensure(PeekableBuffer buf, int n) async {
    while (buf.length < n) {
      buf.append(await _recv());
    }
  }

  Future<Wrapper> _recvWrapper(PeekableBuffer buf) async {
    await _ensure(buf, 5);
    final rh = RecordHeader.deserialize(buf.peek(5));

    await _ensure(buf, 5 + rh.size);

    final bytes = buf.read(5 + rh.size);
    return Wrapper.deserialize(ByteReader(bytes));
  }

  Future<ChangeCipherSuite> _recvChangeCipherSuite(PeekableBuffer buf) async {
    await _ensure(buf, 5);
    final rh = RecordHeader.deserialize(buf.peek(5));

    await _ensure(buf, 5 + rh.size);

    final bytes = buf.read(5 + rh.size);
    return ChangeCipherSuite.deserialize(ByteReader(bytes));
  }
}

/// Same PeekableBuffer you already use.
class PeekableBuffer {
  Uint8List _buf = Uint8List(0);
  int _off = 0;

  int get length => _buf.length - _off;

  Uint8List peek([int? n]) {
    final take = n ?? length;
    return _buf.sublist(_off, _off + take);
  }

  Uint8List read(int n) {
    final out = _buf.sublist(_off, _off + n);
    _off += n;
    if (_off == _buf.length) {
      _buf = Uint8List(0);
      _off = 0;
    }
    return out;
  }

  void append(Uint8List data) {
    final remain = peek();
    final out = Uint8List(remain.length + data.length);
    out.setRange(0, remain.length, remain);
    out.setRange(remain.length, out.length, data);
    _buf = out;
    _off = 0;
  }
}
