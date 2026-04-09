import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:async/async.dart';

import 'client_hello.dart';
import 'hash.dart';
import 'hkdf.dart';
import 'server_hello.dart';
import 'record_header.dart';
import 'wrapper.dart';
import 'change_cipher_suite.dart';
import 'handshake_headers.dart';

import 'crypto.dart';
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

/// ---------------- BUFFER ----------------
class PeekableBuffer {
  Uint8List _buf = Uint8List(0);
  int _off = 0;

  int get length => _buf.length - _off;

  Uint8List peek([int? n]) {
    final avail = length;
    final take = n == null ? avail : (n <= avail ? n : avail);
    return _buf.sublist(_off, _off + take);
  }

  Uint8List read(int n) {
    if (length < n) throw StateError('Need more data');
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

/// ---------------- TLS SESSION ----------------
class TLS13Session {
  Socket? _socket;
  StreamQueue<Uint8List>? _queue;

  final Uint8List host;
  final int port;

  final BytesBuilder _helloHash = BytesBuilder();

  KeyPair keyPair;

  HandshakeKeys? handshakeKeys;
  ApplicationKeys? applicationKeys;

  late final Aead _aead;
  final CipherSuite cipherSuite;

  int hsSend = 0;
  int hsRecv = 0;
  int appSend = 0;
  int appRecv = 0;

  TLS13Session({
    required this.host,
    required this.port,
    this.cipherSuite = CipherSuite.aes128gcm,
    KeyPair? keyPair,
  }) : keyPair = keyPair ?? KeyPair.generate() {
    _aead = Aead(cipherSuite);
  }

  /// ---------------- CONNECT ----------------
  Future<void> connect() async {
    _socket = await Socket.connect(utf8.decode(host), port);
    _queue = StreamQueue(_socket!);

    await _sendClientHello();

    final buf = PeekableBuffer();
    buf.append(await _recv());

    final sh = await _recvServerHello(buf);

    final serverKeyShare = sh.extensions.whereType<ServerHelloKeyShare>().first;
    final sharedSecret = keyPair.exchange(serverKeyShare.keyExchange);

    handshakeKeys = keyPair.derive(sharedSecret, sha256(_helloHash.toBytes()));

    final sccs = await _recvChangeCipherSuite(buf);

    final plaintext = await _recvEncryptedHandshake(buf);

    /// ✅ include ALL server handshake messages
    _helloHash.add(plaintext);

    final hash = sha256(_helloHash.toBytes());

    applicationKeys = keyPair.deriveApplicationKeys(
      handshakeKeys!.handshakeSecret,
      hash,
    );

    /// optional compatibility CCS
    _socket!.add(sccs.serialize());
    await _socket!.flush();

    await _sendFinished(hash);
  }

  /// ---------------- CLIENT HELLO ----------------
  Future<void> _sendClientHello() async {
    final ch = ClientHello(
      domain: host,
      publicKeyBytes: keyPair.publicKeyBytes,
    );

    final bytes = ch.serialize();

    _helloHash.add(bytes.sublist(5));

    _socket!.add(bytes);
    await _socket!.flush();
  }

  /// ---------------- SERVER HELLO ----------------
  Future<ServerHello> _recvServerHello(PeekableBuffer buf) async {
    await _ensure(buf, 5);
    final rh = RecordHeader.deserialize(buf.peek(5));

    await _ensure(buf, 5 + rh.size);

    final bytes = buf.read(5 + rh.size);

    final sh = ServerHello.deserialize(ByteReader(bytes));

    _helloHash.add(bytes.sublist(5));

    return sh;
  }

  /// ---------------- ENCRYPTED HANDSHAKE ----------------
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

      final data = plain.sublist(0, plain.length - 1);
      out.add(data);

      final p = PeekableBuffer()..append(out.toBytes());

      while (true) {
        if (p.length < 4) break;

        final headerBytes = p.peek(4);
        final hh = HandshakeHeader.deserialize(headerBytes);

        if (p.length < 4 + hh.size) break;

        p.read(4);
        final payload = p.read(hh.size);

        if (hh.messageType == 0x14) {
          /// ✅ VERIFY SERVER FINISHED
          final expected = HandshakeFinishedHandshakePayload.generate(
            clientHandshakeTrafficSecret:
                handshakeKeys!.serverHandshakeTrafficSecret,
            helloHash: sha256(_helloHash.toBytes()),
          );

          if (!_constantTimeEqual(payload, expected.verifyData)) {
            throw StateError('TLS Finished verification failed');
          }

          return out.toBytes();
        }
      }
    }
  }

  /// ---------------- FINISHED ----------------
  Future<void> _sendFinished(Uint8List hash) async {
    final payload = HandshakeFinishedHandshakePayload.generate(
      clientHandshakeTrafficSecret: handshakeKeys!.clientHandshakeTrafficSecret,
      helloHash: hash,
    );

    final header = HandshakeHeader(
      messageType: payload.defaultHType,
      size: payload.verifyData.length,
    );

    final handshakeMsg = Uint8List.fromList([
      ...header.serialize(),
      ...payload.verifyData,
    ]);

    /// ✅ MUST update transcript BEFORE encryption
    _helloHash.add(handshakeMsg);

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
  }

  /// ---------------- SEND ----------------
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

  Future<void> close() async {
    await _socket?.close();
  }

  bool _constantTimeEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    int diff = 0;
    for (int i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}
