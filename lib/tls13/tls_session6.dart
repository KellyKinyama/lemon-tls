// ============================================================================
// TLS 1.3 Client Session - WITH NewSessionTicket support
// ============================================================================

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:async/async.dart';

import 'client_hello2.dart';
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
  int get defaultHType => 0x14;
  final Uint8List verifyData;

  HandshakeFinishedHandshakePayload(Uint8List payload) : verifyData = payload;

  static HandshakeFinishedHandshakePayload generate({
    required Uint8List clientHandshakeTrafficSecret,
    required Uint8List helloHash,
  }) {
    final hashLen = 32;
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

// ============================================================================
// PeekableBuffer
// ============================================================================

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

// ============================================================================
// TLS 1.3 CLIENT SESSION
// ============================================================================

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

  // ==========================================================================
  // CONNECT
  // ==========================================================================

  Future<void> connect() async {
    print("🔌 Connecting to ${utf8.decode(host)}:$port ...");

    _socket = await Socket.connect(utf8.decode(host), port);
    _queue = StreamQueue(_socket!);

    await _sendClientHello();

    final buf = PeekableBuffer();
    buf.append(await _recv());

    final sh = await _recvServerHello(buf);

    final serverKeyShare = sh.extensions.whereType<ServerHelloKeyShare>().first;
    final sharedSecret = keyPair.exchange(serverKeyShare.keyExchange);

    handshakeKeys = keyPair.derive(sharedSecret, sha256(_helloHash.toBytes()));

    ChangeCipherSuite? sccs;
    try {
      sccs = await _recvChangeCipherSuite(buf);
    } catch (_) {
      print("⚠ No CCS received.");
    }

    final plaintext = await _recvEncryptedHandshake(buf);
    _helloHash.add(plaintext);

    final hash = sha256(_helloHash.toBytes());

    applicationKeys = keyPair.deriveApplicationKeys(
      handshakeKeys!.handshakeSecret,
      hash,
    );

    if (sccs != null) {
      _socket!.add(sccs.serialize());
      await _socket!.flush();
    }

    await _sendFinished(hash);

    print("✅ TLS 1.3 handshake complete.");
  }

  // ==========================================================================
  // SEND CLIENTHELLO
  // ==========================================================================

  Future<void> _sendClientHello() async {
    final ch = ClientHello(
      domain: host,
      publicKeyBytes: keyPair.publicKeyBytes,
    );

    final bytes = ch.serialize();
    _helloHash.add(bytes.sublist(5));

    print("➡ Sending ClientHello (${bytes.length} bytes)");
    _socket!.add(bytes);
    await _socket!.flush();
  }

  // ==========================================================================
  // RECV SERVERHELLO
  // ==========================================================================

  Future<ServerHello> _recvServerHello(PeekableBuffer buf) async {
    await _ensure(buf, 5);
    final rh = RecordHeader.deserialize(buf.peek(5));

    await _ensure(buf, 5 + rh.size);
    final bytes = buf.read(5 + rh.size);

    final sh = ServerHello.deserialize(ByteReader(bytes));
    _helloHash.add(bytes.sublist(5));

    print("✅ ServerHello received.");
    return sh;
  }

  // ==========================================================================
  // RECV ENCRYPTED HANDSHAKE (Flight 2)
  // ==========================================================================

  Future<Uint8List> _recvEncryptedHandshake(PeekableBuffer buf) async {
    final out = BytesBuilder();

    while (true) {
      final w = await _recvWrapper(buf);

      final decrypted = _aead.decrypt(
        key: handshakeKeys!.serverKey,
        nonce: xorIv(handshakeKeys!.serverIv, hsRecv),
        aad: w.recordHeader.serialize(),
        ciphertext: w.payload,
      );
      hsRecv++;

      final fragment = decrypted.sublist(0, decrypted.length - 1);
      final reader = ByteReader(fragment);

      while (reader.remaining >= 4) {
        final headerBytes = reader.readBytes(4);
        final hh = HandshakeHeader.deserialize(headerBytes);

        if (reader.remaining < hh.size)
          throw StateError("Partial handshake msg");

        final payload = reader.readBytes(hh.size);
        out.add([...headerBytes, ...payload]);

        print("🔍 Handshake msg type=${hh.messageType}, size=${hh.size}");

        if (hh.messageType == 0x14) {
          print("✅ FINISHED received.");
          return out.toBytes();
        }
      }
    }
  }

  // ==========================================================================
  // SEND CLIENT FINISHED
  // ==========================================================================

  Future<void> _sendFinished(Uint8List hash) async {
    print("➡ Preparing ClientFinished...");

    final payload = HandshakeFinishedHandshakePayload.generate(
      clientHandshakeTrafficSecret: handshakeKeys!.clientHandshakeTrafficSecret,
      helloHash: hash,
    );

    final header = HandshakeHeader(
      messageType: payload.defaultHType,
      size: payload.verifyData.length,
    );

    final msg = Uint8List.fromList([
      ...header.serialize(),
      ...payload.verifyData,
    ]);
    _helloHash.add(msg);

    final plain = Uint8List.fromList([...msg, 0x16]);
    final record = RecordHeader(rtype: 0x17, size: plain.length + 16);

    final ct = _aead.encrypt(
      key: handshakeKeys!.clientKey,
      nonce: xorIv(handshakeKeys!.clientIv, hsSend),
      aad: record.serialize(),
      plaintext: plain,
    );

    hsSend++;
    final wrapped = Wrapper(recordHeader: record, payload: ct);

    print("➡ Sending ClientFinished...");
    _socket!.add(wrapped.serialize());
    await _socket!.flush();
    print("✅ ClientFinished sent.");
  }

  // ==========================================================================
  // APPLICATION DATA RECEIVE WITH NEW SESSION TICKET HANDLING
  // ==========================================================================

  Future<Uint8List> recv() async {
    while (true) {
      final buf = PeekableBuffer();
      buf.append(await _recv());

      final w = await _recvWrapper(buf);

      final plaintext = _aead.decrypt(
        key: applicationKeys!.serverKey,
        nonce: xorIv(applicationKeys!.serverIv, appRecv),
        aad: w.recordHeader.serialize(),
        ciphertext: w.payload,
      );

      appRecv++;

      final body = plaintext.sublist(0, plaintext.length - 1);

      // ✅ Detect post-handshake NewSessionTicket
      if (body.isNotEmpty && body[0] == 0x04) {
        print("🎫 Received NewSessionTicket (ignored).");
        continue; // wait for next record
      }

      return body;
    }
  }

  // ==========================================================================
  // INTERNAL HELPERS
  // ==========================================================================

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

  bool _constantTimeEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    int diff = 0;
    for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff == 0;
  }

  Future<void> close() async {
    await _socket?.close();
  }

  /// ---------------- SEND APPLICATION DATA ----------------
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
}
