// filepath: /c:/www/dart/lemon-tls/lib/tls13/tls_server_session.dart
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:async/async.dart';

import 'aead.dart';
import 'byte_reader.dart';
import 'change_cipher_suite.dart';
import 'client_hello4.dart'; // must be able to deserialize ClientHello
import 'crypto.dart';
import 'handshake_headers2.dart';
import 'hash.dart';
import 'hkdf.dart';
import 'record_header.dart';
import 'server_hello2.dart';
import 'wrapper.dart';

class _PeekableBuffer {
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
    if (data.isEmpty) return;
    final remain = peek();
    final out = Uint8List(remain.length + data.length);
    out.setRange(0, remain.length, remain);
    out.setRange(remain.length, out.length, data);
    _buf = out;
    _off = 0;
  }
}

/// Toy TLS 1.3 server session meant to interop with THIS repo's toy client.
///
/// Not a general TLS server: no certificates, no signature auth, no ALPN, etc.
class TLS13ServerSession {
  final Socket _socket;
  late final StreamQueue<Uint8List> _queue;

  final BytesBuilder _transcript = BytesBuilder(copy: false);

  final CipherSuite cipherSuite;
  late final Aead _aead;

  final KeyPair keyPair;

  HandshakeKeys? handshakeKeys;
  ApplicationKeys? applicationKeys;

  int hsSend = 0;
  int hsRecv = 0;
  int appSend = 0;
  int appRecv = 0;

  TLS13ServerSession(
    this._socket, {
    this.cipherSuite = CipherSuite.aes128gcm,
    KeyPair? keyPair,
  }) : keyPair = keyPair ?? KeyPair.generate() {
    _queue = StreamQueue(_socket);
    _aead = Aead(cipherSuite);
  }

  Future<void> handshake() async {
    final buf = _PeekableBuffer();
    buf.append(await _recv());

    // 1) Read ClientHello record and add to transcript (handshake bytes only).
    final clientHelloBytes = await _recvClientHelloBytes(buf);
    _transcript.add(clientHelloBytes); // already excludes record header

    final ch = ClientHello.deserialize(ByteReader(clientHelloBytes));
    final clientKeyShare = ch.parsedExtensions
        .whereType<ClientHelloKeyShare>()
        .first; // will throw if missing, but now it’s the right list

    final sharedSecret = keyPair.exchange(clientKeyShare.keyExchange);

    // 2) Send ServerHello (record) and add handshake bytes to transcript.
    final sh = ServerHello.buildForToyServer(
      // You must implement this builder to match your existing ServerHello serializer.
      // It should include supported_versions + key_share, and select cipher_suite.
      keySharePublic: keyPair.publicKeyBytes,
      cipherSuite: cipherSuite,
    );
    final shBytes = sh.serialize(); // includes record header
    _socket.add(shBytes);
    await _socket.flush();

    // add handshake message bytes (excluding record header) to transcript
    _transcript.add(shBytes.sublist(5));

    // 3) Derive handshake keys using transcript hash after CH+SH
    final helloHash = sha256(_transcript.toBytes());
    handshakeKeys = keyPair.derive(sharedSecret, helloHash);

    // 4) Send (encrypted) EncryptedExtensions + Finished.
    // In a real server, you would send Certificate/CertificateVerify too.
    final encryptedHandshake = _buildServerEncryptedFlight(helloHash);
    await _sendHandshakeCiphertext(encryptedHandshake);

    // 5) Read client's Finished under handshake keys, verify, then derive app keys.
    final clientFinishedMsg = await _recvHandshakeFinished(buf);
    _transcript.add(clientFinishedMsg); // add plaintext handshake message
    final handshakeHash = sha256(_transcript.toBytes());

    applicationKeys = keyPair.deriveApplicationKeys(
      handshakeKeys!.handshakeSecret,
      handshakeHash,
    );
  }

  /// Receive one decrypted application-data fragment (skips post-handshake handshake).
  Future<Uint8List> recv() async {
    if (applicationKeys == null) throw StateError('handshake not complete');
    final buf = _PeekableBuffer();

    while (true) {
      final w = await _recvWrapper(buf);

      final pt = _aead.decrypt(
        key: applicationKeys!.clientKey, // client->server direction
        nonce: xorIv(applicationKeys!.clientIv, appRecv),
        aad: w.recordHeader.serialize(),
        ciphertext: w.payload,
      );
      appRecv++;

      if (pt.isEmpty) continue;
      final innerType = pt.last;
      final content = pt.sublist(0, pt.length - 1);

      if (innerType == 0x17) return content; // application_data
      if (innerType == 0x16) continue; // ignore post-handshake handshake
      if (innerType == 0x15) return Uint8List(0); // alert => treat as EOF (toy)
    }
  }

  Future<void> send(Uint8List data) async {
    if (applicationKeys == null) throw StateError('handshake not complete');

    final plain = Uint8List.fromList([...data, 0x17]);
    final record = RecordHeader(rtype: 0x17, size: plain.length + 16);

    final ct = _aead.encrypt(
      key: applicationKeys!.serverKey, // server->client direction
      nonce: xorIv(applicationKeys!.serverIv, appSend),
      aad: record.serialize(),
      plaintext: plain,
    );
    appSend++;

    final w = Wrapper(recordHeader: record, payload: ct);
    _socket.add(w.serialize());
    await _socket.flush();
  }

  Future<void> close() async {
    await _socket.close();
  }

  // ---------------- internal recv helpers ----------------

  Future<Uint8List> _recv() async => Uint8List.fromList(await _queue.next);

  Future<void> _ensure(_PeekableBuffer buf, int n) async {
    while (buf.length < n) {
      final more = await _recv();
      if (more.isEmpty) throw StateError('connection closed');
      buf.append(more);
    }
  }

  Future<Wrapper> _recvWrapper(_PeekableBuffer buf) async {
    await _ensure(buf, 5);
    final rh = RecordHeader.deserialize(buf.peek(5));
    await _ensure(buf, 5 + rh.size);
    final bytes = buf.read(5 + rh.size);
    return Wrapper.deserialize(ByteReader(bytes));
  }

  /// Returns the raw Handshake message bytes of ClientHello (header+body), excluding record header.
  Future<Uint8List> _recvClientHelloBytes(_PeekableBuffer buf) async {
    await _ensure(buf, 5);
    final rh = RecordHeader.deserialize(buf.peek(5));
    await _ensure(buf, 5 + rh.size);
    final rec = buf.read(5 + rh.size);
    // rec = recordHeader(5) + handshake(...)
    return rec.sublist(5);
  }

  Uint8List _buildServerEncryptedFlight(Uint8List helloHash) {
    // Toy: only send Finished (optionally you could include EncryptedExtensions).
    final finishedKey = hkdfExpandLabel(
      secret: handshakeKeys!.serverHandshakeTrafficSecret,
      label: 'finished',
      context: Uint8List(0),
      length: 32,
    );
    final verifyData = hmacSha256(key: finishedKey, data: helloHash);

    final hh = HandshakeHeader(messageType: 0x14, size: verifyData.length);
    final finishedMsg = Uint8List.fromList([...hh.serialize(), ...verifyData]);

    // IMPORTANT: transcript includes plaintext handshake messages in order.
    _transcript.add(finishedMsg);

    return finishedMsg;
  }

  Future<void> _sendHandshakeCiphertext(
    Uint8List handshakePlaintextMsgs,
  ) async {
    // wrap plaintext handshake bytes as TLSInnerPlaintext + content_type=handshake(0x16)
    final plain = Uint8List.fromList([...handshakePlaintextMsgs, 0x16]);
    final record = RecordHeader(rtype: 0x17, size: plain.length + 16);

    final ct = _aead.encrypt(
      key: handshakeKeys!.serverKey,
      nonce: xorIv(handshakeKeys!.serverIv, hsSend),
      aad: record.serialize(),
      plaintext: plain,
    );
    hsSend++;

    final w = Wrapper(recordHeader: record, payload: ct);
    _socket.add(w.serialize());
    await _socket.flush();
  }

  /// Reads encrypted handshake records until it finds client's Finished, verifies it, and returns the plaintext Finished message bytes.
  Future<Uint8List> _recvHandshakeFinished(_PeekableBuffer buf) async {
    while (true) {
      final w = await _recvWrapper(buf);

      final pt = _aead.decrypt(
        key: handshakeKeys!.clientKey,
        nonce: xorIv(handshakeKeys!.clientIv, hsRecv),
        aad: w.recordHeader.serialize(),
        ciphertext: w.payload,
      );
      hsRecv++;

      if (pt.isEmpty) continue;
      if (pt.last != 0x16) continue; // want handshake

      final fragment = pt.sublist(0, pt.length - 1);
      final r = ByteReader(fragment);

      while (r.remaining >= 4) {
        final headerBytes = r.readBytes(4);
        final hh = HandshakeHeader.deserialize(headerBytes);
        if (r.remaining < hh.size) break;

        final payload = r.readBytes(hh.size);

        if (hh.messageType == 0x14) {
          // verify client's Finished against transcript hash so far (excluding this Finished)
          final handshakeHash = sha256(_transcript.toBytes());

          final finishedKey = hkdfExpandLabel(
            secret: handshakeKeys!.clientHandshakeTrafficSecret,
            label: 'finished',
            context: Uint8List(0),
            length: 32,
          );
          final expected = hmacSha256(key: finishedKey, data: handshakeHash);

          if (!_constantTimeEqual(payload, expected)) {
            throw StateError('client Finished verify failed');
          }

          return Uint8List.fromList([...headerBytes, ...payload]);
        }
      }
    }
  }

  bool _constantTimeEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}
