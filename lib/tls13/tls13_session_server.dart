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
import 'handshake_headers.dart';
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

  // ---------------- logging helpers ----------------

  static String _hex(Uint8List b, {int max = 256}) {
    final take = b.length <= max ? b.length : max;
    final sb = StringBuffer();
    for (var i = 0; i < take; i++) {
      if (i > 0) sb.write(i % 16 == 0 ? '\n' : ' ');
      sb.write(b[i].toRadixString(16).padLeft(2, '0'));
    }
    if (take != b.length) sb.write('\n... (${b.length} bytes total)');
    return sb.toString();
  }

  static void _logBytes(String label, Uint8List bytes, {int max = 256}) {
    stdout.writeln('--- $label (${bytes.length} bytes) ---');
    stdout.writeln(_hex(bytes, max: max));
    stdout.writeln('--- end $label ---');
  }

  // ---------------- handshake message builders ----------------

  Uint8List _hs(int msgType, Uint8List body) {
    final hh = HandshakeHeader(messageType: msgType, size: body.length);
    return Uint8List.fromList([...hh.serialize(), ...body]);
  }

  Uint8List _buildEncryptedExtensionsBody() {
    // RFC 8446 §4.3.1: EncryptedExtensions = extensions<0..2^16-1>
    // minimal empty extension list:
    return Uint8List.fromList([0x00, 0x00]);
  }

  Uint8List _buildServerEncryptedFlight(Uint8List helloHash) {
    final out = BytesBuilder(copy: false);

    // EncryptedExtensions
    final ee = _hs(0x08, _buildEncryptedExtensionsBody());
    _transcript.add(ee);
    out.add(ee);

    // Finished verify_data must use current transcript hash (CH + SH + EE),
    // not helloHash (CH + SH).
    final transcriptHashForFinished = sha256(_transcript.toBytes());

    final finishedKey = hkdfExpandLabel(
      secret: handshakeKeys!.serverHandshakeTrafficSecret,
      label: 'finished',
      context: Uint8List(0),
      length: 32,
    );

    final verifyData = hmacSha256(
      key: finishedKey,
      data: transcriptHashForFinished,
    );

    final fin = _hs(0x14, verifyData);
    _transcript.add(fin);
    out.add(fin);

    return out.toBytes();
  }

  // ---------------- public API ----------------

  Future<void> handshake() async {
    final buf = _PeekableBuffer();
    buf.append(await _recv());

    // 1) Read ClientHello (handshake bytes only) and add to transcript
    final clientHelloBytes = await _recvClientHelloBytes(buf);
    _logBytes(
      'CLIENT -> SERVER ClientHello handshake (no record header)',
      clientHelloBytes,
    );
    _transcript.add(clientHelloBytes);

    final ch = ClientHello.deserialize(ByteReader(clientHelloBytes));

    final clientKeyShare = ch.parsedExtensions
        .whereType<ClientHelloKeyShare>()
        .first;
    final sharedSecret = keyPair.exchange(clientKeyShare.keyExchange);

    // 2) Send ServerHello (record) and add handshake bytes to transcript
    final sh = ServerHello.buildForToyServer(
      keySharePublic: keyPair.publicKeyBytes,
      cipherSuite: cipherSuite,
    );
    final shBytes = sh.serialize(); // includes record header (5)
    _logBytes('SERVER -> CLIENT ServerHello record', shBytes, max: 128);

    _socket.add(shBytes);
    await _socket.flush();

    final shHandshake = shBytes.sublist(5);
    _logBytes(
      'SERVER -> CLIENT ServerHello handshake (no record header)',
      shHandshake,
      max: 128,
    );
    _transcript.add(shHandshake);

    // 3) Derive handshake keys using transcript hash after CH+SH
    final helloHash = sha256(_transcript.toBytes());
    handshakeKeys = keyPair.derive(sharedSecret, helloHash);

    // DEBUG: dump handshake material (compare with client logs)
    _logBytes('DEBUG server helloHash', helloHash, max: 64);
    _logBytes(
      'DEBUG server s_hs_traffic_secret',
      handshakeKeys!.serverHandshakeTrafficSecret,
      max: 64,
    );
    _logBytes(
      'DEBUG server c_hs_traffic_secret',
      handshakeKeys!.clientHandshakeTrafficSecret,
      max: 64,
    );
    _logBytes('DEBUG server server hs key', handshakeKeys!.serverKey, max: 64);
    _logBytes('DEBUG server server hs iv', handshakeKeys!.serverIv, max: 64);
    _logBytes('DEBUG server client hs key', handshakeKeys!.clientKey, max: 64);
    _logBytes('DEBUG server client hs iv', handshakeKeys!.clientIv, max: 64);

    // 4) Send encrypted handshake messages as separate records: EE then Finished.
    // 4) Send EE
    final ee = _hs(0x08, _buildEncryptedExtensionsBody());
    _transcript.add(ee);
    _logBytes('SERVER handshake plaintext: EncryptedExtensions', ee);
    await _sendHandshakeCiphertext(ee);

    // Force the client to process the first record before the second arrives.
    // (Workaround for any client-side buffering/ordering bug.)
    await Future<void>.delayed(const Duration(milliseconds: 5));

    // 5) Send Finished
    final transcriptHashForFinished = sha256(_transcript.toBytes());
    final finishedKey = hkdfExpandLabel(
      secret: handshakeKeys!.serverHandshakeTrafficSecret,
      label: 'finished',
      context: Uint8List(0),
      length: 32,
    );
    final verifyData = hmacSha256(
      key: finishedKey,
      data: transcriptHashForFinished,
    );

    final fin = _hs(0x14, verifyData);
    _transcript.add(fin);
    _logBytes('SERVER handshake plaintext: Finished', fin);
    await _sendHandshakeCiphertext(fin);

    // 5) Read client's Finished, verify, then derive application keys.
    final clientFinishedMsg = await _recvHandshakeFinished(buf);
    _logBytes(
      'CLIENT -> SERVER Finished (plaintext, decrypted)',
      clientFinishedMsg,
    );
    _transcript.add(clientFinishedMsg);

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

    final aad = record.serialize();
    final ct = _aead.encrypt(
      key: applicationKeys!.serverKey, // server->client direction
      nonce: xorIv(applicationKeys!.serverIv, appSend),
      aad: aad,
      plaintext: plain,
    );
    appSend++;

    final w = Wrapper(recordHeader: record, payload: ct);
    final out = w.serialize();
    _logBytes('SERVER -> CLIENT application record (full)', out, max: 96);

    _socket.add(out);
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

    if (rh.rtype != 0x16) {
      throw StateError(
        'expected handshake record for ClientHello, got ${rh.rtype}',
      );
    }

    await _ensure(buf, 5 + rh.size);
    final rec = buf.read(5 + rh.size);

    final handshakeFragment = rec.sublist(5);
    final r = ByteReader(handshakeFragment);

    // Must start with HandshakeHeader
    final headerBytes = r.readBytes(4);
    final hh = HandshakeHeader.deserialize(headerBytes);

    if (hh.messageType != 0x01) {
      throw StateError('expected ClientHello (1), got ${hh.messageType}');
    }
    if (r.remaining < hh.size) {
      throw StateError(
        'partial ClientHello in first record (toy server cannot reassemble)',
      );
    }

    final body = r.readBytes(hh.size);
    return Uint8List.fromList([...headerBytes, ...body]);
  }

  Future<void> _sendHandshakeCiphertext(
    Uint8List handshakePlaintextMsgs,
  ) async {
    // TLSInnerPlaintext = content || type (no padding for toy)
    final plain = Uint8List.fromList([...handshakePlaintextMsgs, 0x16]);

    final nonce = xorIv(handshakeKeys!.serverIv, hsSend);

    // AES-GCM => ciphertext = plaintext + 16-byte tag
    final ct = _aead.encrypt(
      key: handshakeKeys!.serverKey,
      nonce: nonce,
      aad: Uint8List(0), // placeholder, replaced below
      plaintext: plain,
    );

    // Build TLSCiphertext record header ourselves:
    // struct { ContentType(23)=0x17, ProtocolVersion(0x0303), length } TLSCiphertext;
    final len = ct.length;
    final header = Uint8List.fromList([
      0x17,
      0x03,
      0x03,
      (len >> 8) & 0xff,
      len & 0xff,
    ]);

    // Now re-encrypt with correct AAD (the header)
    final ct2 = _aead.encrypt(
      key: handshakeKeys!.serverKey,
      nonce: nonce,
      aad: header,
      plaintext: plain,
    );

    // Sanity checks
    if (ct2.length != plain.length + 16) {
      throw StateError(
        'bad aead: ctLen=${ct2.length} plainLen=${plain.length}',
      );
    }
    final out = Uint8List(header.length + ct2.length);
    out.setRange(0, 5, header);
    out.setRange(5, out.length, ct2);

    _logBytes('SERVER handshake TLSInnerPlaintext', plain);
    _logBytes('SERVER handshake record header (AAD)', header);
    _logBytes('SERVER handshake ciphertext (payload only)', ct2);
    _logBytes(
      'SERVER -> CLIENT encrypted handshake record (full)',
      out,
      max: 128,
    );

    hsSend++;

    _socket.add(out);
    await _socket.flush();
  }

  /// Reads encrypted handshake records until it finds client's Finished, verifies it,
  /// and returns the plaintext Finished message bytes.
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
