import 'dart:convert';
import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:lemon_tls/quic/handshake/tls_messages.dart';

import '../buffer.dart';
import '../frames/quic_frames.dart';
// import 'quic_session.dart';

/// =============================================================
/// Parsed QUIC payload result
/// =============================================================
class ParsedQuicPayload {
  final List<QuicFrame> frames;
  List<CryptoFrame> cryptoFrames = [];
  final AckFrame? ack;

  List<TlsHandshakeMessage> tlsMessages;

  ParsedQuicPayload({
    required this.frames,
    this.ack,
    required this.cryptoFrames,
    required this.tlsMessages,
  });
}

ParsedQuicPayload parse_quic_frames(Uint8List plaintextPayload) {
  int offset = 0;
  final textDecoder = utf8;

  final buf = QuicBuffer(data: plaintextPayload);
  // final frames = <QuicFrame>[];
  final frames = <dynamic>[];
  final cryptoFrames = <CryptoFrame>[];
  final tlsMessages = <TlsHandshakeMessage>[];
  AckFrame? ackFrame;

  // function safeReadVarInt() {
  //   if (offset >= buf.length) return null;
  //   const res = readVarInt(buf, offset);
  //   if (!res || typeof res.byteLength !== 'number') return null;
  //   offset += res.byteLength;
  //   return res;
  // }

  while (buf.remaining > 0) {
    final start = offset;
    int type = buf.pullVarInt();

    if (type >= 0x80) {
      offset--; // backtrack and read full varint
      // const t = safeReadVarInt();
      // if (!t) break;
      // type = t.value;
    }

    if (type == 0x00) {
      // padding
    } else if (type == 0x01) {
      frames.add((type: 'ping'));
    } else if ((type & 0xfe) == 0x02) {
      final hasECN = (type & 0x01) == 0x01;
      final largest = buf.pullVarInt();
      final delay = buf.pullVarInt();
      // if (!delay) break;
      final rangeCount = buf.pullVarInt();
      // if (!rangeCount) break;
      final firstRange = buf.pullVarInt();
      // if (!firstRange) break;

      final ranges = [];
      for (int i = 0; i < rangeCount; i++) {
        final gap = buf.pullVarInt();
        // if (!gap) break;
        final len = buf.pullVarInt();
        // if (!len) break;
        ranges.add((gap: gap, length: len));
      }

      var ecn = null;
      if (hasECN) {
        final ect0 = buf.pullVarInt();
        // if (!ect0) break;
        final ect1 = buf.pullVarInt();
        // if (!ect1) break;
        final ce = buf.pullVarInt();
        // if (!ce) break;
        ecn = (ect0: ect0, ect1: ect1, ce: ce);
      }

      frames.add((
        type: 'ack',
        largest: largest,
        delay: delay,
        firstRange: firstRange,
        ranges,
        ecn,
      ));
    } else if (type == 0x04) {
      final id = buf.pullVarInt();
      // if (!id) break;
      if (buf.remaining < 2) break;
      final error = buf.pullUint16();
      final finalSize = buf.pullVarInt();
      // if (!finalSize) break;
      frames.add((type: 'reset_stream', id: id, error, finalSize: finalSize));
    } else if (type == 0x05) {
      final id = buf.pullVarInt();
      // if (!id) break;
      if (buf.remaining < 2) break;
      final error = buf.pullVarInt();
      frames.add((type: 'stop_sending', id: id, error));
    } else if (type == 0x06) {
      final off = buf.pullVarInt();
      // if (!off) break;
      final len = buf.pullVarInt();
      // if (!len) break;
      if (buf.remaining < 2) break;
      final data = buf.pullBytes(len);
      // offset += len.value;
      frames.add((type: 'crypto', offset: off, data));
    } else if (type == 0x07) {
      final len = buf.pullVarInt();
      // if (!len) break;
      if (buf.remaining < 2) break;
      final token = buf.pullBytes(len);
      offset += len;
      frames.add((type: 'new_token', token));
    } else if ((type & 0xe0) == 0x00) {
      final fin = !!(type & 0x01 > 0x0);
      final lenb = !!(type & 0x02 > 0x0);
      final offb = !!(type & 0x04 > 0x0);

      final stream_id = buf.pullVarInt();
      // if (!stream_id) break;
      final offset_val = offb ? buf.pullVarInt() : 0;
      // if (!offset_val) break;
      final length_val = lenb ? buf.pullVarInt() : buf.pullBytes(buf.remaining);
      // if (!length_val) break;

      if (offset + length_val.value > buf.length) break;

      const data = buf.slice(offset, offset + length_val.value);
      offset += length_val.value;

      frames.push({
        type: 'stream',
        id: stream_id.value,
        offset: offset_val.value,
        fin,
        data,
      });
    } else if (type == 0x09) {
      const max = safeReadVarInt();
      if (!max) break;
      frames.push({type: 'max_data', max: max.value});
    } else if (type == 0x0a) {
      const id = safeReadVarInt();
      if (!id) break;
      const max = safeReadVarInt();
      if (!max) break;
      frames.push({type: 'max_stream_data', id: id.value, max: max.value});
    } else if (type == 0x12 || type == 0x13) {
      const max = safeReadVarInt();
      if (!max) break;
      frames.push({
        type: type == 0x12 ? 'max_streams_bidi' : 'max_streams_uni',
        max: max.value,
      });
    } else if (type == 0x14) {
      const max = safeReadVarInt();
      if (!max) break;
      frames.push({type: 'data_blocked', max: max.value});
    } else if (type == 0x15) {
      const id = safeReadVarInt();
      if (!id) break;
      frames.push({type: 'stream_data_blocked', id: id.value});
    } else if (type == 0x16 || type == 0x17) {
      const max = safeReadVarInt();
      if (!max) break;
      frames.push({
        type: type == 0x16 ? 'streams_blocked_bidi' : 'streams_blocked_uni',
        max: max.value,
      });
    } else if (type == 0x18) {
      const seq = safeReadVarInt();
      if (!seq) break;
      const retire = safeReadVarInt();
      if (!retire) break;
      if (offset >= buf.length) break;
      const len = buf[offset++];
      if (offset + len + 16 > buf.length) break;
      const connId = buf.slice(offset, offset + len);
      offset += len;
      const token = buf.slice(offset, offset + 16);
      offset += 16;
      frames.push({
        type: 'new_connection_id',
        seq: seq.value,
        retire: retire.value,
        connId,
        token,
      });
    } else if (type == 0x19) {
      const seq = safeReadVarInt();
      if (!seq) break;
      frames.push({type: 'retire_connection_id', seq: seq.value});
    } else if (type == 0x1a || type == 0x1b) {
      if (offset + 8 > buf.length) break;
      const data = buf.slice(offset, offset + 8);
      offset += 8;
      frames.push({
        type: type == 0x1a ? 'path_challenge' : 'path_response',
        data,
      });
    } else if (type == 0x1c || type == 0x1d) {
      if (offset + 2 > buf.length) break;
      const error = buf[offset++] << 8 | buf[offset++];
      let frameType = null;
      if (type == 0x1c) {
        const ft = safeReadVarInt();
        if (!ft) break;
        frameType = ft.value;
      }
      const reasonLen = safeReadVarInt();
      if (!reasonLen) break;
      if (offset + reasonLen.value > buf.length) break;
      const reason = textDecoder.decode(
        buf.slice(offset, offset + reasonLen.value),
      );
      offset += reasonLen.value;
      frames.push({
        type: 'connection_close',
        application: type == 0x1d,
        error,
        frameType,
        reason,
      });
    } else if (type == 0x1e) {
      frames.push({type: 'handshake_done'});
    } else if (type == 0x1f) {
      frames.push({type: 'immediate_ack'});
    } else if (type == 0x30 || type == 0x31) {
      let contextId = null;
      let len = null;

      if (type == 0x31) {
        // קורא את context ID
        var cid = safeReadVarInt(buf, offset);
        if (!cid) break;
        contextId = cid.value;
        offset = cid.nextOffset;
      }

      // החישוב של len מבוסס על מה שנשאר בפאקט אחרי הקריאה של contextId
      len = {value: buf.length - offset};

      if (offset + len.value > buf.length) break;

      const data = buf.slice(offset, offset + len.value);
      offset += len.value;

      frames.push({type: 'datagram', contextId: contextId, data: data});
    } else if (type == 0xaf) {
      const seq = safeReadVarInt();
      if (!seq) break;
      const packetTolerance = safeReadVarInt();
      if (!packetTolerance) break;
      if (offset >= buf.length) break;
      const ackDelayExponent = buf[offset++];
      const maxAckDelay = safeReadVarInt();
      if (!maxAckDelay) break;
      frames.push({
        type: 'ack_frequency',
        seq: seq.value,
        packetTolerance: packetTolerance.value,
        ackDelayExponent,
        maxAckDelay: maxAckDelay.value,
      });
    } else if (type >= 0x15228c00 && type <= 0x15228cff) {
      frames.push({type: 'multipath_extension', frameType: type});
    } else {
      frames.push({type: 'unknown', frameType: type, offset: start});
      break;
    }
  }

  return frames;
}
