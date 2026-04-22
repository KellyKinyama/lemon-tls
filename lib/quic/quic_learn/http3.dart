// HTTP/3 INTEGRATION INTO *YOUR* QuicServerSession
// ------------------------------------------------------------
// This replaces the abstract Http3Connection example and shows
// the EXACT hooks inside your existing server.
//
// You already have:
//  - QUIC handshake + 1-RTT keys
//  - STREAM frame parsing in _parsePayload()
//  - send/receive of application packets
//
// HTTP/3 starts ONLY AFTER:
//   handshakeComplete == true

import 'dart:convert';
import 'dart:typed_data';

import '../utils.dart';
import 'h31.dart';
// import 'h3_qpack.dart';
// import '../../utils.dart';
import 'server/quic_server_session.dart';

// ------------------------------------------------------------
// HTTP/3 constants
// ------------------------------------------------------------

const int H3_FRAME_DATA = 0x00;
const int H3_FRAME_HEADERS = 0x01;
const int H3_FRAME_SETTINGS = 0x04;
const int H3_STREAM_TYPE_CONTROL = 0x00;
// ------------------------------------------------------------
// HTTP/3 per-connection state
// ------------------------------------------------------------

class Http3State {
  bool controlStreamSent = false;
  // Reassembly buffers per request stream
  final Map<int, Map<int, Uint8List>> streamChunks = {};
  final Map<int, int> streamOffsets = {};
}

// ------------------------------------------------------------
// REQUIRED: add this field to QuicServerSession
// ------------------------------------------------------------
//
//   final Http3State h3 = Http3State();
//
// ------------------------------------------------------------
// 1) SEND CONTROL STREAM (call once after handshakeComplete)
// ------------------------------------------------------------
void sendHttp3ControlStream(QuicServerSession s) {
  if (s.h3.controlStreamSent) return;
  final settingsPayload = build_settings_frame({
    'SETTINGS_QPACK_MAX_TABLE_CAPACITY': 0,
    'SETTINGS_QPACK_BLOCKED_STREAMS': 0,
    // enable later
    // 'SETTINGS_H3_DATAGRAM': 1,
    // 'SETTINGS_ENABLE_WEBTRANSPORT': 1,
  });
  final controlStreamBytes = Uint8List.fromList([
    ...writeVarInt(H3_STREAM_TYPE_CONTROL),
    ...writeVarInt(H3_FRAME_SETTINGS),
    ...writeVarInt(settingsPayload.length),
    ...settingsPayload,
  ]);
  // SERVER-INITIATED UNIDIRECTIONAL STREAM
  s.sendApplicationUnidirectionalStream(controlStreamBytes);
  s.h3.controlStreamSent = true;
  print('✅ HTTP/3 control stream sent');
}

// ------------------------------------------------------------
// 2) CALL FROM _parsePayload() WHEN YOU PARSE A STREAM FRAME
// ------------------------------------------------------------
void handleHttp3StreamData(
  QuicServerSession s,
  int streamId,
  Uint8List streamData,
) {
  final chunks = s.h3.streamChunks.putIfAbsent(streamId, () => {});
  final offset = s.h3.streamOffsets[streamId] ?? 0;
  chunks[offset] = streamData;
  final extracted = extract_h3_frames_from_chunks(chunks, offset);
  s.h3.streamOffsets[streamId] = extracted['new_from_offset'] as int;
  for (final frame in extracted['frames']) {
    final int type = frame['frame_type'] as int;
    final Uint8List payload = frame['payload'] as Uint8List;
    if (type == H3_FRAME_HEADERS) {
      handleHttp3HeadersFrame(s, streamId, payload);
    }

    if (type == H3_FRAME_DATA) {
      // request body (optional)
    }
  }
}

// ------------------------------------------------------------
// 3) DECODE HEADERS AND SEND RESPONSE
// ------------------------------------------------------------
void handleHttp3HeadersFrame(
  QuicServerSession s,
  int streamId,
  Uint8List headerBlock,
) {
  final headers = decode_qpack_header_fields(headerBlock);
  String method = 'GET';
  String path = '/';
  for (final h in headers) {
    if (h.name == ':method') method = h.value;
    if (h.name == ':path') path = h.value;
  }
  print('📥 HTTP/3 request on stream $streamId: $method $path');
  final body = utf8.encode('hello from http/3');
  final responseHeaderBlock = build_http3_literal_headers_frame({
    ':status': '200',
    'content-type': 'text/plain; charset=utf-8',
    'content-length': body.length,
  });
  final responseFrames = build_h3_frames([
    {'frame_type': H3_FRAME_HEADERS, 'payload': responseHeaderBlock},
    {'frame_type': H3_FRAME_DATA, 'payload': Uint8List.fromList(body)},
  ]);
  // SAME STREAM AS REQUEST, FIN = true
  s.sendApplicationStream(streamId, responseFrames, fin: true);
}

// ------------------------------------------------------------
// REQUIRED SERVER HOOKS (YOU ALREADY HAVE THESE)
// ------------------------------------------------------------
//
// In _maybeHandleClientFinished():
//
//   handshakeComplete = true;
//   _deriveApplicationSecrets();
//   sendHttp3ControlStream(this);
//
// In _parsePayload(), when parsing STREAM frames at 1-RTT:
//
//   handleHttp3StreamData(this, streamId, streamData);
//
// That is the FULL HTTP/3 integration.
