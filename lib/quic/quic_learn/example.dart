
// Minimal HTTP/3 connection integration example
// ------------------------------------------------------------
// This example shows exactly how to:
// 1) Create the HTTP/3 control stream
// 2) Parse request streams (HEADERS frames)
// 3) Send HEADERS + DATA responses
//
// It assumes you already have:
// - A working QUIC connection abstraction
// - Stream read/write primitives
// - The QPACK/HTTP3 helpers file you asked for earlier imported
//
// This is NOT a full QUIC stack; it is the glue layer between
// your QUIC streams and HTTP/3 semantics.

import 'dart:convert';
import 'dart:typed_data';

import 'h3_qpack.dart'; // <- the corrected file I gave you
import 'utils.dart';    // concatUint8Lists, writeVarInt, readVarInt

// ------------------------------------------------------------
// Minimal QUIC stream abstraction (what your QUIC layer provides)
// ------------------------------------------------------------

abstract class QuicStream {
  final int id;
  QuicStream(this.id);

  void write(Uint8List data);
  void close();
}

abstract class QuicConnection {
  QuicStream openUnidirectionalStream();
  void onBidirectionalStream(void Function(QuicStream stream) cb);
}

// ------------------------------------------------------------
// HTTP/3 connection wrapper
// ------------------------------------------------------------

class Http3Connection {
  final QuicConnection quic;

  Http3Connection(this.quic);

  /// Call once after QUIC handshake completes
  void initialize() {
    _createControlStream();
    _listenForRequestStreams();
  }

  // ----------------------------------------------------------
  // 1) Create HTTP/3 control stream
  // ----------------------------------------------------------

  void _createControlStream() {
    final QuicStream control = quic.openUnidirectionalStream();

    // SETTINGS for a static-QPACK server
    final settingsBytes = build_control_stream({
      'SETTINGS_QPACK_MAX_TABLE_CAPACITY': 0,
      'SETTINGS_QPACK_BLOCKED_STREAMS': 0,
      // Enable these later when you implement them
      // 'SETTINGS_H3_DATAGRAM': 1,
      // 'SETTINGS_ENABLE_WEBTRANSPORT': 1,
    });

    control.write(settingsBytes);
    control.close();
  }

  // ----------------------------------------------------------
  // 2) Accept and parse request streams
  // ----------------------------------------------------------

  void _listenForRequestStreams() {
    quic.onBidirectionalStream((QuicStream stream) {
      _handleRequestStream(stream);
    });
  }

  void _handleRequestStream(QuicStream stream) {
    // Very minimal buffering model
    final Map<int, Uint8List> chunks = {};
    int offset = 0;

    // This callback represents data arriving on the stream
    void onData(Uint8List data) {
      chunks[offset] = data;

      final extracted = extract_h3_frames_from_chunks(chunks, offset);
      offset = extracted['new_from_offset'] as int;

      for (final frame in extracted['frames']) {
        final int frameType = frame['frame_type'] as int;
        final Uint8List payload = frame['payload'] as Uint8List;

        // HEADERS frame
        if (frameType == 0x01) {
          _handleHeadersFrame(stream, payload);
        }

        // DATA frame (ignored in this minimal example)
        if (frameType == 0x00) {
          // Request body handling would go here
        }
      }
    }

    // In a real implementation, you would hook this into your
    // QUIC stream receive callback. For example:
    // stream.onData(onData);
  }

  // ----------------------------------------------------------
  // 3) Parse HEADERS and send response
  // ----------------------------------------------------------

  void _handleHeadersFrame(QuicStream stream, Uint8List headerBlock) {
    // Decode QPACK
    final headers = decode_qpack_header_fields(headerBlock);

    String method = 'GET';
    String path = '/';

    for (final h in headers) {
      if (h.name == ':method') method = h.value;
      if (h.name == ':path') path = h.value;
    }

    print('HTTP/3 request: $method $path');

    // Build response
    final body = utf8.encode('hello from http/3');

    final responseHeaders = <String, Object?>{
      ':status': '200',
      'content-type': 'text/plain; charset=utf-8',
      'content-length': body.length,
    };

    final headersBlock = build_http3_literal_headers_frame(responseHeaders);

    final responseBytes = build_h3_frames([
      {
        'frame_type': 0x01, // HEADERS
        'payload': headersBlock,
      },
      {
        'frame_type': 0x00, // DATA
        'payload': Uint8List.fromList(body),
      },
    ]);

    stream.write(responseBytes);
    stream.close();
  }
}

// ------------------------------------------------------------
// Usage (conceptual)
// ------------------------------------------------------------

void attachHttp3(QuicConnection quic) {
  final h3 = Http3Connection(quic);
  h3.initialize();
}
