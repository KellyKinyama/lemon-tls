// ===============================================================
// TLS Socket Reader (safe utility, NOT crypto)
// ===============================================================

import 'dart:io';
import 'dart:typed_data';

class TlsSocketReader {
  final Socket socket;
  final BytesBuilder _buffer = BytesBuilder();
  bool _listening = false;

  TlsSocketReader(this.socket);

  void _ensureListening() {
    if (_listening) return;
    _listening = true;

    socket.listen((data) {
      _buffer.add(data);
    });
  }

  Future<Uint8List?> readTlsRecord() async {
    _ensureListening();

    // Wait for header
    while (_buffer.length < 5) {
      await Future.delayed(Duration(milliseconds: 1));
    }

    final bytes = _buffer.toBytes();
    final length = (bytes[3] << 8) | bytes[4];

    // Wait for full record
    while (_buffer.length < 5 + length) {
      await Future.delayed(Duration(milliseconds: 1));
    }

    final full = _buffer.toBytes();
    final record = Uint8List.fromList(full.sublist(0, 5 + length));

    final remaining = full.sublist(5 + length);
    _buffer.clear();
    _buffer.add(remaining);

    return record;
  }
}
