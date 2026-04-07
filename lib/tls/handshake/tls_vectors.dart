// ============================================================================
// tls_vectors.dart
// TLS vector helpers converted from JavaScript with minimal changes.
// Includes: veclen(), readVec(), isVec2()
// ============================================================================

import 'dart:typed_data';
import 'tls_write.dart';
import 'tls_read.dart';
import 'tls_utils.dart';

/// Encode a vector with a length prefix of 1, 2, or 3 bytes.
/// Equivalent to JS: veclen(lenBytes, inner)
Uint8List veclen(int lenBytes, Uint8List inner) {
  if (lenBytes == 1) {
    final out = Uint8List(1 + inner.length);
    int off = 0;
    off = w_u8(out, off, inner.length);
    off = w_bytes(out, off, inner);
    return out;
  }

  if (lenBytes == 2) {
    final out = Uint8List(2 + inner.length);
    int off = 0;
    off = w_u16(out, off, inner.length);
    off = w_bytes(out, off, inner);
    return out;
  }

  if (lenBytes == 3) {
    final out = Uint8List(3 + inner.length);
    int off = 0;
    off = w_u24(out, off, inner.length);
    off = w_bytes(out, off, inner);
    return out;
  }

  throw ArgumentError('veclen only supports 1/2/3 bytes');
}

/// Read a vector with a 1-, 2-, or 3‑byte length prefix.
/// Equivalent to JS: readVec(buf, off, lenBytes)
///
/// Returns: [Uint8List value, int newOffset]
List<dynamic> readVec(Uint8List buf, int off, int lenBytes) {
  int n;
  int off2 = off;

  if (lenBytes == 1) {
    final r = r_u8(buf, off2);
    n = r[0];
    off2 = r[1];
  } else if (lenBytes == 2) {
    final r = r_u16(buf, off2);
    n = r[0];
    off2 = r[1];
  } else if (lenBytes == 3) {
    final r = r_u24(buf, off2);
    n = r[0];
    off2 = r[1];
  } else {
    throw ArgumentError('readVec only supports 1/2/3 bytes');
  }

  final r2 = r_bytes(buf, off2, n);
  final bytes = r2[0] as Uint8List;
  final newOffset = r2[1] as int;

  return [bytes, newOffset];
}

/// Check if the given Uint8List matches the vec<2> format:
/// first two bytes give the length, and total size == length + 2.
/// Equivalent to JS: isVec2(u8)
bool isVec2(Uint8List u8) {
  if (u8.length < 2) return false;
  final len = (u8[0] << 8) | u8[1];
  return u8.length == 2 + len;
}