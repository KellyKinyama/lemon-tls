// ============================================================================
// tls_read.dart// tls_read.dart
// ============================================================================

import 'dart:typed_data';

/// Read 1 byte, return [value, newOffset]
List<dynamic> r_u8(Uint8List buf, int off) {
  int v = buf[off] & 0xFF;
  return [v, off + 1];
}

/// Read 2 bytes big‑endian, return [value, newOffset]
List<dynamic> r_u16(Uint8List buf, int off) {
  int v = ((buf[off] << 8) | buf[off + 1]) & 0xFFFF;
  return [v, off + 2];
}

/// Read 3 bytes big‑endian, return [value, newOffset]
List<dynamic> r_u24(Uint8List buf, int off) {
  int v = ((buf[off] << 16) | (buf[off + 1] << 8) | buf[off + 2]) & 0xFFFFFF;
  return [v, off + 3];
}

/// Read N bytes and return a Uint8List slice + new offset
List<dynamic> r_bytes(Uint8List buf, int off, int n) {
  // Uint8List.sublist returns a copy (good — JS .slice creates new buffer)
  Uint8List slice = buf.sublist(off, off + n);
  return [slice, off + n];
}
// Binary read helpers (r_u8, r_u16, r_u24, r_bytes)
// ============================================================================
// tls_write.dart
// Binary write helpers (w_u8, w_u16, w_u24, w_bytes)
// Converted directly from the original JavaScript implementation
// ============================================================================

/// Write 1 byte (unsigned)
int w_u8(Uint8List buf, int off, int v) {
  buf[off++] = v & 0xFF;
  return off;
}

/// Write 2 bytes big‑endian (unsigned)
int w_u16(Uint8List buf, int off, int v) {
  buf[off++] = (v >> 8) & 0xFF;
  buf[off++] = v & 0xFF;
  return off;
}

/// Write 3 bytes big‑endian (unsigned)
int w_u24(Uint8List buf, int off, int v) {
  buf[off++] = (v >> 16) & 0xFF;
  buf[off++] = (v >> 8) & 0xFF;
  buf[off++] = v & 0xFF;
  return off;
}

/// Copy a byte array into `buf` starting at offset
int w_bytes(Uint8List buf, int off, Uint8List bytes) {
  buf.setRange(off, off + bytes.length, bytes);
  return off + bytes.length;
}

// ============================================================================
// tls_vectors.dart
// TLS vector helpers converted from JavaScript with minimal changes.
// Includes: veclen(), readVec(), isVec2()
// ============================================================================

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

Uint8List toU8(dynamic v) {
  if (v == null) return Uint8List(0);
  if (v is Uint8List) return v;
  if (v is ByteBuffer) return Uint8List.view(v);
  if (v is List<int>) return Uint8List.fromList(v);
  throw ArgumentError(
    'Expected Uint8List/List<int>/ByteBuffer, got ${v.runtimeType}',
  );
}

Uint8List concatUint8Arrays(List<Uint8List> parts) {
  var total = 0;
  for (final p in parts) {
    total += p.length;
  }

  final out = Uint8List(total);
  var offset = 0;
  for (final p in parts) {
    out.setRange(offset, offset + p.length, p);
    offset += p.length;
  }
  return out;
}
