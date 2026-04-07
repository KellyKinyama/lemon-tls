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
