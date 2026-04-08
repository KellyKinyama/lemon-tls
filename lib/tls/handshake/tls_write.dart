// // ============================================================================
// // tls_write.dart
// // Binary write helpers (w_u8, w_u16, w_u24, w_bytes)
// // Converted directly from the original JavaScript implementation
// // ============================================================================

// import 'dart:typed_data';

// /// Write 1 byte (unsigned)
// int w_u8(Uint8List buf, int off, int v) {
//   buf[off++] = v & 0xFF;
//   return off;
// }

// /// Write 2 bytes big‑endian (unsigned)
// int w_u16(Uint8List buf, int off, int v) {
//   buf[off++] = (v >> 8) & 0xFF;
//   buf[off++] = v & 0xFF;
//   return off;
// }

// /// Write 3 bytes big‑endian (unsigned)
// int w_u24(Uint8List buf, int off, int v) {
//   buf[off++] = (v >> 16) & 0xFF;
//   buf[off++] = (v >> 8) & 0xFF;
//   buf[off++] = v & 0xFF;
//   return off;
// }

// /// Copy a byte array into `buf` starting at offset
// int w_bytes(Uint8List buf, int off, Uint8List bytes) {
//   buf.setRange(off, off + bytes.length, bytes);
//   return off + bytes.length;
// }