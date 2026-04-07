// ============================================================================
// tls_utils.dart
// Utility helpers converted from the original JavaScript implementation
// ============================================================================

import 'dart:typed_data';
import 'dart:convert';

/// Convert various input types into Uint8List (similar to JS toU8)
Uint8List toU8(dynamic x) {
  if (x == null) {
    return Uint8List(0);
  }

  if (x is Uint8List) {
    return x;
  }

  if (x is List<int>) {
    return Uint8List.fromList(x);
  }

  if (x is String) {
    return Uint8List.fromList(utf8.encode(x));
  }

  return Uint8List(0);
}

/// Concatenate multiple Uint8List segments into one
Uint8List concatUint8Arrays(List<Uint8List> parts) {
  int total = 0;
  for (var p in parts) {
    total += p.length;
  }

  final out = Uint8List(total);
  int offset = 0;

  for (var p in parts) {
    out.setRange(offset, offset + p.length, p);
    offset += p.length;
  }

  return out;
}

/// Concatenate two Uint8List objects (common operation)
Uint8List concat2(Uint8List a, Uint8List b) {
  final out = Uint8List(a.length + b.length);
  out.setRange(0, a.length, a);
  out.setRange(a.length, a.length + b.length, b);
  return out;
}

/// Create a zero-filled Uint8List of the given length
Uint8List u8(int length) {
  return Uint8List(length);
}