import 'dart:typed_data';

import 'handshake_common.dart';    // wU16, wBytes, concat
import 'ext_registry.dart';        // your TLS_EXT + exts registry

/// Build a TLS extension list into a vec<u16> buffer.
/// Each entry in [list] is:
///   { "type": int or string, "value": any, "data": Uint8List? }
///
/// If `data` exists, it is used directly.
/// Otherwise, looks up encoder in `exts[ name ].encode(value)`.
Uint8List buildExtensions(List<Map<String, dynamic>> list) {
  if (list.isEmpty) {
    // Empty vec<u16> = [0x00, 0x00]
    return Uint8List.fromList([0x00, 0x00]);
  }

  final parts = <Uint8List>[];
  int total = 2; // vec<u16> length prefix

  for (final item in list) {
    dynamic t = item["type"];

    // Allow symbolic names (e.g. "SERVER_NAME")
    if (t is String) {
      t = TLS_EXT[t]; // lookup from your registry
    }

    // Determine payload: user-supplied data OR registry encoder
    Uint8List payload;

    if (item.containsKey("data") && item["data"] is Uint8List) {
      payload = item["data"];
    } else {
      final name = extNameByCode(t);
      final encoder = exts[name]?.encode;

      if (encoder != null) {
        payload = encoder(item["value"]);
      } else {
        payload = Uint8List(0);
      }
    }

    // Build extension record: type(2) + length(2) + payload
    final rec = Uint8List(4 + payload.length);
    int off = 0;

    off = wU16(rec, off, t);
    off = wU16(rec, off, payload.length);
    wBytes(rec, off, payload);

    parts.add(rec);
    total += rec.length;
  }

  // Final vec<u16> output = 2‑byte length + all extension entries
  final out = Uint8List(total);
  int off2 = 0;

  off2 = wU16(out, off2, total - 2);

  for (final rec in parts) {
    off2 = wBytes(out, off2, rec);
  }

  return out;
}