// ============================================================================
// TLS 1.3 Extensions
// RFC 8446 §4.2
// ============================================================================

import 'dart:typed_data';
import 'dart:convert';

import 'tls_constants.dart';
import 'utils.dart';

/// Extension handler entry
class TlsExtensionHandler {
  Uint8List Function(dynamic)? encode;
  dynamic Function(Uint8List)? decode;

  TlsExtensionHandler({this.encode, this.decode});
}

/// Global registry
final Map<String, TlsExtensionHandler> tls13Ext = {
  "SERVER_NAME": TlsExtensionHandler(),
  "SUPPORTED_VERSIONS": TlsExtensionHandler(),
  "SUPPORTED_GROUPS": TlsExtensionHandler(),
  "SIGNATURE_ALGORITHMS": TlsExtensionHandler(),
  "PSK_KEY_EXCHANGE_MODES": TlsExtensionHandler(),
  "KEY_SHARE": TlsExtensionHandler(),
  "ALPN": TlsExtensionHandler(),
  "COOKIE": TlsExtensionHandler(),
};

/// Resolve extension symbolic name
String extNameByCode(int code) {
  for (final entry in TLSExt.values.entries) {
    if (entry.value == code) return entry.key;
  }
  return "EXT_$code";
}

// ============================================================================
//  SERVER NAME INDICATION  (SNI)
// ============================================================================

void _initSNI() {
  tls13Ext["SERVER_NAME"]!.encode = (value) {
    final host = toU8(value ?? "");
    // list(2) → one entry: type=0, len=hostLen, host bytes
    final inner = Uint8List(1 + 2 + host.length);
    int off = 0;
    off = w_u8(inner, off, 0);
    off = w_u16(inner, off, host.length);
    off = w_bytes(inner, off, host);
    return veclen(2, inner);
  };

  tls13Ext["SERVER_NAME"]!.decode = (Uint8List data) {
    int off = 0;
    final listRes = readVec(data, off, 2);
    final list = listRes[0] as Uint8List;

    int p = 0;
    while (p < list.length) {
      final typeR = r_u8(list, p);
      final type = typeR[0];
      p = typeR[1];

      final lenR = r_u16(list, p);
      final len = lenR[0];
      p = lenR[1];

      final valR = r_bytes(list, p, len);
      final v = valR[0] as Uint8List;
      p = valR[1];

      if (type == 0) {
        return utf8.decode(v);
      }
    }

    return "";
  };
}

// ============================================================================
// SUPPORTED_VERSIONS  (ClientHello + ServerHello)
// ============================================================================

void _initSupportedVersions() {
  tls13Ext["SUPPORTED_VERSIONS"]!.encode = (value) {
    if (value is int) {
      // ServerHello form
      final out = Uint8List(2);
      w_u16(out, 0, value);
      return out;
    }

    // ClientHello → vector of u16
    final arr = (value is List) ? value.cast<int>() : [TLSVersion.TLS1_3];
    final body = Uint8List(1 + arr.length * 2);

    int off = 0;
    off = w_u8(body, off, arr.length * 2);
    for (final v in arr) {
      off = w_u16(body, off, v);
    }
    return body;
  };

  tls13Ext["SUPPORTED_VERSIONS"]!.decode = (Uint8List data) {
    if (data.length == 2) {
      final r = r_u16(data, 0);
      return r[0];
    }

    int off = 0;
    final lenR = r_u8(data, off);
    int n = lenR[0];
    off = lenR[1];

    final out = <int>[];
    for (int i = 0; i < n; i += 2) {
      final r = r_u16(data, off);
      out.add(r[0]);
      off = r[1];
    }
    return out;
  };
}

// ============================================================================
// SUPPORTED_GROUPS  (X25519, secp256r1)
// ============================================================================

void _initSupportedGroups() {
  tls13Ext["SUPPORTED_GROUPS"]!.encode = (value) {
    final groups = (value is List) ? value.cast<int>() : [0x001D, 0x0017];
    final body = Uint8List(2 + groups.length * 2);

    int off = 0;
    off = w_u16(body, off, groups.length * 2);
    for (final g in groups) {
      off = w_u16(body, off, g);
    }
    return body;
  };

  tls13Ext["SUPPORTED_GROUPS"]!.decode = (Uint8List data) {
    int off = 0;
    final r = r_u16(data, off);
    int n = r[0];
    off = r[1];

    final list = <int>[];
    for (int i = 0; i < n; i += 2) {
      final rr = r_u16(data, off);
      list.add(rr[0]);
      off = rr[1];
    }
    return list;
  };
}

// ============================================================================
// SIGNATURE_ALGORITHMS  (TLS 1.3 needs ECDSA + SHA256)
// ============================================================================

void _initSignatureAlgorithms() {
  tls13Ext["SIGNATURE_ALGORITHMS"]!.encode = (value) {
    final algs = (value is List)
        ? value.cast<int>()
        : [0x0403]; // ecdsa_secp256r1_sha256

    final body = Uint8List(2 + algs.length * 2);
    int off = 0;
    off = w_u16(body, off, algs.length * 2);

    for (final a in algs) {
      off = w_u16(body, off, a);
    }
    return body;
  };

  tls13Ext["SIGNATURE_ALGORITHMS"]!.decode = (Uint8List data) {
    int off = 0;
    final r = r_u16(data, off);
    int n = r[0];
    off = r[1];

    final list = <int>[];
    for (int i = 0; i < n; i += 2) {
      final rr = r_u16(data, off);
      list.add(rr[0]);
      off = rr[1];
    }
    return list;
  };
}

// ============================================================================
// PSK KEY EXCHANGE MODES  (Required even if unused)
// ============================================================================

void _initPSKModes() {
  tls13Ext["PSK_KEY_EXCHANGE_MODES"]!.encode = (value) {
    final modes = (value is List) ? value.cast<int>() : [1];
    final body = Uint8List(1 + modes.length);

    int off = 0;
    off = w_u8(body, off, modes.length);
    for (final m in modes) {
      off = w_u8(body, off, m);
    }
    return body;
  };

  tls13Ext["PSK_KEY_EXCHANGE_MODES"]!.decode = (Uint8List data) {
    int off = 0;
    final r = r_u8(data, off);
    int n = r[0];
    off = r[1];

    final out = <int>[];
    for (int i = 0; i < n; i++) {
      final rr = r_u8(data, off);
      out.add(rr[0]);
      off = rr[1];
    }
    return out;
  };
}

// ============================================================================
// KEY_SHARE (ClientHello / ServerHello) — FINAL, CORRECTED VERSION
// ============================================================================
void _initKeyShare() {
  tls13Ext["KEY_SHARE"]!.encode = (value) {
    if (value is Map) {
      // ServerHello
      final Uint8List ke = toU8(value["key_exchange"]);
      final out = Uint8List(4 + ke.length);
      int off = 0;

      off = w_u16(out, off, value["group"]);
      off = w_u16(out, off, ke.length);
      off = w_bytes(out, off, ke);

      return out;
    }

    // ClientHello list format
    final list = (value is List)
        ? value.cast<Map<String, dynamic>>()
        : <Map<String, dynamic>>[];

    final parts = <Uint8List>[];

    for (final e in list) {
      final Uint8List ke = toU8(e["key_exchange"]);
      final entry = Uint8List(4 + ke.length);
      int off = 0;
      off = w_u16(entry, off, e["group"]);
      off = w_u16(entry, off, ke.length);
      off = w_bytes(entry, off, ke);
      parts.add(entry);
    }

    return veclen(2, concatUint8Arrays(parts));
  };

  tls13Ext["KEY_SHARE"]!.decode = (Uint8List data) {
    // ✅ FIRST: Detect ClientHello via vector<2> length-prefix
    if (data.length >= 2) {
      final declared = (data[0] << 8) | data[1];
      if (declared == data.length - 2) {
        // ClientHello list
        int off = 2;
        final end = 2 + declared;
        final out = <Map<String, dynamic>>[];

        while (off + 4 <= end) {
          final group = (data[off] << 8) | data[off + 1];
          final len = (data[off + 2] << 8) | data[off + 3];
          off += 4;

          if (off + len > end) break;

          final key = data.sublist(off, off + len);
          off += len;

          out.add({"group": group, "key_exchange": key});
        }

        return out;
      }
    }

    // ✅ SECOND: Treat as ServerHello KEY_SHARE
    if (data.length >= 4) {
      final group = (data[0] << 8) | data[1];
      final len = (data[2] << 8) | data[3];

      if (4 + len == data.length) {
        final key = data.sublist(4);
        return {"group": group, "key_exchange": key};
      }
    }

    return null;
  };
}
// ============================================================================
// ALPN (Application-Layer Protocol Negotiation)
// ============================================================================

void _initALPN() {
  tls13Ext["ALPN"]!.encode = (value) {
    final list = (value is List) ? value.cast<String>() : [];

    // ✅ FIX: convert strings to UTF‑8 byte lists
    final protocols = list.map((s) => utf8.encode(s)).toList();

    int total = 2;
    for (final p in protocols) {
      total += 1 + p.length;
    }

    final out = Uint8List(total);
    int off = 0;

    off = w_u16(out, off, total - 2);

    for (final p in protocols) {
      off = w_u8(out, off, p.length);
      off = w_bytes(out, off, Uint8List.fromList(p));
    }

    return out;
  };

  tls13Ext["ALPN"]!.decode = (Uint8List data) {
    int off = 0;
    final r = r_u16(data, off);
    int n = r[0];
    off = r[1];

    final out = <String>[];
    int end = off + n;

    while (off < end) {
      final r1 = r_u8(data, off);
      final len = r1[0];
      off = r1[1];

      final r2 = r_bytes(data, off, len);
      out.add(utf8.decode(r2[0]));
      off = r2[1];
    }

    return out;
  };
}

// ============================================================================
// COOKIE (used for HelloRetryRequest)
// ============================================================================

void _initCookie() {
  tls13Ext["COOKIE"]!.encode = (v) {
    final Uint8List bytes = toU8(v ?? Uint8List(0));
    return veclen(2, bytes);
  };

  tls13Ext["COOKIE"]!.decode = (Uint8List data) {
    final r = readVec(data, 0, 2);
    return r[0];
  };
}

// ============================================================================
// Build extension list into a TLS vector<2>
// ============================================================================

Uint8List buildExtensions(List<Map<String, dynamic>> list) {
  if (list.isEmpty) {
    final empty = Uint8List(2);
    w_u16(empty, 0, 0);
    return empty;
  }

  final parts = <Uint8List>[];
  int total = 2;

  for (final e in list) {
    dynamic t = e["type"];
    if (t is String) t = TLSExt.values[t];

    Uint8List payload;

    if (e.containsKey("data") && e["data"] is Uint8List) {
      payload = e["data"];
    } else {
      final name = extNameByCode(t);
      final handler = tls13Ext[name];
      payload = handler?.encode?.call(e["value"]) ?? Uint8List(0);
    }

    final rec = Uint8List(4 + payload.length);
    int off = 0;
    off = w_u16(rec, off, t);
    off = w_u16(rec, off, payload.length);
    off = w_bytes(rec, off, payload);

    parts.add(rec);
    total += rec.length;
  }

  final out = Uint8List(total);
  int off = 0;

  off = w_u16(out, off, total - 2);
  for (final p in parts) {
    off = w_bytes(out, off, p);
  }

  return out;
}

// ============================================================================
// Parse extension list
// ============================================================================

List<Map<String, dynamic>> parseExtensions(Uint8List buf) {
  final out = <Map<String, dynamic>>[];

  int off = 0;
  final r0 = r_u16(buf, off);
  int total = r0[0];
  off = r0[1];

  final end = off + total;

  while (off < end) {
    final r1 = r_u16(buf, off);
    final type = r1[0];
    off = r1[1];

    final r2 = r_u16(buf, off);
    final len = r2[0];
    off = r2[1];

    final r3 = r_bytes(buf, off, len);
    final Uint8List data = r3[0];
    off = r3[1];

    final name = extNameByCode(type);
    final handler = tls13Ext[name];

    final value = handler?.decode?.call(data);

    out.add({"type": type, "name": name, "data": data, "value": value});
  }

  return out;
}

// ============================================================================
// Initialize registry on load
// ============================================================================

void initTls13Extensions() {
  _initSNI();
  _initSupportedVersions();
  _initSupportedGroups();
  _initSignatureAlgorithms();
  _initPSKModes();
  _initKeyShare();
  _initALPN();
  _initCookie();
}

// initTls13Extensions();
