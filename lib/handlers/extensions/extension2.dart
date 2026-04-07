/* =========================== Extensions registry =========================== */
import 'dart:convert';
import 'dart:typed_data';

import '../../utils.dart';
import '../message_types.dart';
import 'extensions.dart';

class Codec {
  Function? encode;

  Function? decode;
  Codec({this.encode, this.decode});
}

Map<String, Codec> exts = {};

void initParsing() {
  // Predeclare wanted entries
  exts['SERVER_NAME'] = Codec(encode: null, decode: null);
  exts['SUPPORTED_VERSIONS'] = Codec(encode: null, decode: null);
  exts['SUPPORTED_GROUPS'] = Codec(encode: null, decode: null);
  exts['SIGNATURE_ALGORITHMS'] = Codec(encode: null, decode: null);
  exts['PSK_KEY_EXCHANGE_MODES'] = Codec(encode: null, decode: null);
  exts['KEY_SHARE'] = Codec(encode: null, decode: null);
  exts['ALPN'] = Codec(encode: null, decode: null);
  exts['RENEGOTIATION_INFO'] = Codec(encode: null, decode: null);

  /* ------------------------------ SERVER_NAME (0) ------------------------------ */
  exts['SERVER_NAME']!.encode = (value) {
    var host = toU8(value ?? "");

    // one name: type(1)=0, len(2), bytes
    var inner = Uint8List(1 + 2 + host.length);
    var off = 0;

    off = w_u8(inner, off, 0);
    off = w_u16(inner, off, host.length);
    off = w_bytes(inner, off, host);

    // ServerNameList is vector<2>
    return veclen(2, inner);
  };

  exts['SERVER_NAME']!.decode = (data) {
    var off = 0;
    var list;
    (list, off) = readVec(data, off, 2);

    var off2 = 0;
    var host = "";

    while (off2 < list.length) {
      var typ;
      (typ, off2) = r_u8(list, off2);

      var l;
      (l, off2) = r_u16(list, off2);

      var v;
      (v, off2) = r_bytes(list, off2, l);

      if (typ == 0) {
        host = utf8.decode(v);
      }
    }

    // Return just the value (string), not {host: ...}
    return host;
  };

  /* --------------------------- SUPPORTED_VERSIONS (43) --------------------------- */
  exts['SUPPORTED_VERSIONS']!.encode = (value) {
    // ServerHello form: selected (number)
    if (value is num) {
      var out = Uint8List(2);
      var off = 0;
      off = w_u16(out, off, value);
      return out;
    }

    // ClientHello form: array of versions
    List<int> arr = (value is Uint8List || value is List<int>)
        ? value
        : [TLS_VERSION.TLS1_3.value, TLS_VERSION.TLS1_2.value];

    var body = Uint8List(1 + arr.length * 2);
    var off2 = 0;

    off2 = w_u8(body, off2, arr.length * 2);
    for (var i = 0; i < arr.length; i++) {
      off2 = w_u16(body, off2, arr[i]);
    }
    return body;
  };

  exts['SUPPORTED_VERSIONS']!.decode = (data) {
    // ServerHello form: 2 bytes
    if (data.length == 2) {
      var v, off = 0;
      (v, off) = r_u16(data, off);
      return v; // return the selected version (number)
    }

    // ClientHello form: vector<1> of versions (u16 each)
    var off2 = 0;
    var n;
    (n, off2) = r_u8(data, off2);

    var out = [];
    for (var i = 0; i < n; i += 2) {
      var vv;
      (vv, off2) = r_u16(data, off2);
      out.add(vv);
    }
    return out; // return the array directly
  };

  /* ---------------------------- SUPPORTED_GROUPS (10) ---------------------------- */
  exts['SUPPORTED_GROUPS']!.encode = (value) {
    var groups =
        ((value is Uint8List || value is List<int>) ? value : [23, 29])
            as List<int>; // secp256r1, x25519

    var body = Uint8List(2 + groups.length * 2);
    var off = 0;

    off = w_u16(body, off, groups.length * 2);
    for (var i = 0; i < groups.length; i++) {
      off = w_u16(body, off, groups[i]);
    }
    return body;
  };

  exts['SUPPORTED_GROUPS']!.decode = (data) {
    var off = 0;
    var n;
    (n, off) = r_u16(data, off);

    var out = [];
    for (var i = 0; i < n; i += 2) {
      var g;
      (g, off) = r_u16(data, off);
      out.add(g);
    }
    return out; // array of named groups
  };

  /* -------------------------- SIGNATURE_ALGORITHMS (13) -------------------------- */
  exts['SIGNATURE_ALGORITHMS']!.encode = (value) {
    var algs =
        ((value is Uint8List || value is List<int>)
                ? value
                : [0x0403, 0x0804, 0x0401])
            as List<int>;

    var body = Uint8List(2 + algs.length * 2);
    var off = 0;

    off = w_u16(body, off, algs.length * 2);
    for (var i = 0; i < algs.length; i++) {
      off = w_u16(body, off, algs[i]);
    }
    return body;
  };

  exts['SIGNATURE_ALGORITHMS']!.decode = (data) {
    var off = 0;
    var n;
    (n, off) = r_u16(data, off);

    var out = [];
    for (var i = 0; i < n; i += 2) {
      var a;
      (a, off) = r_u16(data, off);
      out.add(a);
    }
    return out; // array of sigalgs (u16)
  };

  /* ------------------------ PSK_KEY_EXCHANGE_MODES (45) ------------------------ */
  exts['PSK_KEY_EXCHANGE_MODES']!.encode = (value) {
    var modes =
        ((value is Uint8List || value is List<int>) ? value : [1])
            as List<int>; // 0=psk_ke, 1=psk_dhe_ke

    var body = Uint8List(1 + modes.length);
    var off = 0;

    off = w_u8(body, off, modes.length);
    for (var i = 0; i < modes.length; i++) {
      off = w_u8(body, off, modes[i]);
    }
    return body;
  };

  exts['PSK_KEY_EXCHANGE_MODES']!.decode = (data) {
    var off = 0;
    var n;
    (n, off) = r_u8(data, off);

    var out = [];
    for (var i = 0; i < n; i++) {
      var m;
      (m, off) = r_u8(data, off);
      out.add(m);
    }
    return out; // array of modes (u8)
  };

  /* --------------------------------- KEY_SHARE (51) -------------------------------- */
  exts['KEY_SHARE']!.encode = (value) {
    // ServerHello form: { group:number, key_exchange:Uint8Array }
    if (value != null && value.group is num && value.key_exchange) {
      var ke = toU8(value.key_exchange);

      var out = Uint8List(2 + 2 + ke.length);
      var off = 0;

      off = w_u16(out, off, value.group);
      off = w_u16(out, off, ke.length);
      off = w_bytes(out, off, ke);

      return out;
    }

    // ClientHello form: [{ group:number, key_exchange:Uint8Array }, ...]
    var list = (value is Uint8List || value is List<int>) ? value : [];

    List<Uint8List> parts = [];
    for (var i = 0; i < list.length; i++) {
      var e = list[i];
      var ke2 = toU8(e.key_exchange ?? Uint8List(0));

      var ent = Uint8List(2 + 2 + ke2.length);
      var o2 = 0;

      o2 = w_u16(ent, o2, e.group >>> 0);
      o2 = w_u16(ent, o2, ke2.length);
      o2 = w_bytes(ent, o2, ke2);

      parts.add(ent);
    }

    return veclen(2, concatUint8Arrays(parts));
  };

  exts['KEY_SHARE']!.decode = (data) {
    // Try ServerHello form: group(2) + len(2) + key
    if (data.length >= 4) {
      var g, off = 0;
      (g, off) = r_u16(data, off);

      var l;
      (l, off) = r_u16(data, off);

      if (4 + l == data.length) {
        var ke;
        (ke, off) = r_bytes(data, off, l);
        // Two fields required → return object
        return (group: g, key_exchange: ke);
      }
    }

    // ClientHello form: vector<2> of KeyShareEntry
    var off2 = 0;
    var listBytes;
    (listBytes, off2) = r_u16(data, off2);

    var end = off2 + listBytes;
    var out = [];

    while (off2 < end) {
      var g2;
      (g2, off2) = r_u16(data, off2);

      var l2;
      (l2, off2) = r_u16(data, off2);

      var ke2;
      (ke2, off2) = r_bytes(data, off2, l2);

      out.add((group: g2, key_exchange: ke2));
    }

    return out; // array of entries
  };

  /* ------------------------------------ ALPN (16) ----------------------------------- */
  exts['ALPN']!.encode = (value) {
    var list = (value is Uint8List || value is List<int>) ? value : [];

    var total = 2; // vec16 length
    var items = [];

    for (var i = 0; i < list.length; i++) {
      var p = toU8(list[i]);
      items.add(p);
      total += 1 + p.length;
    }

    var out = Uint8List(total);
    var off = 0;

    off = w_u16(out, off, total - 2);
    for (var j = 0; j < items.length; j++) {
      off = w_u8(out, off, items[j].length);
      off = w_bytes(out, off, items[j]);
    }

    return out;
  };

  exts['ALPN']!.decode = (data) {
    var off = 0;
    var n;
    (n, off) = r_u16(data, off);

    var end = off + n;
    var out = [];

    while (off < end) {
      var l;
      (l, off) = r_u8(data, off);

      var v;
      (v, off) = r_bytes(data, off, l);

      out.add(utf8.decode(v));
    }

    return out; // array of protocol strings
  };

  /* ----------------------------- RENEGOTIATION_INFO (FF01) ----------------------------- */
  exts['RENEGOTIATION_INFO']!.encode = (value) {
    // value is Uint8Array of renegotiated_connection data
    var rb = toU8(value ?? Uint8List(0));
    return veclen(1, rb);
  };

  exts['RENEGOTIATION_INFO']!.decode = (data) {
    var off = 0;
    var v;
    (v, off) = readVec(data, off, 1);
    return v; // return raw bytes (Uint8Array)
  };
}

/* ============================= Extensions helpers ============================= */
String ext_name_by_code(code) {
  // best-effort pretty name
  for (var k in TLS_EXT.values) {
    if ((k.value >> 0) == (code >> 0)) return k.name;
  }
  return 'EXT_ ${code}';
}
