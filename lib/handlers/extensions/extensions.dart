import 'dart:convert';
import 'dart:typed_data';

import '../../utils.dart';
import 'extension2.dart';

enum TLS_EXT {
  SERVER_NAME(0),
  MAX_FRAGMENT_LENGTH(1),
  STATUS_REQUEST(5),
  SUPPORTED_GROUPS(10),
  SIGNATURE_ALGORITHMS(13),
  USE_SRTP(14),
  HEARTBEAT(15),
  ALPN(16),
  SCT(18),
  CLIENT_CERT_TYPE(19),
  SERVER_CERT_TYPE(20),
  PADDING(21),
  PRE_SHARED_KEY(41),
  EARLY_DATA(42),
  SUPPORTED_VERSIONS(43),
  COOKIE(44),
  PSK_KEY_EXCHANGE_MODES(45),
  CERTIFICATE_AUTHORITIES(47),
  OID_FILTERS(48),
  POST_HANDSHAKE_AUTH(49),
  SIGNATURE_ALGORITHMS_CERT(50),
  KEY_SHARE(51),
  RENEGOTIATION_INFO(0xFF01),
  UNKNOWN(655291);

  const TLS_EXT(this.value);

  final int value;

  // static TlsExtension decode(TLS_EXT t, Uint8List data) {
  //   switch (t) {
  //     case SERVER_NAME:
  //       {
  //         return TlsExtensionSERVER_NAME.decode(data);
  //         // throw UnimplementedError();
  //       }

  //     case SUPPORTED_VERSIONS:
  //       {
  //         throw UnimplementedError();
  //       }
  //     default:
  //       throw UnimplementedError(t.toString());
  //   }
  // }

  factory TLS_EXT.fromInt(int key) {
    return values.firstWhere(
      (element) => element.value == key,
      orElse: () => UNKNOWN,
    );
  }
}

class TlsExtension {
  Uint8List data;

  TLS_EXT type;

  String name;

  var value;

  TlsExtension({
    required this.data,
    required this.type,
    required this.name,
    this.value,
  });

  Uint8List encode() {
    throw UnimplementedError();
  }

  // Uint8List encode() {
  //   throw UnimplementedError("UnimplementedError");
  // }

  // factory TlsExtension.decode(Uint8List data) {
  //   throw UnimplementedError("UnimplementedError");
  // }
}

// class TlsExtensionSERVER_NAME extends TlsExtension {
//   @override
//   Uint8List encode() {
//     // throw UnimplementedError("UnimplementedError");

//     var host = toU8(data);

//     // one name: type(1)=0, len(2), bytes
//     var inner = Uint8List(1 + 2 + host.length);
//     var off = 0;

//     off = w_u8(inner, off, 0);
//     off = w_u16(inner, off, host.length);
//     off = w_bytes(inner, off, host);

//     // ServerNameList is vector<2>
//     return veclen(2, inner);
//   }

//   @override
//   factory TlsExtensionSERVER_NAME.decode(Uint8List data) {
//     var off = 0;
//     var list;
//     (list, off) = readVec(data, off, 2);

//     var off2 = 0;
//     var host = "";

//     while (off2 < list.length) {
//       var typ;
//       (typ, off2) = r_u8(list, off2);

//       var l;
//       (l, off2) = r_u16(list, off2);

//       var v;
//       (v, off2) = r_bytes(list, off2, l);

//       if (typ == 0) {
//         host = utf8.decode(v);
//       }
//     }

//     // Return just the value (string), not {host: ...}
//     return TlsExtensionSERVER_NAME(utf8.encode(host), TLS_EXT.SERVER_NAME);
//   }

//   @override
//   Uint8List data;

//   @override
//   // TODO: implement type
//   TLS_EXT type;

//   TlsExtensionSERVER_NAME(this.data, this.type) : s;
// }

Uint8List build_extensions(List<TlsExtension> list) {
  // list items may be {type:number|string, value:any, data?:Uint8Array}
  if (list.isEmpty) {
    var e = Uint8List(2);
    w_u16(e, 0, 0);
    return e;
  }

  var parts = [];
  var total = 2; // vec16

  for (var i in list) {
    var t = i.type;

    // allow symbolic name e.g. 'SERVER_NAME'
    // if (t is ) {
    //   t = TLS_EXT[t];
    // }

    Uint8List payload;
    if (i.data.isEmpty) {
      payload = i.data;
    } else {
      // try registry
      // var regKey = ext_name_by_code(t);
      // var enc = exts[regKey] && exts[regKey].encode;
      payload = i.encode(); // enc ? enc(list[i].value) : Uint8List(0);
    }

    var rec = Uint8List(4 + payload.length);
    var off = 0;

    off = w_u16(rec, off, t.value >> 0);
    off = w_u16(rec, off, payload.length);
    off = w_bytes(rec, off, payload);

    parts.add(rec);
    total += rec.length;
  }

  var out = Uint8List(total);
  var off2 = 0;

  off2 = w_u16(out, off2, total - 2);

  for (var j = 0; j < parts.length; j++) {
    off2 = w_bytes(out, off2, parts[j]);
  }

  return out;
}

// List<TlsExtension> parse_extensions(Uint8List buf) {
//   var off = 0;
//   var n;
//   (n, off) = r_u16(buf, off);

//   var end = off + n;
//   List<TlsExtension> out = [];

//   while (off < end) {
//     int t;
//     (t, off) = r_u16(buf, off);

//     var l;
//     (l, off) = r_u16(buf, off);

//     var d;
//     (d, off) = r_bytes(buf, off, l);

//     final extension = TLS_EXT.decode(TLS_EXT.fromInt(t), d);
//     out.add(extension);

//     // var name = ext_name_by_code(t);
//     // var dec = exts[name] && exts[name].decode;
//     // var val = dec ? dec(d) : null;

//     // out.push(( type: t, name: name, data: d, value: val ));
//   }

//   return out;
// }

List<TlsExtension> parse_extensions(Uint8List buf) {
  var off = 0;
  var n;
  (n, off) = r_u16(buf, off);

  var end = off + n;
  List<TlsExtension> out = [];

  while (off < end) {
    int t;
    (t, off) = r_u16(buf, off);

    var l;
    (l, off) = r_u16(buf, off);

    var d;
    (d, off) = r_bytes(buf, off, l);

    var name = ext_name_by_code(t);
    print("Extension name: $name");
    var dec = (exts[name] != null && exts[name]!.decode != null)
        ? exts[name]!.decode
        : null;
    var val = dec != null ? dec(d) : null;

    out.add(
      TlsExtension(type: TLS_EXT.fromInt(t), name: name, data: d, value: val),
    );
  }

  return out;
}
