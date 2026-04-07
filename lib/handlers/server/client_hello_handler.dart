/* ================================ Hello I/O ================================ */
import 'dart:math';
import 'dart:typed_data';

import '../../tls_session_class.dart';
import '../../utils.dart';
import '../extensions/extensions.dart';
import '../handshake/client_hello.dart';
import '../handshake/server_hello.dart';
import '../message_types.dart';
// import '../../wire.dart';

Uint8List build_hello(kind, params) {
  params = params ?? {};

  var legacy_version = TLS_VERSION.TLS1_2; // even for TLS1.3 legacy fields

  var sid = toU8(params.session_id ?? "");
  if (sid.length > 32) sid = sid.sublist(0, 32);

  var extsBuf = build_extensions(params.extensions ?? []);

  if (kind == 'client') {
    var cs =
        (params.cipher_suites ?? [0x1301, 0x1302, 0x1303, 0xC02F, 0xC02B])
            as List<int>;

    var csBlock = Uint8List(2 + cs.length * 2);
    var o = 0;
    o = w_u16(csBlock, o, cs.length * 2);
    for (var i = 0; i < cs.length; i++) {
      o = w_u16(csBlock, o, cs[i]);
    }

    var comp =
        (params.legacy_compression ?? [0])
            as List<int>; // for TLS1.3 must be [0]
    var compBlock = Uint8List(1 + comp.length);
    var oc = 0;
    oc = w_u8(compBlock, oc, comp.length);
    for (var j = 0; j < comp.length; j++) {
      oc = w_u8(compBlock, oc, comp[j]);
    }

    var out = Uint8List(
      2 +
          32 +
          1 +
          sid.length +
          csBlock.length +
          compBlock.length +
          extsBuf.length,
    );

    var off = 0;
    off = w_u16(out, off, legacy_version);
    off = w_bytes(out, off, params.random);
    off = w_u8(out, off, sid.length);
    off = w_bytes(out, off, sid);
    off = w_bytes(out, off, csBlock);
    off = w_bytes(out, off, compBlock);
    off = w_bytes(out, off, extsBuf);

    return out;
  }

  if (kind == 'server') {
    var cipher_suite = (params.cipher_suite is num)
        ? params.cipher_suite
        : 0x1301;

    var out2 = Uint8List(2 + 32 + 1 + sid.length + 2 + 1 + extsBuf.length);
    var off2 = 0;

    off2 = w_u16(out2, off2, legacy_version);
    off2 = w_bytes(out2, off2, params.random);
    off2 = w_u8(out2, off2, sid.length);
    off2 = w_bytes(out2, off2, sid);
    off2 = w_u16(out2, off2, cipher_suite);
    off2 = w_u8(out2, off2, 0); // compression method = 0
    off2 = w_bytes(out2, off2, extsBuf);

    return out2;
  }

  throw Exception('build_hello: kind must be "client" or "server"');
}

// (local var) build_message_params: {
//     type: string;
//     version: never;
//     random: null;
//     session_id: null;
//     cipher_suite: null;
//     extensions: {
//         type: string;
//         value: {
//             group: null;
//             key_exchange: null;
//         };
//     }[];
// } | {
//     type: string;
//     version: never;
//     random: null;
//     session_id: Uint8Array<ArrayBuffer>;
//     cipher_suite: null;
//     extensions: ({
//         type: string;
//         value: Uint8Array<ArrayBuffer>;
//         data?: undefined;
//     } | {
//         type: number;
//         data: Uint8Array<ArrayBuffer>;
//         value?: undefined;
//     })[];
// }

Uint8List build_server_hello(ClientHello params){
  var version = params.version_hint.value;
  BytesBuilder body =BytesBuilder();

  // 1) legacy_version
  var legacy_version = (version == 0x0304) ? 0x0303 : 0x0303;
  body.add([(legacy_version>>8)&0xFF, legacy_version&0xFF]);

  // 2) random
   body.add(List.generate(32, (_)=>Random.secure().nextInt(255)));
  // for (var i=0;i<rnd.length;i++) body.a(rnd[i]);

  // 3) legacy_session_id
  var sid = params.session_id.isNotEmpty? params.session_id : Uint8List(0);
  body.addByte(sid.length & 0xFF);
  for (var i=0;i<sid.length;i++) body.addByte(sid[i]);

  // 4) cipher_suite
  var cs = params.cipher_suites.firstWhere((test)=>test==0x0304);
  body.add([(cs>>8)&0xFF, cs&0xFF]);

  // 5) legacy_compression_method
  body.addByte(params.legacy_compression.first);

  // 6) extensions
  var exts = [];

  if (version == 0x0304){
    // --- TLS 1.3 extensions ---

    // supported_versions (0x002b)
    exts.add([0x00,0x2b]); // type
    exts.add([0x00,0x02]); // len=2
    exts.add([0x03,0x04]); // TLS1.3

    // key_share (0x0033)
    var group = params.selected_group|0;
    var pub   = params.server_key_share;
    var ks = [];
    ks.push((group>>>8)&0xFF, group&0xFF);
    ks.push((pub.length>>>8)&0xFF, pub.length&0xFF);
    for (var j=0;j<pub.length;j++) ks.push(pub[j]);

    exts.push(0x00,0x33); // type
    exts.push((ks.length>>>8)&0xFF, ks.length&0xFF);
    for (var j=0;j<ks.length;j++) exts.push(ks[j]);

  } else if (version === 0x0303){
    // --- TLS 1.2 extensions (אופציונלי) ---

    if (params.secure_renegotiation){
      // renegotiation_info (0xFF01), length=1, value=0x00
      exts.push(0xFF,0x01);
      exts.push(0x00,0x01);
      exts.push(0x00);
    }
    if (params.extended_master_secret){
      // extended_master_secret (0x0017), empty
      exts.push(0x00,0x17);
      exts.push(0x00,0x00);
    }
  }

  if (params.extra_extensions && params.extra_extensions.length){
    for (var e=0;e<params.extra_extensions.length;e++){
      var ext = params.extra_extensions[e];
      var et = ext.type|0;
      var ed = ext.data;
      exts.push((et>>>8)&0xFF, et&0xFF);
      exts.push((ed.length>>>8)&0xFF, ed.length&0xFF);
      for (var k=0;k<ed.length;k++) exts.push(ed[k]);
    }
  }

  body.push((exts.length>>>8)&0xFF, exts.length&0xFF);
  for (var i=0;i<exts.length;i++) body.push(exts[i]);

  // 7) Handshake header (ServerHello=2)
  var sh = [];
  sh.push(2); // msg_type=server_hello
  var len = body.length;
  sh.push((len>>>16)&0xFF, (len>>>8)&0xFF, len&0xFF);
  for (var i=0;i<body.length;i++) sh.push(body[i]);

  return new Uint8Array(sh);
}

HandShakeMessageType parse_message(Uint8List buf) {
  var off = 0;
  var t;
  (t, off) = r_u8(buf, off);

  var l;

  // print("buffer length: ${buf.length}, offset: $off, t: $t");
  (l, off) = r_u24(buf, off);

  // print("buffer length: ${buf.length}, offset: $off, l: $l");

  Uint8List b;
  (b, off) = r_bytes(buf, off, l);

  return HandShakeMessageType(TLS_MESSAGE_TYPE.fromBytes(t), b);
}

ClientHello parse_client_hello(TLS_MESSAGE_TYPE hsType, Uint8List body) {
  var isClient = (hsType == TLS_MESSAGE_TYPE.CLIENT_HELLO);

  var off = 0;

  int legacy_version;
  (legacy_version, off) = r_u16(body, off);

  Uint8List random;
  (random, off) = r_bytes(body, off, 32);

  int sidLen;
  (sidLen, off) = r_u8(body, off);

  Uint8List session_id;
  (session_id, off) = r_bytes(body, off, sidLen);

  if (isClient) {
    var csLen;
    (csLen, off) = r_u16(body, off);

    var csEnd = off + csLen;
    List<int> cipher_suites = [];

    while (off < csEnd) {
      var cs;
      (cs, off) = r_u16(body, off);
      cipher_suites.add(cs);
    }

    var compLen;
    (compLen, off) = r_u8(body, off);

    List<int> legacy_compression = [];
    for (var i = 0; i < compLen; i++) {
      var c;
      (c, off) = r_u8(body, off);
      legacy_compression.add(c);
    }

    Uint8List extRaw = (body.length > off) ? body.sublist(off) : Uint8List(0);
    List<TlsExtension> extensions = extRaw.isNotEmpty
        ? parse_extensions(extRaw)
        : [];

    // version hint: if supported_versions includes TLS1.3, prefer it
    TLS_VERSION ver = TLS_VERSION.fromBytes(legacy_version);

    for (var k = 0; k < extensions.length; k++) {
      var e = extensions[k];
      if (e.type == TLS_EXT.SUPPORTED_VERSIONS &&
          (e.value is Uint8List || e.value is List<int>)) {
        for (var t = 0; t < e.value.length; t++) {
          if (e.value[t] == TLS_VERSION.TLS1_3) {
            ver = TLS_VERSION.TLS1_3;
            break;
          }
        }
      }
    }

    return ClientHello(
      message: TLS_MESSAGE_TYPE.CLIENT_HELLO,
      legacy_version: legacy_version,
      version_hint: ver,
      random: random,
      session_id: session_id,
      cipher_suites: cipher_suites,
      legacy_compression: legacy_compression,
      extensions: extensions,
      body: body,
    );
  }

  throw UnimplementedError();

  // ServerHello
  // var cipher_suite;
  // (cipher_suite, off) = r_u16(body, off);

  // var comp;
  // (comp, off) = r_u8(body, off);

  // var extRaw2 = (body.length > off) ? body.sublist(off) : Uint8List(0);
  // var extensions2 = extRaw2.isNotEmpty
  //     ? parse_extensions(extRaw2)
  //     : Uint8List(0);

  // var ver2 = legacy_version;
  // for (var z = 0; z < extensions2.length; z++) {
  //   var ex = extensions2[z];
  //   if (ex.type == TLS_EXT.SUPPORTED_VERSIONS && ex.value is num) {
  //     ver2 = ex.value; // selected version
  //   }
  // }

  // return ClientHello(
  //   message: 'server_hello',
  //   legacy_version: legacy_version,
  //   version: ver2,
  //   random: random,
  //   session_id: session_id,
  //   cipher_suite: cipher_suite,
  //   legacy_compression: comp,
  //   extensions: extensions2,
  // );
}

ServerHello parse_server_hello(TLS_MESSAGE_TYPE hsType, Uint8List body) {
  var isClient = (hsType == TLS_MESSAGE_TYPE.CLIENT_HELLO);

  var off = 0;

  int legacy_version;
  (legacy_version, off) = r_u16(body, off);

  Uint8List random;
  (random, off) = r_bytes(body, off, 32);

  int sidLen;
  (sidLen, off) = r_u8(body, off);

  Uint8List session_id;
  (session_id, off) = r_bytes(body, off, sidLen);

  // ServerHello
  var cipher_suite;
  (cipher_suite, off) = r_u16(body, off);

  var comp;
  (comp, off) = r_u8(body, off);

  var extRaw2 = (body.length > off) ? body.sublist(off) : Uint8List(0);
  List<TlsExtension> extensions2 = extRaw2.isNotEmpty
      ? parse_extensions(extRaw2)
      : [];

  TLS_VERSION ver2 = TLS_VERSION.fromBytes(legacy_version);

  for (var k = 0; k < extensions2.length; k++) {
    var e = extensions2[k];
    if (e.type == TLS_EXT.SUPPORTED_VERSIONS &&
        (e.value is Uint8List || e.value is List<int>)) {
      for (var t = 0; t < e.value.length; t++) {
        if (e.value[t] == TLS_VERSION.TLS1_3) {
          ver2 = TLS_VERSION.TLS1_3;
          break;
        }
      }
    }
  }

  return ServerHello(
    message: TLS_MESSAGE_TYPE.SERVER_HELLO,
    legacy_version: legacy_version,
    version: ver2,
    random: random,
    session_id: session_id,
    cipher_suite: cipher_suite,
    legacy_compression: comp,
    extensions: extensions2,
    body: body,
  );
}

TlsSession normalizeClientHello(dynamic hello) {
  var isClient = (hello.message == TLS_MESSAGE_TYPE.CLIENT_HELLO);
  // ClientHello hello;
  hello = hello as ClientHello;
  TlsSession out = TlsSession(
    // Basics
    message: hello.message, // 'client_hello' | 'server_hello'
    legacy_version: hello.legacy_version, // 0x0303
    version: hello.legacy_version ?? hello.version_hint ?? null,
    random: hello.random ?? null, // Uint8Array(32)
    session_id: hello.session_id ?? null, // Uint8Array
    // Negotiation fields
    cipher_suites: hello.cipher_suites ?? null, // ClientHello array
    // cipher_suite: hello.cipher_suite ?? null, // ServerHello selected
    legacy_compression: hello.legacy_compression ?? null,

    // Commonly used extensions (flattened)
    sni: null, // string
    alpn: null, // string[]
    key_shares:
        null, // Client: array of {group, key_exchange}; Server: {group, key_exchange}
    supported_versions: null, // Client: number[]; Server: number
    signature_algorithms: null, // number[]
    supported_groups: null, // number[]
    // TLS 1.2 / misc
    renegotiation_info: null, // Uint8Array
    status_request: null, // raw/decoded if available
    max_fragment_length: null, // number or enum
    signature_algorithms_cert: null, // number[]
    certificate_authorities: null, // raw/decoded if available
    sct: null, // SignedCertificateTimestamp list (raw/decoded)
    heartbeat: null, // heartbeat mode
    use_srtp: null, // SRTP profiles
    // TLS 1.3 specific
    cookie: null, // Uint8Array
    early_data: null, // true/params if present
    psk_key_exchange_modes: null, // number[]
    // Raw list of extensions
    extensions: hello.extensions ?? [],

    // Bucket for anything unmapped
    unknown: [],
  );

  if (hello.extensions.isEmpty) {
    return out;
  }

  for (var i = 0; i < hello.extensions.length; i++) {
    TlsExtension e = hello.extensions[i];
    var val = (e.value != null && e.value != null) ? e.value : null;

    switch (e.name) {
      case 'SERVER_NAME':
        out.sni = val; // string
        break;

      case 'ALPN':
        out.alpn = val; // string[]
        break;

      case 'KEY_SHARE':
        out.key_shares = val; // client: array, server: object
        break;

      case 'SUPPORTED_VERSIONS':
        out.supported_versions = val; // array or number
        break;

      case 'SIGNATURE_ALGORITHMS':
        out.signature_algorithms = val; // number[]
        break;

      case 'SUPPORTED_GROUPS':
        out.supported_groups = val; // number[]
        break;

      // ---- TLS 1.2 & misc ----
      case 'RENEGOTIATION_INFO':
        out.renegotiation_info = val; // Uint8Array
        break;

      case 'STATUS_REQUEST':
        out.status_request = val; // currently raw unless a decoder is added
        break;

      case 'MAX_FRAGMENT_LENGTH':
        out.max_fragment_length =
            val; // number/enum (decoder not implemented yet)
        break;

      case 'SIGNATURE_ALGORITHMS_CERT':
        out.signature_algorithms_cert = val; // number[]
        break;

      case 'CERTIFICATE_AUTHORITIES':
        out.certificate_authorities = val; // raw list unless decoder added
        break;

      case 'SCT':
        out.sct = val; // raw/decoded SCT list
        break;

      case 'HEARTBEAT':
        out.heartbeat = val; // heartbeat mode
        break;

      case 'USE_SRTP':
        out.use_srtp = val; // SRTP params
        break;

      // ---- TLS 1.3 ----
      case 'COOKIE':
        out.cookie = val; // Uint8Array
        break;

      case 'EARLY_DATA':
        out.early_data = (val == null)
            ? true
            : val; // presence indicates support
        break;

      case 'PSK_KEY_EXCHANGE_MODES':
        out.psk_key_exchange_modes = val; // number[]
        break;

      default:
        out.unknown.add(e);
    }
  }

  // --- פוסט-פרוסס: השלמות ל-1.2 כשאין ext SUPPORTED_VERSIONS ---
  if (out.supported_versions == null) {
    if (out.message == 'client_hello' && out.legacy_version is num) {
      // ב-1.2 הקליינט לא שולח ext, נשתול מערך עם הגרסה ה"מורשת" (לרוב 0x0303)
      out.supported_versions = [out.legacy_version | 0];
    } else if (out.message == 'server_hello' && out.legacy_version is num) {
      // בסרבר: הגרסה הנבחרת נמצאת בשדה הישן; שמור גם ב-version
      if (out.version == null) out.version = out.legacy_version | 0;
      out.supported_versions = out.version; // שמור סכימה: בסרבר זה "number"
    }
  }

  // גם אם אין KEY_SHARE ב-1.2, נרצה אינדיקציה ריקה במקום null (קוד downstream נקי יותר)
  if (out.key_shares == null && out.message == 'client_hello') {
    out.key_shares = []; // ב-1.2 ה-ECDHE יבוא ב-ServerKeyExchange, לא כאן
  }

  return out;
}

TlsSession normalizeServerHello(dynamic hello) {
  var isClient = (hello.message == TLS_MESSAGE_TYPE.CLIENT_HELLO);
  // ClientHello hello;
  hello = hello as ServerHello;
  TlsSession out = TlsSession(
    // Basics
    message: hello.message, // 'client_hello' | 'server_hello'
    legacy_version: hello.legacy_version, // 0x0303
    version: hello.version ?? null,
    random: hello.random ?? null, // Uint8Array(32)
    session_id: hello.session_id ?? null, // Uint8Array
    // Negotiation fields
    // cipher_suites: hello.cipher_suites ?? null, // ClientHello array
    cipher_suite: hello.cipher_suite ?? null, // ServerHello selected
    legacy_compression: hello.legacy_compression ?? null,

    // Commonly used extensions (flattened)
    sni: null, // string
    alpn: null, // string[]
    key_shares:
        null, // Client: array of {group, key_exchange}; Server: {group, key_exchange}
    supported_versions: null, // Client: number[]; Server: number
    signature_algorithms: null, // number[]
    supported_groups: null, // number[]
    // TLS 1.2 / misc
    renegotiation_info: null, // Uint8Array
    status_request: null, // raw/decoded if available
    max_fragment_length: null, // number or enum
    signature_algorithms_cert: null, // number[]
    certificate_authorities: null, // raw/decoded if available
    sct: null, // SignedCertificateTimestamp list (raw/decoded)
    heartbeat: null, // heartbeat mode
    use_srtp: null, // SRTP profiles
    // TLS 1.3 specific
    cookie: null, // Uint8Array
    early_data: null, // true/params if present
    psk_key_exchange_modes: null, // number[]
    // Raw list of extensions
    extensions: hello.extensions ?? [],

    // Bucket for anything unmapped
    unknown: [],
  );

  if (hello.extensions.isEmpty) {
    return out;
  }

  for (var i = 0; i < hello.extensions.length; i++) {
    var e = hello.extensions[i];
    var val = (e.value != null && e.value != null) ? e.value : null;

    switch (e.name) {
      case 'SERVER_NAME':
        out.sni = val; // string
        break;

      case 'ALPN':
        out.alpn = val; // string[]
        break;

      case 'KEY_SHARE':
        out.key_shares = val; // client: array, server: object
        break;

      case 'SUPPORTED_VERSIONS':
        out.supported_versions = val; // array or number
        break;

      case 'SIGNATURE_ALGORITHMS':
        out.signature_algorithms = val; // number[]
        break;

      case 'SUPPORTED_GROUPS':
        out.supported_groups = val; // number[]
        break;

      // ---- TLS 1.2 & misc ----
      case 'RENEGOTIATION_INFO':
        out.renegotiation_info = val; // Uint8Array
        break;

      case 'STATUS_REQUEST':
        out.status_request = val; // currently raw unless a decoder is added
        break;

      case 'MAX_FRAGMENT_LENGTH':
        out.max_fragment_length =
            val; // number/enum (decoder not implemented yet)
        break;

      case 'SIGNATURE_ALGORITHMS_CERT':
        out.signature_algorithms_cert = val; // number[]
        break;

      case 'CERTIFICATE_AUTHORITIES':
        out.certificate_authorities = val; // raw list unless decoder added
        break;

      case 'SCT':
        out.sct = val; // raw/decoded SCT list
        break;

      case 'HEARTBEAT':
        out.heartbeat = val; // heartbeat mode
        break;

      case 'USE_SRTP':
        out.use_srtp = val; // SRTP params
        break;

      // ---- TLS 1.3 ----
      case 'COOKIE':
        out.cookie = val; // Uint8Array
        break;

      case 'EARLY_DATA':
        out.early_data = (val == null)
            ? true
            : val; // presence indicates support
        break;

      case 'PSK_KEY_EXCHANGE_MODES':
        out.psk_key_exchange_modes = val; // number[]
        break;

      default:
        out.unknown.push(e);
    }
  }

  // --- פוסט-פרוסס: השלמות ל-1.2 כשאין ext SUPPORTED_VERSIONS ---
  if (out.supported_versions == null) {
    if (out.message == 'client_hello' && out.legacy_version is num) {
      // ב-1.2 הקליינט לא שולח ext, נשתול מערך עם הגרסה ה"מורשת" (לרוב 0x0303)
      out.supported_versions = [out.legacy_version | 0];
    } else if (out.message == 'server_hello' && out.legacy_version is num) {
      // בסרבר: הגרסה הנבחרת נמצאת בשדה הישן; שמור גם ב-version
      if (out.version == null) out.version = out.legacy_version | 0;
      out.supported_versions = out.version; // שמור סכימה: בסרבר זה "number"
    }
  }

  // גם אם אין KEY_SHARE ב-1.2, נרצה אינדיקציה ריקה במקום null (קוד downstream נקי יותר)
  if (out.key_shares == null && out.message == 'client_hello') {
    out.key_shares = []; // ב-1.2 ה-ECDHE יבוא ב-ServerKeyExchange, לא כאן
  }

  return out;
}
