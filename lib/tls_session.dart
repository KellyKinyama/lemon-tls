import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:elliptic/elliptic.dart' as elliptic;
import 'package:hex/hex.dart';
import 'package:x25519/x25519.dart';

import 'cert_utils.dart';
import 'hash.dart';
import 'hkdf.dart';
// import { sha256, sha384 } from '@noble/hashes/sha2.js';

import 'tls_context_class.dart';
import 'tls_session_class.dart';
import 'x25519.dart';
// import { ed25519, x25519 } from '@noble/curves/ed25519.js';

// var nobleHashes = { hmac, hkdf, hkdf_extract, hkdf_expand, sha256 };

import 'crypto.dart';

import 'utils.dart';
import 'wire.dart' as wire;


import 'package:events_emitter/events_emitter.dart';

enum SIG {
  ECDSA_P256_SHA256(0x0403),
  ECDSA_P384_SHA384(0x0503),
  ECDSA_P521_SHA512(0x0603),
  RSA_PSS_SHA256(0x0804),
  RSA_PSS_SHA384(0x0805),
  RSA_PSS_SHA512(0x0806),
  ED25519(0x0807),
  ED448(0x0808);

  const SIG(this.value);
  final int value;
}

// import {
//   TLS_CIPHER_SUITES,
//   build_cert_verify_tbs,
//   get_handshake_finished,
//   derive_handshake_traffic_secrets,
//   derive_app_traffic_secrets
// } from './crypto.js';

// import {
//   concatUint8Arrays,
//   arraybufferEqual,
//   arraysEqual
// } from './utils.js';

//var wire = require('./wire');

/** מינימל-Emitter בסגנון שלך */
dynamic Emitter() {
  var listeners = {};
  return (
    on: (name, fn) {
      (listeners[name] = listeners[name] ?? []).add(fn);
    },
    emit: (name) {
      print("event: $name");
      // List args = this.call(arguments, 1);
      // var arr = listeners[name] ?? [];
      // for (var i=0;i<arr.length;i++){ try{ arr[i].apply(null, args); }catch(e){} }
    },
  );
}

dynamic arrOrDefault(a, d) {
  return (a && a.length) ? a.slice(0) : d.slice(0);
}

dynamic arrOrNull(a) {
  return (a && a.length) ? a.slice(0) : null;
}

TlsSession normalizeHello(hello) {
  TlsSession out = TlsSession(
    // Basics
    message: hello.message, // 'client_hello' | 'server_hello'
    legacy_version: hello.legacy_version, // 0x0303
    version: hello.version || hello.version_hint ?? null,
    random: hello.random ?? null, // Uint8Array(32)
    session_id: hello.session_id ?? null, // Uint8Array
    // Negotiation fields
    cipher_suites: hello.cipher_suites ?? null, // ClientHello array
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

  if (!hello.extensions) {
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

dynamic normalizeOptions(opts) {
  opts = opts ?? {};
  TlsOptions out = TlsOptions(
    minVersion: opts.minVersion ?? null,
    maxVersion: opts.maxVersion ?? null,

    cipherPreference: arrOrDefault(opts.cipherPreference, null),
    groupPreference: arrOrDefault(opts.groupPreference, null),
    sigAlgPreference: arrOrDefault(opts.sigAlgPreference, null),

    ALPNProtocols: arrOrNull(opts.ALPNProtocols),

    requestCert: !!opts.requestCert,
    rejectUnauthorized: !!opts.rejectUnauthorized,

    secureContext: opts.secureContext ?? null,
    isServer: !!opts.isServer,
  );

  // ודא min<=max
  if (out.minVersion > out.maxVersion) {
    var t = out.minVersion;
    out.minVersion = out.maxVersion;
    out.maxVersion = t;
  }

  return out;
}

dynamic set_context(options, TlsContext context, dynamic ev) {
  var has_changed = false;

  var fields = [
    'local_versions',
    'local_cipher_suites',
    'local_alpns',
    'local_groups',
    'local_signature_algorithms',
    'local_extensions',

    'remote_versions',
    'remote_cipher_suites',
    'remote_alpns',
    'remote_groups',
    'remote_signature_algorithms',
    'remote_extensions',
    'remote_key_shares',
    'remote_sni',
    'remote_session_id',
    'remote_random',

    'selected_version',
    'selected_cipher_suite',
    'selected_alpn',
    'selected_group',
    'selected_signature_algorithm',
    'selected_extensions',
    'selected_sni',
    'selected_session_id',

    'local_key_share_public',
    'local_key_share_private',
    'ecdhe_shared_secret',

    'server_handshake_traffic_secret',
    'client_handshake_traffic_secret',

    'server_app_traffic_secret',
    'client_app_traffic_secret',

    'local_cert_chain',
    'remote_cert_chain',

    'cert_private_key',

    'remote_finished_ok',
    'remote_finished',
    'expected_remote_finished',
  ];

  TlsContext prev = TlsContext();

  options = options as TlsOptions;

  if (options is Object) {
    if (options.local_versions.isNotEmpty) {
      if (arraysEqual(options.local_versions, context.local_versions) ==
          false) {
        prev.local_versions = context.local_versions;
        context.local_versions = options.local_versions;
        has_changed = true;
      }
    }

    if (options.local_cipher_suites.isNotEmpty) {
      if (arraysEqual(
            options.local_cipher_suites,
            context.local_cipher_suites,
          ) ==
          false) {
        prev.local_cipher_suites = context.local_cipher_suites;
        context.local_cipher_suites = options.local_cipher_suites;
        has_changed = true;
      }
    }

    if (options.local_alpns.isNotEmpty) {
      if (arraysEqual(options.local_alpns, context.local_alpns) == false) {
        prev.local_alpns = context.local_alpns;
        context.local_alpns = options.local_alpns;
        has_changed = true;
      }
    }

    if (options.local_groups.isNotEmpty) {
      if (arraysEqual(options.local_groups, context.local_groups) == false) {
        prev.local_groups = context.local_groups;
        context.local_groups = options.local_groups;
        has_changed = true;
      }
    }

    if (options.local_signature_algorithms.isNotEmpty) {
      if (arraysEqual(
            options.local_signature_algorithms,
            context.local_signature_algorithms,
          ) ==
          false) {
        prev.local_signature_algorithms = context.local_signature_algorithms;
        context.local_signature_algorithms = options.local_signature_algorithms;
        has_changed = true;
      }
    }

    if (options.local_extensions.isNotEmpty) {
      if (arraysEqual(options.local_extensions, context.local_extensions) ==
          false) {
        prev.local_extensions = context.local_extensions;
        context.local_extensions = options.local_extensions;
        has_changed = true;
      }
    }

    if (options.local_key_share_public.isNotEmpty) {
      if ((context.local_key_share_public == null &&
              options.local_key_share_public != null) ||
          !arraybufferEqual(
            options.local_key_share_public,
            context.local_key_share_public,
          )) {
        prev.local_key_share_public = context.local_key_share_public;
        context.local_key_share_public = options.local_key_share_public;
        has_changed = true;
      }
    }

    if (options.local_key_share_private.isNotEmpty) {
      if ((context.local_key_share_private == null &&
              options.local_key_share_private != null) ||
          !arraybufferEqual(
            options.local_key_share_private,
            context.local_key_share_private.buffer,
          )) {
        prev.local_key_share_private = context.local_key_share_private;
        context.local_key_share_private = options.local_key_share_private;
        has_changed = true;
      }
    }

    if (options.remote_versions) {
      if (arraysEqual(options.remote_versions, context.remote_versions) ==
          false) {
        prev.remote_versions = context.remote_versions;
        context.remote_versions = options.remote_versions;
        has_changed = true;
      }
    }

    if (options.remote_cipher_suites) {
      if (arraysEqual(
            options.remote_cipher_suites,
            context.remote_cipher_suites,
          ) ==
          false) {
        prev.remote_cipher_suites = context.remote_cipher_suites;
        context.remote_cipher_suites = options.remote_cipher_suites;
        has_changed = true;
      }
    }

    if (options.remote_alpns) {
      if (arraysEqual(options.remote_alpns, context.remote_alpns) == false) {
        prev.remote_alpns = context.remote_alpns;
        context.remote_alpns = options.remote_alpns;
        has_changed = true;
      }
    }

    if (options.remote_groups) {
      if (arraysEqual(options.remote_groups, context.remote_groups) == false) {
        prev.remote_groups = context.remote_groups;
        context.remote_groups = options.remote_groups;
        has_changed = true;
      }
    }

    if (options.remote_signature_algorithms) {
      if (arraysEqual(
            options.remote_signature_algorithms,
            context.remote_signature_algorithms,
          ) ==
          false) {
        prev.remote_signature_algorithms = context.remote_signature_algorithms;
        context.remote_signature_algorithms =
            options.remote_signature_algorithms;
        has_changed = true;
      }
    }

    if (options.remote_extensions) {
      if (arraysEqual(options.remote_extensions, context.remote_extensions) ==
          false) {
        prev.remote_extensions = context.remote_extensions;
        context.remote_extensions = options.remote_extensions;
        has_changed = true;
      }
    }

    if (options.remote_key_shares) {
      if (arraysEqual(options.remote_key_shares, context.remote_key_shares) ==
          false) {
        prev.remote_key_shares = context.remote_key_shares;
        context.remote_key_shares = options.remote_key_shares;
        has_changed = true;
      }
    }

    if (options.remote_sni) {
      if (options.remote_sni != context.remote_sni) {
        prev.remote_sni = context.remote_sni;
        context.remote_sni = options.remote_sni;
        has_changed = true;
      }
    }

    if (options.remote_session_id) {
      if ((context.remote_session_id == null &&
              options.remote_session_id != null) ||
          !arraybufferEqual(
            options.remote_session_id.buffer,
            context.remote_session_id.buffer,
          )) {
        prev.remote_session_id = context.remote_session_id;
        context.remote_session_id = options.remote_session_id;
        has_changed = true;
      }
    }

    if (options.remote_random) {
      if ((context.remote_random == null && options.remote_random != null) ||
          !arraybufferEqual(
            options.remote_random.buffer,
            context.remote_random.buffer,
          )) {
        prev.remote_random = context.remote_random;
        context.remote_random = options.remote_random;
        has_changed = true;
      }
    }

    if (options.selected_version) {
      if (options.selected_version != context.selected_version) {
        prev.selected_version = context.selected_version;
        context.selected_version = options.selected_version;
        has_changed = true;
      }
    }

    if (options.selected_cipher_suite) {
      if (options.selected_cipher_suite != context.selected_cipher_suite) {
        prev.selected_cipher_suite = context.selected_cipher_suite;
        context.selected_cipher_suite = options.selected_cipher_suite;
        has_changed = true;
      }
    }

    if (options.selected_alpn) {
      if (options.selected_alpn != context.selected_alpn) {
        prev.selected_alpn = context.selected_alpn;
        context.selected_alpn = options.selected_alpn;
        has_changed = true;
      }
    }

    if (options.selected_group) {
      if (options.selected_group != context.selected_group) {
        prev.selected_group = context.selected_group;
        context.selected_group = options.selected_group;
        has_changed = true;
      }
    }

    if (options.selected_signature_algorithm) {
      if (options.selected_signature_algorithm !=
          context.selected_signature_algorithm) {
        prev.selected_signature_algorithm =
            context.selected_signature_algorithm;
        context.selected_signature_algorithm =
            options.selected_signature_algorithm;
        has_changed = true;
      }
    }

    if (options.selected_extensions) {
      if (arraysEqual(
            options.selected_extensions,
            context.selected_extensions,
          ) ==
          false) {
        prev.selected_extensions = context.selected_extensions;
        context.selected_extensions = options.selected_extensions;
        has_changed = true;
      }
    }

    if (options.selected_sni) {
      if (options.selected_sni != context.selected_sni) {
        prev.selected_sni = context.selected_sni;
        context.selected_sni = options.selected_sni;
        has_changed = true;
      }
    }

    if (options.selected_session_id) {
      if ((context.selected_session_id == null &&
              options.selected_session_id != null) ||
          !arraybufferEqual(
            options.selected_session_id.buffer,
            context.selected_session_id.buffer,
          )) {
        prev.selected_session_id = context.selected_session_id;
        context.selected_session_id = options.selected_session_id;
        has_changed = true;
      }
    }

    if (options.ecdhe_shared_secret) {
      if (context.ecdhe_shared_secret == null &&
          options.ecdhe_shared_secret != null) {
        prev.ecdhe_shared_secret = context.ecdhe_shared_secret;
        context.ecdhe_shared_secret = options.ecdhe_shared_secret;
        has_changed = true;
      }
    }

    if (options.handshake_secret) {
      if (context.handshake_secret == null &&
          options.handshake_secret != null) {
        prev.handshake_secret = context.handshake_secret;
        context.handshake_secret = options.handshake_secret;
        has_changed = true;
      }
    }

    if (options.client_handshake_traffic_secret) {
      if (context.client_handshake_traffic_secret == null &&
          options.client_handshake_traffic_secret != null) {
        prev.client_handshake_traffic_secret =
            context.client_handshake_traffic_secret;
        context.client_handshake_traffic_secret =
            options.client_handshake_traffic_secret;
        has_changed = true;
      }
    }

    if (options
        .server_handshake_traffic_secret
        .server_handshake_traffic_secret) {
      if (context.server_handshake_traffic_secret == null &&
          options.server_handshake_traffic_secret != null) {
        prev.server_handshake_traffic_secret =
            context.server_handshake_traffic_secret;
        context.server_handshake_traffic_secret =
            options.server_handshake_traffic_secret;
        has_changed = true;
      }
    }

    if (options.client_app_traffic_secret.client_app_traffic_secret) {
      if (context.client_app_traffic_secret == null &&
          options.client_app_traffic_secret != null) {
        prev.client_app_traffic_secret = context.client_app_traffic_secret;
        context.client_app_traffic_secret = options.client_app_traffic_secret;
        has_changed = true;
      }
    }

    if (options.server_app_traffic_secret) {
      if (context.server_app_traffic_secret == null &&
          options.server_app_traffic_secret != null) {
        prev.server_app_traffic_secret = context.server_app_traffic_secret;
        context.server_app_traffic_secret = options.server_app_traffic_secret;
        has_changed = true;
      }
    }

    if (options.local_cert_chain) {
      if (context.local_cert_chain == null &&
          options.local_cert_chain != null) {
        prev.local_cert_chain = context.local_cert_chain;
        context.local_cert_chain = options.local_cert_chain;
        has_changed = true;
      }
    }

    if (options.cert_private_key) {
      if (context.cert_private_key == null &&
          options.cert_private_key != null) {
        prev.cert_private_key = context.cert_private_key;
        context.cert_private_key = options.cert_private_key;
        has_changed = true;
      }
    }

    if (options.expected_remote_finished) {
      if (context.expected_remote_finished == null &&
          options.expected_remote_finished != null) {
        prev.expected_remote_finished = context.expected_remote_finished;
        context.expected_remote_finished = options.expected_remote_finished;
        has_changed = true;
      }
    }

    if (options.remote_finished) {
      if (context.remote_finished == null && options.remote_finished != null) {
        prev.remote_finished = context.remote_finished;
        context.remote_finished = options.remote_finished;
        has_changed = true;
      }
    }

    if (options.remote_finished_ok) {
      if (context.remote_finished_ok != options.remote_finished_ok) {
        prev.remote_finished_ok = context.remote_finished_ok;
        context.remote_finished_ok = options.remote_finished_ok;
        has_changed = true;
      }
    }
  }

  if (has_changed == true) {
    TlsContext params_to_set = TlsContext();

    if (!arraysEqual(context.local_versions, prev.local_versions) ||
        !arraysEqual(context.remote_versions, prev.remote_versions) ||
        !arraysEqual(context.local_cipher_suites, prev.local_cipher_suites) ||
        !arraysEqual(context.remote_cipher_suites, prev.remote_cipher_suites) ||
        !arraysEqual(context.local_alpns, prev.local_alpns) ||
        !arraysEqual(context.remote_alpns, prev.remote_alpns) ||
        !arraysEqual(context.local_groups, prev.local_groups) ||
        !arraysEqual(context.remote_groups, prev.remote_groups) ||
        !arraysEqual(
          context.local_signature_algorithms,
          prev.local_signature_algorithms,
        ) ||
        !arraysEqual(
          context.remote_signature_algorithms,
          prev.remote_signature_algorithms,
        ) ||
        // הרחבות כלליות
        !arraysEqual(context.local_extensions, prev.local_extensions) ||
        //!arraysEqual(context.local_ee_extensions,         prev.local_ee_extensions)         || // TLS 1.3 EE
        //!arraysEqual(context.remote_extensions_all,       prev.remote_extensions_all)       ||
        //!arraysEqual(context.remote_extensions_unknown,   prev.remote_extensions_unknown)   ||
        // key_shares הם מערך של אובייקטים {group, pubkey} → deep compare
        !arraysEqual(context.remote_key_shares, prev.remote_key_shares) ||
        // session_id הוא Uint8Array → בדיקה ייעודית
        !arraybufferEqual(
          context.remote_session_id.buffer,
          prev.remote_session_id.buffer,
        ) ||
        // סניפים/מחרוזות פשוט
        context.remote_sni != prev.remote_sni ||
        1 == 1) {
      // == גרסה ==
      if (context.selected_version == null &&
          context.local_versions.length > 0 &&
          context.remote_versions.length > 0) {
        for (var i = 0; i < context.local_versions.length; i++) {
          var v = context.local_versions[i] | 0;
          for (var j = 0; j < context.remote_versions.length; j++) {
            if ((context.remote_versions[j] | 0) == v) {
              params_to_set.selected_version = v;
              break;
            }
          }
          if (params_to_set.selected_version &&
              params_to_set.selected_version != null)
            break;
        }

        if (params_to_set.selected_version ||
            params_to_set.selected_version == null) {
          //console.log('no match version...');
        }
      }

      // == Cipher Suite ==
      if (context.selected_cipher_suite == null &&
          context.local_cipher_suites.length > 0 &&
          context.remote_cipher_suites.length > 0) {
        for (var i2 = 0; i2 < context.local_cipher_suites.length; i2++) {
          var cs = context.local_cipher_suites[i2] | 0;
          for (var j2 = 0; j2 < context.remote_cipher_suites.length; j2++) {
            if ((context.remote_cipher_suites[j2] | 0) == cs) {
              params_to_set.selected_cipher_suite = cs;
              break;
            }
          }
          if (params_to_set.selected_cipher_suite == true &&
              params_to_set.selected_cipher_suite != null)
            break;
        }

        if (params_to_set.selected_cipher_suite ||
            params_to_set.selected_cipher_suite == null) {
          //console.log('no match cipher_suites...');
        }
      }

      // == ALPN ==
      if (context.selected_alpn == null &&
          context.local_alpns &&
          context.remote_alpns) {
        // עבור על הרשימה המקומית לפי סדר עדיפויות
        for (var a = 0; a < context.local_alpns.length; a++) {
          var cand = context.local_alpns[a];
          for (var b = 0; b < context.remote_alpns.length; b++) {
            if (context.remote_alpns[b] == cand) {
              params_to_set.selected_alpn = cand;
              break;
            }
          }
          if (params_to_set.selected_alpn &&
              params_to_set.selected_alpn != null)
            break;
        }
      }

      // == Group (ECDHE) ==
      if (context.selected_group == null) {
        if (context.selected_version == wire.TLS_VERSION.TLS1_3) {
          if (context.local_groups.length > 0 &&
              context.remote_key_shares.length > 0) {
            for (var g = 0; g < context.local_groups.length; g++) {
              var grp = context.local_groups[g] | 0;
              for (var k = 0; k < context.remote_key_shares.length; k++) {
                var ent = context.remote_key_shares[k];
                if ((ent.group | 0) == grp) {
                  params_to_set.selected_group = grp;
                  params_to_set.remote_key_share_selected_public =
                      ent.pubkey ?? ent.key_exchange ?? null;
                  break;
                }
              }
              if (params_to_set.selected_group == true &&
                  params_to_set.selected_group != null)
                break;
            }
            if (!params_to_set.selected_group &&
                context.selected_version == wire.TLS_VERSION.TLS1_3) {
              params_to_set.need_hrr =
                  true; // HelloRetryRequest אם לא נמצא group
            }

            if (params_to_set.selected_group == false ||
                params_to_set.selected_group == null) {
              //console.log('no match selected_group...');
            }
          }
        } else if (context.selected_version == wire.TLS_VERSION.TLS1_2) {
          //console.log('...remote_groups...');

          // 1.2 – לבחור עקום מתוך supported_groups של הלקוח (אין key_share)
          if (context.local_groups.length > 0 &&
              context.remote_groups.length > 0) {
            for (var grp in context.local_groups) {
              if (context.remote_groups.reduce(
                    (g, grp) => (g | 0) == (grp | 0) ? 1 : 0,
                  ) ==
                  0) {
                params_to_set.selected_group = grp | 0;
                break;
              }
            }

            if (params_to_set.selected_group == false ||
                params_to_set.selected_group == null) {
              //console.log('no match selected_group...');
            }
          }
        }
      }

      // == Signature Algorithm ==
      if (context.selected_signature_algorithm == null &&
          context.local_signature_algorithms.length > 0 &&
          context.remote_signature_algorithms.length > 0) {
        for (var s = 0; s < context.local_signature_algorithms.length; s++) {
          var sa = context.local_signature_algorithms[s] | 0;
          for (var t = 0; t < context.remote_signature_algorithms.length; t++) {
            if ((context.remote_signature_algorithms[t] | 0) == sa) {
              params_to_set.selected_signature_algorithm = sa;
              break;
            }
          }
          if (params_to_set.selected_signature_algorithm == true &&
              params_to_set.selected_signature_algorithm != null)
            break;
        }

        if (params_to_set.selected_signature_algorithm == false ||
            params_to_set.selected_signature_algorithm == null) {
          //console.log('no match selected_signature_algorithm...');
        }
      }

      // == SNI ==
      if (context.selected_sni == null) {
        params_to_set.selected_sni = context.remote_sni ?? null;
      }

      // == Session ID (TLS 1.2 בלבד) ==
      if (context.selected_session_id == null) {
        params_to_set.selected_session_id =
            context.remote_session_id ?? Uint8List(0);
      }

      // == Extensions ==
      if (context.selected_extensions == null && 1 == 2) {
        var sel = [];
        var allowed = {};
        if (context.local_extensions) {
          for (var lx = 0; lx < context.local_extensions.length; lx++) {
            var lt =
                context.local_extensions[lx] &&
                context.local_extensions[lx].type;
            if (lt is num) allowed[lt | false] = true;
          }
        }
        if (context.local_ee_extensions.isNotEmpty) {
          for (var ex = 0; ex < context.local_ee_extensions.length; ex++) {
            var et =
                context.local_ee_extensions[ex] &&
                context.local_ee_extensions[ex].type;
            if (et is num) allowed[et | false] = true;
          }
        }
        if (context.remote_extensions_all) {
          for (var rx = 0; rx < context.remote_extensions_all.length; rx++) {
            var rt =
                context.remote_extensions_all[rx] &&
                context.remote_extensions_all[rx].type;
            if (rt is num && allowed[rt | false]) {
              sel.add(rt | false);
            }
          }
        }
        if (params_to_set.selected_version == wire.TLS_VERSION.TLS1_3) {
          if (sel.indexOf(0x002b) == -1) sel.add(0x002b); // supported_versions
          if (sel.indexOf(0x0033) == -1) sel.add(0x0033); // key_share
        }
        params_to_set.selected_extensions = sel;
      }

      //console.log(params_to_set);
    }

    //יצירת מפתח תלוי ב GROUP
    if (context.selected_group != null &&
        context.local_key_share_private == null &&
        context.local_key_share_public == null) {
      if (context.selected_version == wire.TLS_VERSION.TLS1_3) {
        var client_public_key = null;
        for (var i = 0; i < context.remote_key_shares.length; i++) {
          if ((context.remote_key_shares[i].group | 0) ==
              (context.selected_group | 0)) {
            client_public_key =
                context.remote_key_shares[i].pubkey ||
                    context.remote_key_shares[i].key_exchange ??
                null;
            break;
          }
        }

        if (client_public_key != null) {
          // כאן ליצור את זוג המפתחות (priv/pub) בהתאם לקבוצה

          if (context.selected_group == 0x001d) {
            // X25519

            // --- secp256r1 (P-256) Logic ---
            var ec = elliptic.getP256();
            var priv = ec.generatePrivateKey();

            final local_key_share_private = Uint8List.fromList(priv.bytes);
            final local_key_share_public = Uint8List.fromList(
              HEX.decode(priv.publicKey.toHex()),
            );

            var clientPub = elliptic.PublicKey.fromHex(
              ec,
              HEX.encode(local_key_share_public),
            );

            // Calculate Shared Secret (X-coordinate of scalar multiplication)
            var sharedPoint = ec.scalarMul(clientPub, priv.bytes);
            String xHex = sharedPoint.X.toRadixString(16).padLeft(64, '0');
            final ecdhe_shared_secret = Uint8List.fromList(HEX.decode(xHex));

            // דרישות פורמט: client_public_key צריך להיות באורך 32 בייטים
            // (נמנעים כאן מטיפול שגיאות כרגע)
            // var local_key_share_private = Uint8List.fromList(List.generate(32,(_)=>Random.secure().nextInt(255)));
            // var local_key_share_public  = x25519.getPublicKey(local_key_share_private);
            // var ecdhe_shared_secret = x25519.getSharedSecret(local_key_share_private, client_public_key);
            // אפשר לבצע strip של ה־first byte אם הספרייה מחזירה 32/33 — תלוי במימוש.

            params_to_set.local_key_share_private = local_key_share_private;
            params_to_set.local_key_share_public = local_key_share_public;
            params_to_set.ecdhe_shared_secret = ecdhe_shared_secret;
          } else if (context.selected_group == 0x0017) {
            // secp256r1 (P-256)
            //console.log('P-256');
            // --- secp256r1 (P-256) Logic ---
            var ec = elliptic.getP256();
            var priv = ec.generatePrivateKey();

            final local_key_share_private = Uint8List.fromList(priv.bytes);
            final local_key_share_public = Uint8List.fromList(
              HEX.decode(priv.publicKey.toHex()),
            );

            var clientPub = elliptic.PublicKey.fromHex(
              ec,
              HEX.encode(local_key_share_public),
            );

            // Calculate Shared Secret (X-coordinate of scalar multiplication)
            var sharedPoint = ec.scalarMul(clientPub, priv.bytes);
            String xHex = sharedPoint.X.toRadixString(16).padLeft(64, '0');
            final ecdhe_shared_secret = Uint8List.fromList(HEX.decode(xHex));

            // var local_key_share_private = p256.utils.randomPrivateKey();
            // var local_key_share_public  = p256.getPublicKey(priv, false); // uncompressed 65B

            // var clientPoint = p256.ProjectivePoint.fromHex(client_public_key);
            // // נקודת השיתוף = priv * clientPoint
            // var sharedPoint = clientPoint.multiply(BigInt('0x' + Buffer.from(priv).toString('hex')));
            // // שליפת הקואורדינטה X כ-32 בתים big-endian:
            // var affine = sharedPoint.toAffine();                     // { x: bigint, y: bigint }
            // var xHex   = affine.x.toString(16).padStart(64, '0');    // 32B hex
            // var ecdhe_shared_secret     = Uint8Array.from(Buffer.from(xHex, 'hex'));  // ← הסוד ל-TLS הוא X בלבד

            params_to_set.local_key_share_private = local_key_share_private;
            params_to_set.local_key_share_public = local_key_share_public;
            params_to_set.ecdhe_shared_secret = ecdhe_shared_secret;
          }
        }
      } else if (context.selected_version == wire.TLS_VERSION.TLS1_2) {
        //console.log('@@@ 2');
        // רק ליצור (priv/pub) עבור ServerKeyExchange
        if (context.selected_group == 0x001d) {
          // X25519
          // --- X25519 Logic ---
          var aliceKeyPair = generateKeyPair(); // Server Keypair
          final priv = Uint8List.fromList(aliceKeyPair.privateKey);
          final pub = Uint8List.fromList(aliceKeyPair.publicKey);

          // Secret = X25519(myPrivateKey, theirPublicKey)
          final sharedSecret = Uint8List.fromList(X25519(priv, pub));

          // const priv = new Uint8Array(crypto.randomBytes(32));
          // const pub  = x25519.getPublicKey(priv);
          params_to_set.local_key_share_private = priv;
          params_to_set.local_key_share_public = pub;
          params_to_set.ecdhe_shared_secret = sharedSecret;
          // אל תחשב shared כאן; תחכה ל-ClientKeyExchange
        }
        // else if (context.selected_group == 0x0017) { // P-256
        //   const priv = p256.utils.randomPrivateKey();
        //   const pub  = p256.getPublicKey(priv, false); // 65B uncompressed
        //   params_to_set.local_key_share_private = priv;
        //   params_to_set.local_key_share_public  = pub;
        // }
      }
    }

    if (context.selected_version != prev.selected_version ||
        context.selected_cipher_suite != prev.selected_cipher_suite ||
        context.selected_session_id != prev.selected_session_id ||
        context.selected_group != prev.selected_group ||
        context.local_key_share_public != prev.local_key_share_public) {
      // build_server_hello... 1.3...

      var can_send_hello = false;
      if (context.hello_sent == false) {
        if (context.selected_version != null &&
            context.selected_cipher_suite != null &&
            context.selected_session_id != null) {
          if (context.selected_version == wire.TLS_VERSION.TLS1_3) {
            if (context.local_key_share_public != null &&
                context.selected_group != null) {
              can_send_hello = true;
            }
          } else if (context.selected_version == wire.TLS_VERSION.TLS1_2) {
            can_send_hello = true;
          }
        }
      }

      if (can_send_hello == true) {
        context.local_random ??= Uint8List.fromList(
          List.generate(32, (_) => Random.secure().nextInt(255)),
        );

        var build_message_params = null;

        if (context.selected_version == wire.TLS_VERSION.TLS1_3) {
          build_message_params = (
            type: 'server_hello',
            version: context.selected_version,
            random: context.local_random,
            session_id: context.remote_session_id,
            cipher_suite:
                context.selected_cipher_suite, // TLS_AES_128_GCM_SHA256
            extensions: [
              (type: 'SUPPORTED_VERSIONS', value: wire.TLS_VERSION.TLS1_3),
              (
                type: 'KEY_SHARE',
                value: (
                  group: context.selected_group,
                  key_exchange: context.local_key_share_public,
                ),
              ),
            ],
          );
        } else if (context.selected_version == wire.TLS_VERSION.TLS1_2) {
          // ⚠️ אין SUPPORTED_VERSIONS/KEY_SHARE בתוך ServerHello של TLS 1.2.
          // מומלץ לכלול renegotiation_info (ריק בהנדשייק ראשון) ו-extended_master_secret (type=23).
          // ALPN (type=16) – אופציונלי: אם נבחר למשל 'http/1.1' או 'h2'.

          var ext_list = [
            // RFC 5746 – initial handshake: value ריק (vec<1> באורך 0)
            (type: 'RENEGOTIATION_INFO', value: Uint8List(0)),

            // RFC 7627 – extended_master_secret (type 23) – ערך ריק.
            // מאחר ואין encoder רשום אצלנו ל-23, נשתמש ישירות ב-data ריק:
            (type: 23, data: Uint8List(0)),
          ];

          if (context.alpn_selected != 0) {
            // RFC 7301 – ב-ServerHello מוחזר פרוטוקול אחד
            ext_list.add((
              type: 'ALPN',
              value: utf8.decode([context.alpn_selected]),
            ));
          }

          build_message_params = (
            type: 'server_hello',
            version: context.selected_version,
            random: context.local_random,
            session_id:
                context.remote_session_id ??
                Uint8List(0), // מקובל להדהד את ה-session_id של הלקוח
            cipher_suite: context
                .selected_cipher_suite, // למשל 0xC02F (ECDHE_RSA_WITH_AES_128_GCM_SHA256)
            // compression_method תמיד 0 ב-1.2 אצלנו; ה-builder כבר כותב 0.
            extensions: ext_list,
          );
        }

        if (build_message_params != null) {
          //console.log('sent server hello...')
          var message_data = wire.build_message(build_message_params);

          context.transcript.push(message_data);

          context.hello_sent = true;

          ev.emit(
            'message',
            0,
            context.message_sent_seq,
            'hello',
            message_data,
          );

          context.message_sent_seq++;
        }
      }
    }

    if (context.selected_version == wire.TLS_VERSION.TLS1_3) {
      if (context.selected_cipher_suite != null &&
          (context.ecdhe_shared_secret != null)) {
        // || context.selected_psk != null

        var d = derive_handshake_traffic_secrets(
          TLS_CIPHER_SUITES[context.selected_cipher_suite]!.hash,
          context.ecdhe_shared_secret,
          concatUint8Arrays(context.transcript),
        );

        params_to_set.handshake_secret = d.handshake_secret;

        params_to_set.client_handshake_traffic_secret =
            d.client_handshake_traffic_secret;
        params_to_set.server_handshake_traffic_secret =
            d.server_handshake_traffic_secret;
      }
    }

    if (context.selected_version == wire.TLS_VERSION.TLS1_3) {
      if (context.encrypted_exts_sent == false &&
          context.hello_sent == true &&
          context.server_handshake_traffic_secret != null) {
        var extensions = [];
        if (context.selected_alpn != null) {
          extensions.add((type: 'ALPN', value: [context.selected_alpn]));
        }

        //console.log('extensions:');
        //console.log(extensions);

        for (var i in context.local_extensions) {
          extensions.add(context.local_extensions[i]);
        }

        var message_data = wire.build_message((
          type: 'encrypted_extensions',
          extensions: extensions,
        ));

        //console.log('message_data:');
        //console.log(message_data);

        context.transcript.push(message_data);

        context.encrypted_exts_sent = true;

        ev.emit(
          'message',
          1,
          context.message_sent_seq,
          'encrypted_extensions',
          message_data,
        );

        context.message_sent_seq++;
      }
    }

    if (context.cert_sent == false && context.local_cert_chain != null) {
      if ((context.selected_version == wire.TLS_VERSION.TLS1_3 &&
              context.encrypted_exts_sent == true &&
              context.server_handshake_traffic_secret != null) ||
          (context.selected_version == wire.TLS_VERSION.TLS1_2 &&
              context.hello_sent == true)) {
        var message_data = wire.build_message((
          type: 'certificate',
          version: context.selected_version,
          entries: context.local_cert_chain,
        ));
        context.transcript.push(message_data);

        context.cert_sent = true;

        if (context.selected_version == wire.TLS_VERSION.TLS1_3) {
          ev.emit(
            'message',
            1,
            context.message_sent_seq,
            'certificate',
            message_data,
          );
        } else {
          ev.emit(
            'message',
            0,
            context.message_sent_seq,
            'certificate',
            message_data,
          );
        }

        context.message_sent_seq++;
      }
    }

    if (context.selected_version == wire.TLS_VERSION.TLS1_3) {
      if (context.cert_sent == true &&
          context.cert_verify_sent == false &&
          context.local_cert_chain != null &&
          context.server_handshake_traffic_secret != null) {
        var tbs_data = build_cert_verify_tbs(
          TLS_CIPHER_SUITES[context.selected_cipher_suite]!.hash,
          true,
          concatUint8Arrays(context.transcript),
        );

        // var cert_private_key_obj = crypto.createPrivateKey({
        //   key: Buffer.from(context.cert_private_key),
        //   format: 'der',
        //   type: 'pkcs8',
        // });

        final ecCertificate = generateSelfSignedCertificate();

        var candidates = [];
        // if (cert_private_key_obj.asymmetricKeyType == 'ed25519') candidates.add(SIG.ED25519);
        // if (cert_private_key_obj.asymmetricKeyType == 'ed448')   candidates.add(SIG.ED448);
        // if (cert_private_key_obj.asymmetricKeyType == 'rsa')     candidates.add(SIG.RSA_PSS_SHA256, SIG.RSA_PSS_SHA384, SIG.RSA_PSS_SHA512); // TLS 1.3 → רק PSS

        // if (cert_private_key_obj.asymmetricKeyType == 'ec') {

        //  serverEcCertificate
        //   var c = (cert_private_key_obj.asymmetricKeyDetails && cert_private_key_obj.asymmetricKeyDetails && cert_private_key_obj.asymmetricKeyDetails.namedCurve) || '';
        // if (c == 'prime256v1')
        candidates.add(SIG.ECDSA_P256_SHA256);
        // if (c == 'secp384r1')  candidates.add(SIG.ECDSA_P384_SHA384);
        // if (c == 'secp521r1')  candidates.add(SIG.ECDSA_P521_SHA512);
        // }

        //console.log(candidates);

        var preference_order = [
          SIG.ED25519,
          SIG.ED448,
          SIG.ECDSA_P256_SHA256,
          SIG.ECDSA_P384_SHA384,
          SIG.ECDSA_P521_SHA512,
          SIG.RSA_PSS_SHA256,
          SIG.RSA_PSS_SHA384,
          SIG.RSA_PSS_SHA512,
        ];

        var selected_scheme = null;
        for (var s in preference_order) {
          if (context.remote_signature_algorithms.contains(s) == true &&
              candidates.contains(s) == true) {
            selected_scheme = s;
            break;
          }
        }

        var sig_data = null;

        switch (selected_scheme) {
          case SIG.ED25519:
            throw UnimplementedError(selected_scheme);
            // sig_data = new Uint8Array(crypto.sign(null, tbs_data, cert_private_key_obj));
            break;

          case SIG.ECDSA_P256_SHA256:
            sig_data = ecCertificate.fingerPrint;
            // sig_data = new Uint8Array(crypto.sign('sha256', tbs_data, cert_private_key_obj));
            break;

          case SIG.ECDSA_P384_SHA384:
            throw UnimplementedError(selected_scheme);
            // sig_data = new Uint8Array(crypto.sign('sha384', tbs_data, cert_private_key_obj));
            break;

          case SIG.ECDSA_P521_SHA512:
            throw UnimplementedError(selected_scheme);
            // sig_data = new Uint8Array(crypto.sign('sha512', tbs_data, cert_private_key_obj));
            break;

          case SIG.RSA_PSS_SHA256:
            throw UnimplementedError(selected_scheme);
            // sig_data = new Uint8Array(crypto.sign('sha256', tbs_data, {
            //   key: cert_private_key_obj,
            //   padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            //   saltLength: 32
            // }));
            break;

          case SIG.RSA_PSS_SHA384:
            throw UnimplementedError(selected_scheme);
            // sig_data = new Uint8Array(crypto.sign('sha384', tbs_data, {
            //   key: cert_private_key_obj,
            //   padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            //   saltLength: 48
            // }));
            break;

          case SIG.RSA_PSS_SHA512:
            throw UnimplementedError(selected_scheme);
            // sig_data = new Uint8Array(crypto.sign('sha512', tbs_data, {
            //   key: cert_private_key_obj,
            //   padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            //   saltLength: 64
            // }));
            break;
        }

        //console.log('sig_data:');
        //console.log(sig_data);

        if (sig_data) {
          var message_data = wire.build_message((
            type: 'certificate_verify',
            scheme: selected_scheme,
            signature: sig_data,
          ));

          //console.log(message_data);
          //console.log('certificate_verify sent!');
          context.transcript.push(message_data);

          context.cert_verify_sent = true;

          ev.emit(
            'message',
            1,
            context.message_sent_seq,
            'certificate_verify',
            message_data,
          );

          context.message_sent_seq++;
        } else {
          //..
        }
      }
    }

    if (context.selected_version == wire.TLS_VERSION.TLS1_3) {
      if (context.cert_verify_sent == true &&
          context.finished_sent == false &&
          context.local_cert_chain != null &&
          context.server_handshake_traffic_secret != null) {
        var finished_data = get_handshake_finished(
          TLS_CIPHER_SUITES[context.selected_cipher_suite]!.hash,
          context.server_handshake_traffic_secret,
          concatUint8Arrays(context.transcript),
        );

        var message_data = wire.build_message((
          type: 'finished',
          data: finished_data,
        ));

        context.transcript.add(message_data);

        context.finished_sent = true;

        ev.emit(
          'message',
          1,
          context.message_sent_seq,
          'finished',
          message_data,
        );

        context.message_sent_seq++;
      }
    }

    if (context.selected_version == wire.TLS_VERSION.TLS1_3) {
      if (context.finished_sent == true &&
          context.handshake_secret != null &&
          context.server_app_traffic_secret == null) {
        var d2 = derive_app_traffic_secrets(
          TLS_CIPHER_SUITES[context.selected_cipher_suite]!.hash,
          context.handshake_secret,
          concatUint8Arrays(context.transcript),
        );

        params_to_set.handshake_secret = null;

        params_to_set.client_app_traffic_secret = d2.client_app_traffic_secret;
        params_to_set.server_app_traffic_secret = d2.server_app_traffic_secret;
      }
    }

    //בניית פינישד צפוי
    if (context.selected_version == wire.TLS_VERSION.TLS1_3) {
      if (context.finished_sent == true &&
          context.expected_remote_finished == null &&
          context.client_handshake_traffic_secret != null) {
        params_to_set.expected_remote_finished = get_handshake_finished(
          TLS_CIPHER_SUITES[context.selected_cipher_suite]!.hash,
          context.client_handshake_traffic_secret,
          concatUint8Arrays(context.transcript),
        );
      }
    }

    if (context.selected_version == wire.TLS_VERSION.TLS1_3) {
      if (context.remote_finished_ok == false &&
          context.remote_finished != null &&
          context.expected_remote_finished != null) {
        if (arraybufferEqual(
              context.remote_finished.buffer,
              context.expected_remote_finished.buffer,
            ) ==
            true) {
          context.transcript.push(context.remote_finished);

          context.remote_finished_ok = true;

          context.remote_finished = null;
          context.expected_remote_finished = null;

          //console.log('finished ok!!!...');
        } else {
          context.remote_finished = null;

          //console.log('finished fail...');
        }
      }
    }

    if (context.selected_version == wire.TLS_VERSION.TLS1_3) {
      if (context.remote_finished_ok == true &&
          context.server_app_traffic_secret != null) {
        ev.emit('secureConnect');
      }
    }

    set_context(params_to_set, context, ev);
  }
}

dynamic tlsSession(TlsOptions options) {
  // if (!(this is TLSSession)) return new TLSSession(options);
  // options = options || {};

  var ev = Emitter();

  TlsContext context = TlsContext(
    state: 'new', //new | negotiating | ...
    isServer: !!options.isServer,

    SNICallback: options.SNICallback ?? null,

    local_versions: [], // [0x0304, 0x0303, ...]
    local_cipher_suites: [], //[0x1303, 0x1301, 0x1302]
    local_alpns: [], // ['h3','h2','http/1.1', ...]
    local_groups: [], //[0x001D, 0x0017, 0x0018]// x25519, secp256r1, secp384r1
    local_signature_algorithms:
        [], //[0x0403, 0x0804,  0x0805] //ecdsa_secp256r1_sha256 (0x0403), rsa_pss_rsae_sha256 (0x0804), rsa_pss_rsae_sha384 (0x0805)
    local_extensions: [], // [{ type, data }, ...]

    local_key_share_public: null, // Uint8Array (pubkey שנשלח)
    local_key_share_private: null, // Uint8Array (privkey זמני)
    // REMOTE (מה שהצד המרוחק שלח/מציע)
    remote_versions: [],
    remote_cipher_suites: [],
    remote_alpns: [],
    remote_groups: [],
    remote_signature_algorithms: [],
    remote_extensions: [],
    remote_key_shares: [],
    remote_sni: null,
    remote_session_id: null,
    remote_random: null,

    // SELECTED (מה שנקבע בפועל)
    selected_version: null, // 0x0304 / 0x0303
    selected_cipher_suite: null, // למשל 0x1301
    selected_alpn: null, // 'h3'/'h2'/... או null
    selected_group: null, // למשל 0x001D
    selected_signature_algorithm: null, // למשל 0x0804
    selected_extensions: [], // [type,...] או [{type,dataConfirmed}]
    selected_sni: null, // string|null
    selected_session_id: null, // TLS 1.2 בלבד
    // שאר מצב/מפתחות/תעודות/תזמון
    transcript: [], // Handshake inner messages

    local_random: null,

    //whats already sent?
    hello_sent: false,
    encrypted_exts_sent: false,
    cert_sent: false,
    cert_verify_sent: false,
    finished_sent: false,

    message_sent_seq: 0,

    remote_finished: null,
    expected_remote_finished: null,
    remote_finished_ok: false,

    // local_key_share_private: null,
    // local_key_share_public: null,
    ecdhe_shared_secret: null,

    handshake_secret: null,

    client_handshake_traffic_secret: null,
    server_handshake_traffic_secret: null,

    client_app_traffic_secret: null,
    server_app_traffic_secret: null,

    local_cert_chain: null,
    remote_cert_chain: null,

    selected_cert: null,

    cert_private_key: null,
  );

  dynamic process_income_message(data) {
    var message = wire.parse_message(data);

    if (message.type == wire.TLS_MESSAGE_TYPE.CLIENT_HELLO ||
        message.type == wire.TLS_MESSAGE_TYPE.SERVER_HELLO) {
      var hello = wire.parse_hello(message.type, message.body);

      var info = normalizeHello(hello);
      //console.log(info);
      context.transcript.add(data);

      set_context(
        (
          remote_random: info.random ?? null,
          remote_sni: info.sni ?? null,
          remote_session_id: info.session_id ?? null, // TLS 1.2 בעיקר
          remote_cipher_suites: info.cipher_suites ?? [],
          remote_alpns: info.alpn ?? [],
          remote_key_shares: info.key_shares ?? [],
          remote_versions: info.supported_versions ?? [],
          remote_signature_algorithms: info.signature_algorithms ?? [],
          remote_groups: info.supported_groups ?? [],
          remote_extensions: info.extensions ?? [],
        ),
        context,
        ev,
      );

      ev.emit('hello');

      if (context.SNICallback is dynamic) {
        context.SNICallback(context.remote_sni, (err, creds) {
          if (!err && creds) {
            set_context(
              (
                local_cert_chain: creds.certificateChain,
                cert_private_key: creds.privateKey,
              ),
              context,
              ev,
            );
          } else {
            //console.log('No TLS credentials for', current_params.sni);
          }
        });
      }
    } else if (message.type == wire.TLS_MESSAGE_TYPE.FINISHED) {
      set_context((remote_finished: message.body), context, ev);
    }
  }

  close() {}

  var api = (
    context: context,

    on: (name, fn) {
      ev.on(name, fn);
    },

    message: process_income_message,

    set_context: set_context,

    close: close,

    //getProtocol: getProtocol,
    getCipher: () {
      // TODO: { name, standardName, keyLen, aead } אחרי נגושיאציה
      return null;
    },

    getPeerCertificate: (detailed) {
      void detailed;
      // TODO: להחזיר ch cert או null
      return context.peerCert;
    },

    exportKeyingMaterial: (length, label, context) {
      void length;
      void label;
      void context;
      // TODO: HKDF-Expand-Label על traffic secret מתאים (RFC8446)
      return Uint8List(0);
    },
  );

  // for (var k in api)
  //   if (Object.prototype.hasOwnProperty.call(api, k)) this[k] = api[k];
  // return this;
}

// export default TLSSession;
