// ============================================================================
// tls_constants.dart
// Converted from original JavaScript TLS constants with minimal changes
// ============================================================================

import 'dart:typed_data';

/// TLS protocol version numbers (big-endian u16)
class TLSVersion {
  static const int TLS1_0 = 0x0301;
  static const int TLS1_1 = 0x0302;
  static const int TLS1_2 = 0x0303;
  static const int TLS1_3 = 0x0304;

  static const Map<String, int> values = {
    'TLS1_0': TLS1_0,
    'TLS1_1': TLS1_1,
    'TLS1_2': TLS1_2,
    'TLS1_3': TLS1_3,
  };
}

/// TLS handshake message types
class TLSMessageType {
  static const int CLIENT_HELLO = 1;
  static const int SERVER_HELLO = 2;
  static const int NEW_SESSION_TICKET = 4;
  static const int END_OF_EARLY_DATA = 5;
  static const int ENCRYPTED_EXTENSIONS = 8;
  static const int CERTIFICATE = 11;
  static const int SERVER_KEY_EXCHANGE = 12;
  static const int CERTIFICATE_REQUEST = 13;
  static const int SERVER_HELLO_DONE = 14;
  static const int CERTIFICATE_VERIFY = 15;
  static const int CLIENT_KEY_EXCHANGE = 16;
  static const int FINISHED = 20;
  static const int KEY_UPDATE = 24;
  static const int MESSAGE_HASH = 254;

  static const Map<String, int> values = {
    'CLIENT_HELLO': CLIENT_HELLO,
    'SERVER_HELLO': SERVER_HELло,
    'NEW_SESSION_TICKET': NEW_SESSION_TICKET,
    'END_OF_EARLY_DATA': END_OF_EARLY_DATA,
    'ENCRYPTED_EXTENSIONS': ENCRYPTED_EXTENSIONS,
    'CERTIFICATE': CERTIFICATE,
    'SERVER_KEY_EXCHANGE': SERVER_KEY_EXCHANGE,
    'CERTIFICATE_REQUEST': CERTIFICATE_REQUEST,
    'SERVER_HELло_DONE': SERVER_HELло_DONE,
    'CERTIFICATE_VERIFY': CERTIFICATE_VERIFY,
    'CLIENT_KEY_EXCHANGE': CLIENT_KEY_EXCHANGE,
    'FINISHED': FINISHED,
    'KEY_UPDATE': KEY_UPDATE,
    'MESSAGE_HASH': MESSAGE_HASH,
  };
}

/// TLS Extension type codes
class TLSExt {
  static const int SERVER_NAME = 0;
  static const int MAX_FRAGMENT_LENGTH = 1;
  static const int STATUS_REQUEST = 5;
  static const int SUPPORTED_GROUPS = 10;
  static const int SIGNATURE_ALGORITHMS = 13;
  static const int USE_SRTP = 14;
  static const int HEARTBEAT = 15;
  static const int ALPN = 16;
  static const int SCT = 18;
  static const int CLIENT_CERT_TYPE = 19;
  static const int SERVER_CERT_TYPE = 20;
  static const int PADDING = 21;
  static const int PRE_SHARED_KEY = 41;
  static const int EARLY_DATA = 42;
  static const int SUPPORTED_VERSIONS = 43;
  static const int COOKIE = 44;
  static const int PSK_KEY_EXCHANGE_MODES = 45;
  static const int CERTIFICATE_AUTHORITIES = 47;
  static const int OID_FILTERS = 48;
  static const int POST_HANDSHAKE_AUTH = 49;
  static const int SIGNATURE_ALGORITHMS_CERT = 50;
  static const int KEY_SHARE = 51;
  static const int RENEGOTIATION_INFO = 0xFF01;

  static const Map<String, int> values = {
    'SERVER_NAME': SERVER_NAME,
    'MAX_FRAGMENT_LENGTH': MAX_FRAGMENT_LENGTH,
    'STATUS_REQUEST': STATUS_REQUEST,
    'SUPPORTED_GROUPS': SUPPORTED_GROUPS,
    'SIGNATURE_ALGORITHMS': SIGNATURE_ALGORITHMS,
    'USE_SRTP': USE_SRTP,
    'HEARTBEAT': HEARTBEAT,
    'ALPN': ALPN,
    'SCT': SCT,
    'CLIENT_CERT_TYPE': CLIENT_CERT_TYPE,
    'SERVER_CERT_TYPE': SERVER_CERT_TYPE,
    'PADDING': PADDING,
    'PRE_SHARED_KEY': PRE_SHARED_KEY,
    'EARLY_DATA': EARLY_DATA,
    'SUPPORTED_VERSIONS': SUPPORTED_VERSIONS,
    'COOKIE': COOKIE,
    'PSK_KEY_EXCHANGE_MODES': PSK_KEY_EXCHANGE_MODES,
    'CERTIFICATE_AUTHORITIES': CERTIFICATE_AUTHORITIES,
    'OID_FILTERS': OID_FILTERS,
    'POST_HANDSHAKE_AUTH': POST_HANDSHAKE_AUTH,
    'SIGNATURE_ALGORITHMS_CERT': SIGNATURE_ALGORITHMS_CERT,
    'KEY_SHARE': KEY_SHARE,
    'RENEGOTIATION_INFO': RENEGOTIATION_INFO,
  };
}