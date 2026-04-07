import 'package:events_emitter/events_emitter.dart';

class TlsSession extends EventEmitter {
  var sni;

  var alpn;

  var key_shares;

  var supported_versions;

  var signature_algorithms;

  var supported_groups;

  var renegotiation_info;

  var status_request;

  var max_fragment_length;

  var signature_algorithms_cert;

  var certificate_authorities;

  var sct;

  var heartbeat;

  var use_srtp;

  var cookie;

  var early_data;

  var psk_key_exchange_modes;

  var unknown;

  var message;

  var legacy_version;

  var version;

  var random;

  var session_id;

  var cipher_suites;

  var extensions;

  var cipher_suite;

  var legacy_compression;

  var context;

  bool? isServer;

  var servername;

  var ALPNProtocols;

  var SNICallback;

  TlsSession({
    this.alpn,
    this.certificate_authorities,
    this.cipher_suite,
    this.cipher_suites,
    this.cookie,
    this.early_data,
    this.extensions,
    this.heartbeat,
    this.key_shares,
    this.legacy_compression,
    this.legacy_version,
    this.max_fragment_length,
    this.message,
    this.psk_key_exchange_modes,
    this.random,
    this.renegotiation_info,
    this.sct,
    this.session_id,
    this.signature_algorithms,
    this.signature_algorithms_cert,
    this.sni,
    this.status_request,
    this.supported_groups,
    this.supported_versions,
    this.unknown,
    this.use_srtp,
    this.version,
    this.isServer,
    this.servername,
    this.ALPNProtocols,
    this.SNICallback,
  });

  // void on(String s, Null Function(dynamic) param1) {}

  void set_context({
    required List<int> local_versions,
    required List<String> local_alpns,
    required List<int> local_groups,
    required List<int> local_cipher_suites,
    required List<int> local_signature_algorithms,
    required List<int> local_signature_algorithms_cert,
  }) {}
}

