import 'dart:typed_data';

class TlsContext {
  List<Uint8List> transcript = [];

  var SNICallback;

  var remote_sni;

  var local_versions;

  var local_cipher_suites;

  var local_alpns;

  var local_groups;

  var local_signature_algorithms;

  var local_extensions;

  var local_key_share_public;

  var remote_finished_ok;

  var local_key_share_private;

  var remote_versions;

  var remote_cipher_suites;

  var remote_alpns;

  var remote_groups;

  var remote_signature_algorithms;

  var remote_extensions;

  var remote_key_shares;

  var remote_session_id;

  var remote_random;

  var selected_version;

  var selected_cipher_suite;

  var selected_alpn;

  var selected_group;

  var selected_signature_algorithm;

  var selected_extensions;

  var selected_sni;

  var selected_session_id;

  var ecdhe_shared_secret;

  var handshake_secret;

  var client_handshake_traffic_secret;

  var server_handshake_traffic_secret;

  var client_app_traffic_secret;

  var server_app_traffic_secret;

  var local_cert_chain;

  var cert_private_key;

  var expected_remote_finished;

  var remote_finished;

  var remote_key_share_selected_public;

  var need_hrr;

  var local_ee_extensions;

  var remote_extensions_all;

  var hello_sent;

  var local_random;

  var alpn_selected;

  var message_sent_seq;

  var encrypted_exts_sent;

  var cert_sent;

  var cert_verify_sent;

  var finished_sent;

  var isServer;

  var remote_cert_chain;

  var state;

  var selected_cert;

  var peerCert;

  List<int>? local_signature_algorithms_cert;

  TlsContext({
    dynamic SNICallback,
    Null cert_private_key,
    this.cert_sent,
    this.cert_verify_sent,
    this.client_app_traffic_secret,
    this.client_handshake_traffic_secret,
    this.ecdhe_shared_secret,
    this.encrypted_exts_sent,
    this.expected_remote_finished,
    this.finished_sent,
    this.handshake_secret,
    this.hello_sent,
    this.isServer,
    this.local_alpns,
    this.local_cert_chain,
    this.local_cipher_suites,
    this.local_extensions,
    this.local_groups,
    this.local_key_share_private,
    this.local_key_share_public,
    this.local_random,
    this.local_signature_algorithms,
    this.local_versions,
    this.message_sent_seq,
    this.remote_alpns,
    this.remote_cert_chain,
    this.remote_cipher_suites,
    this.remote_extensions,
    this.remote_finished,
    this.remote_finished_ok,
    this.remote_groups,
    this.remote_key_shares,
    this.remote_random,
    this.remote_session_id,
    this.remote_signature_algorithms,
    this.remote_sni,
    this.remote_versions,
    this.selected_alpn,
    this.selected_cert,
    this.selected_cipher_suite,
    this.selected_extensions,
    this.selected_group,
    this.selected_session_id,
    this.selected_signature_algorithm,
    this.selected_sni,
    this.selected_version,
    this.server_app_traffic_secret,
    this.server_handshake_traffic_secret,
    this.state,
    // this.transcript = const [],
  });
}
