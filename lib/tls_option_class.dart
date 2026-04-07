class TlsOptions {
  var minVersion;

  var maxVersion;

  var isServer;

  var SNICallback;

  var local_versions;

  var local_cipher_suites;

  var local_alpns;

  var local_groups;

  var local_signature_algorithms;

  var local_extensions;

  var local_key_share_public;

  var local_key_share_private;

  var remote_versions;

  var remote_cipher_suites;

  var remote_alpns;

  var remote_groups;

  var remote_signature_algorithms;

  var remote_extensions;

  var remote_key_shares;

  var remote_sni;

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

  var remote_finished_ok;

  var ALPNProtocols;

  var cipherPreference;

  var groupPreference;

  var rejectUnauthorized;

  var requestCert;

  var secureContext;

  var sigAlgPreference;

  TlsOptions({
    this.ALPNProtocols,
    this.cipherPreference,
    this.groupPreference,
    this.isServer,
    this.maxVersion,
    this.minVersion,
    this.rejectUnauthorized,
    this.requestCert,
    this.secureContext,
    this.sigAlgPreference,
  });
}
