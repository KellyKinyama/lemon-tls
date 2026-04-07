import 'tls_session_class.dart';

class KeySchedule {
  var appWriteQueue;

  var app_read_aead;

  var app_read_iv;

  var app_read_key;

  var app_read_seq;

  var app_write_aead;

  var app_write_iv;

  var app_write_key;

  var app_write_seq;

  var destroyed;

  var handshake_read_aead;

  var handshake_read_iv;

  var handshake_read_key;

  var handshake_read_seq;

  var handshake_write_aead;

  var handshake_write_iv;

  var handshake_write_key;

  var handshake_write_seq;

  var readBuffer;

  var options;

  var rec_version;

  var secureEstablished;

  var transport;

  var using_app_keys;

  TlsSession session;

  var application_write;

  KeySchedule({
    this.appWriteQueue,
    this.app_read_aead,
    this.app_read_iv,
    this.app_read_key,
    this.app_read_seq,
    this.app_write_aead,
    this.app_write_iv,
    this.app_write_key,
    this.app_write_seq,
    this.destroyed,
    this.handshake_read_aead,
    this.handshake_read_iv,
    this.handshake_read_key,
    this.handshake_read_seq,
    this.handshake_write_aead,
    this.handshake_write_iv,
    this.handshake_write_key,
    this.handshake_write_seq,
    this.options,
    this.readBuffer,
    this.rec_version,
    this.secureEstablished,
    required this.session,
    this.transport,
    this.using_app_keys,
  });
}
