import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:lemon_tls/key_schedule.dart';
import 'package:lemon_tls/tls_context_class.dart';
import 'package:lemon_tls/tls_session_class.dart';
import 'handlers/message_types.dart';
import 'handlers/record_layer.dart';
import 'handlers/server/client_hello_handler.dart';

class TcpClient {
  // TlsSession tlsSession = TlsSession();
  KeySchedule keySchedule;
  TlsContext context;
  TcpClient(this.transport)
    : keySchedule = KeySchedule(session: TlsSession()),
      context = TlsContext();
  Map<String, Function(List<int>)> handlers = {};

  void handle(List<int> request, Null Function(List<int> data) msgToClient) {
    // msgToClient(utf8.encode("hello client"));
    process_income_message(Uint8List.fromList(request));
  }

  dynamic process_income_message(Uint8List data) {
    final recordLayer = TLSPlaintext.fromBytes(data);
    print("Record layer: $recordLayer");

    var message = parse_message(recordLayer.fragment);

    print("Message: $message");

    if (message.type == TLS_MESSAGE_TYPE.CLIENT_HELLO) {
      var hello = parse_client_hello(message.type, message.body);

      var info = normalizeClientHello(hello);
      print("Tls session: $info");
      context.transcript.add(data);

      // keySchedule.session.remote_random = info.random;

      context.remote_random = info.random ?? null;
      context.remote_sni = info.sni ?? null;
      context.remote_session_id = info.session_id ?? null; // TLS 1.2 בעיקר
      context.remote_cipher_suites = info.cipher_suites ?? [];
      context.remote_alpns = info.alpn ?? [];
      context.remote_key_shares = info.key_shares ?? [];
      context.remote_versions = info.supported_versions ?? [];
      context.remote_signature_algorithms = info.signature_algorithms ?? [];
      context.remote_groups = info.supported_groups ?? [];
      context.remote_extensions = info.extensions ?? [];

      context.local_versions = [0x0304];
      context.local_alpns = ['http/1.1'];
      context.local_groups = [0x001d, 0x0017, 0x0018];
      context.local_cipher_suites = [
        0x1301,
        0x1302,
        0xC02F, // ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xC030, // ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xCCA8, // ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (אם מימשת)
      ];

      // ---- אלגוריתמי חתימה (TLS 1.2 → RSA-PKCS1, לא PSS) ----
      // 0x0401 = rsa_pkcs1_sha256, 0x0501 = rsa_pkcs1_sha384, 0x0601 = rsa_pkcs1_sha512
      context.local_signature_algorithms = [0x0401, 0x0501, 0x0601];
      // אופציונלי (לטובת חלק מהלקוחות): אותו דבר גם ל-signature_algorithms_cert
      context.local_signature_algorithms_cert = [0x0401, 0x0501, 0x0601];

      build_hello(kind, params);
    }

    if (message.type == TLS_MESSAGE_TYPE.SERVER_HELLO) {
      var hello = parse_server_hello(message.type, message.body);

      var info = normalizeServerHello(hello);
      print(info);
      context.transcript.add(data);
    }
  }

  // bool operator ==(SipClient other) {
  //   if (_number == other.getNumber()) {
  //     return true;
  //   }

  //   return false;
  // }

  // String getNumber() {
  //   return number;
  // }

  // SipTransport getAddress() {
  //   return transport;
  // }

  // String port;
  Socket transport;
}
