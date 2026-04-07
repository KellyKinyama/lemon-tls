import 'dart:typed_data';

import 'package:hex/hex.dart';

enum TLS_VERSION {
  TLS1_0(0x0301),
  TLS1_1(0x0302),
  TLS1_2(0x0303),
  TLS1_3(0x0304);

  const TLS_VERSION(this.value);
  final int value;

  factory TLS_VERSION.fromBytes(int key) {
    return values.firstWhere((element) => element.value == key);
  }
}

enum ContentType {
  invalid(0),
  change_cipher_spec(20),
  alert(21),
  handshake(22),
  application_data(23);

  const ContentType(this.value);
  final int value;

  factory ContentType.fromBytes(int key) {
    return values.firstWhere((element) => element.value == key);
  }
}

enum TLS_MESSAGE_TYPE {
  CLIENT_HELLO(1),
  SERVER_HELLO(2),
  NEW_SESSION_TICKET(4),
  END_OF_EARLY_DATA(5),
  ENCRYPTED_EXTENSIONS(8),
  CERTIFICATE(11),
  SERVER_KEY_EXCHANGE(12),
  CERTIFICATE_REQUEST(13),
  SERVER_HELLO_DONE(14),
  CERTIFICATE_VERIFY(15),
  CLIENT_KEY_EXCHANGE(16),
  FINISHED(20),
  KEY_UPDATE(24),
  MESSAGE_HASH(254); // HRR flow marker

  const TLS_MESSAGE_TYPE(this.value);
  final int value;

  factory TLS_MESSAGE_TYPE.fromBytes(int key) {
    return values.firstWhere((element) => element.value == key);
  }
}

class HandShakeMessageType {
  TLS_MESSAGE_TYPE type;

  Uint8List body;

  HandShakeMessageType(this.type, this.body);

  static HandShakeMessageType fromBytes(Uint8List bytes) {
    throw UnimplementedError();
  }

  @override
  String toString() {
    // TODO: implement toString
    return """HandShakeMessageType{type: $type,
    body: ${HEX.encode(body.sublist(0, 10))}
    }""";
  }
}
