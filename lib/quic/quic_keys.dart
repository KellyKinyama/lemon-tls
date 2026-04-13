import 'dart:typed_data';

class InitialKeys {
  final Uint8List key;
  final Uint8List iv;
  final Uint8List hp;
  InitialKeys({required this.key, required this.iv, required this.hp});
}

class HandshakeKeys {
  Uint8List key;
  Uint8List iv;
  Uint8List hp;
  HandshakeKeys({required this.key, required this.iv, required this.hp});
}

class OneRttKeys {
  Uint8List key;
  Uint8List iv;
  Uint8List hp;
  OneRttKeys({required this.key, required this.iv, required this.hp});
}
