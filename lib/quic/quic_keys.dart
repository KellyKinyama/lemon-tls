import 'dart:typed_data';

class InitialKeys {
  final Uint8List key;
  final Uint8List iv;
  final Uint8List hp;
  InitialKeys({required this.key, required this.iv, required this.hp});
}