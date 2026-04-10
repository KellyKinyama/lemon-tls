import 'dart:typed_data';

Uint8List buildFinishedMessage(Uint8List verifyData) {
  final length = verifyData.length;

  final header = Uint8List.fromList([
    0x14, // Finished
    (length >> 16) & 0xff,
    (length >> 8) & 0xff,
    length & 0xff,
  ]);

  return Uint8List.fromList([...header, ...verifyData]);
}
