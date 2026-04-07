import 'dart:typed_data';
import 'package:test/test.dart';

import 'package:lemon_tls/tls2/tls_extensions.dart';

void main() {
  group("KEY_SHARE extension decoding", () {
    setUp(() {
      initTls13Extensions(); // MUST be here
    });

    // ------------------------------------------------------------
    // ✅ TEST 1 — ClientHello KEY_SHARE (single entry)
    // ------------------------------------------------------------
    test("Decode ClientHello KEY_SHARE list (vector<2>)", () {
      // vector<2> length = 36 (0x00 24)
      //
      // Entry:
      //   group = 0x001d
      //   len   = 0x0020 (32 bytes)
      //   key   = [32 bytes]
      //
      final data = Uint8List.fromList([
        0x00, 0x24, // vector length = 36

        0x00, 0x1d, // group = X25519
        0x00, 0x20, // key length = 32
        // 32-byte key share
        0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1,
        0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38,
        0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75,
        0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54,
      ]);

      final decoded = tls13Ext["KEY_SHARE"]!.decode!(data);

      expect(decoded, isA<List<Map<String, dynamic>>>());
      final list = decoded as List<Map<String, dynamic>>;

      expect(list.length, equals(1));
      expect(list[0]["group"], equals(0x001d));
      expect((list[0]["key_exchange"] as Uint8List).length, equals(32));
    });

    // ------------------------------------------------------------
    // ✅ TEST 2 — ServerHello KEY_SHARE (single entry)
    // ------------------------------------------------------------
    test("Decode ServerHello KEY_SHARE (single entry)", () {
      final data = Uint8List.fromList([
        0x00, 0x1d, // group = X25519
        0x00, 0x20, // key length = 32
        // 32-byte key
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
        0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
      ]);

      final decoded = tls13Ext["KEY_SHARE"]!.decode!(data);

      expect(decoded, isA<Map<String, dynamic>>());
      final map = decoded as Map<String, dynamic>;

      expect(map["group"], equals(0x001d));
      expect((map["key_exchange"] as Uint8List).length, equals(32));
    });

    // ------------------------------------------------------------
    // ✅ TEST 3 — ClientHello with TWO KeyShare entries
    // ------------------------------------------------------------
    test("Decode ClientHello containing multiple key shares", () {
      final data = Uint8List.fromList([
        0x00, 0x48, // total vector length = 72 bytes
        // Entry #1: X25519
        0x00, 0x1d, // group
        0x00, 0x20, // key length 32
        // key #1
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,

        // Entry #2: secp256r1
        0x00, 0x17, // group
        0x00, 0x20, // key length 32
        // key #2
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
      ]);

      final decoded = tls13Ext["KEY_SHARE"]!.decode!(data);

      expect(decoded, isA<List<Map<String, dynamic>>>());
      final list = decoded as List<Map<String, dynamic>>;

      expect(list.length, equals(2));

      // Entry #1: X25519
      expect(list[0]["group"], equals(0x001d));
      expect((list[0]["key_exchange"] as Uint8List).length, equals(32));

      // Entry #2: P‑256
      expect(list[1]["group"], equals(0x0017));
      expect((list[1]["key_exchange"] as Uint8List).length, equals(32));
    });
  });
}
