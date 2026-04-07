import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:lemon_tls/tls2/tls_extensions.dart';
import 'package:lemon_tls/tls2/tls_constants.dart';

void main() {
  group("TLS Extension Encoding/Decoding", () {
    setUp(() {
      initTls13Extensions(); // REQUIRED
    });

    // ===============================================================
    // ✅ SUPPORTED_GROUPS
    // ===============================================================
    test("SUPPORTED_GROUPS encode/decode", () {
      final groups = [0x001D, 0x0017];

      final encoded = tls13Ext["SUPPORTED_GROUPS"]!.encode!(groups);

      // expected encoding:
      //   length = 4 bytes => 0x0004
      //   groups: 0x001D, 0x0017
      final expected = Uint8List.fromList([0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);
      expect(encoded, expected);

      final decoded = tls13Ext["SUPPORTED_GROUPS"]!.decode!(encoded);
      expect(decoded, groups);
    });

    // ===============================================================
    // ✅ SUPPORTED_VERSIONS (ClientHello + ServerHello)
    // ===============================================================
    test("SUPPORTED_VERSIONS ServerHello decode", () {
      final data = Uint8List.fromList([0x03, 0x04]); // TLS 1.3
      final decoded = tls13Ext["SUPPORTED_VERSIONS"]!.decode!(data);
      expect(decoded, TLSVersion.TLS1_3);
    });

    test("SUPPORTED_VERSIONS ClientHello decode", () {
      final data = Uint8List.fromList([
        0x04, // list length = 4 bytes
        0x03, 0x03, // TLS 1.2
        0x03, 0x04, // TLS 1.3
      ]);
      final decoded = tls13Ext["SUPPORTED_VERSIONS"]!.decode!(data);
      expect(decoded, [TLSVersion.TLS1_2, TLSVersion.TLS1_3]);
    });

    // ===============================================================
    // ✅ SIGNATURE_ALGORITHMS
    // ===============================================================
    test("SIGNATURE_ALGORITHMS encode/decode", () {
      final algs = [0x0403, 0x0804];

      final encoded = tls13Ext["SIGNATURE_ALGORITHMS"]!.encode!(algs);

      final expected = Uint8List.fromList([0x00, 0x04, 0x04, 0x03, 0x08, 0x04]);
      expect(encoded, expected);

      final decoded = tls13Ext["SIGNATURE_ALGORITHMS"]!.decode!(encoded);
      expect(decoded, algs);
    });

    // ===============================================================
    // ✅ PSK KEY EXCHANGE MODES
    // ===============================================================
    test("PSK_KEY_EXCHANGE_MODES encode/decode", () {
      final modes = [1]; // psk_dhe_ke

      final encoded = tls13Ext["PSK_KEY_EXCHANGE_MODES"]!.encode!(modes);

      expect(encoded, Uint8List.fromList([0x01, 0x01]));

      final decoded = tls13Ext["PSK_KEY_EXCHANGE_MODES"]!.decode!(encoded);
      expect(decoded, modes);
    });

    // ===============================================================
    // ✅ ALPN
    // ===============================================================
    test("ALPN encode/decode", () {
      final protocols = ["h2", "http/1.1"];

      final encoded = tls13Ext["ALPN"]!.encode!(protocols);

      final decoded = tls13Ext["ALPN"]!.decode!(encoded);

      expect(decoded, protocols);
    });

    // ===============================================================
    // ✅ COOKIE (HelloRetryRequest)
    // ===============================================================
    test("COOKIE encode/decode", () {
      final cookie = Uint8List.fromList([1, 2, 3, 4, 5]);

      final encoded = tls13Ext["COOKIE"]!.encode!(cookie);
      final decoded = tls13Ext["COOKIE"]!.decode!(encoded);

      expect(decoded, cookie);
    });

    // ===============================================================
    // ✅ Round-trip extension list (buildExtensions ↔ parseExtensions)
    // ===============================================================
    test("Extension list round-trip", () {
      final list = [
        {
          "type": TLSExt.SUPPORTED_GROUPS,
          "value": [0x001D, 0x0017],
        },
        {
          "type": TLSExt.SIGNATURE_ALGORITHMS,
          "value": [0x0403],
        },
        {
          "type": TLSExt.PSK_KEY_EXCHANGE_MODES,
          "value": [1],
        },
      ];

      final encoded = buildExtensions(list);
      final decodedList = parseExtensions(encoded);

      expect(decodedList.length, equals(3));

      // Check the decoder returned correct values
      expect(decodedList[0]["type"], equals(TLSExt.SUPPORTED_GROUPS));
      expect(decodedList[0]["value"], equals([0x001D, 0x0017]));

      expect(decodedList[1]["type"], equals(TLSExt.SIGNATURE_ALGORITHMS));
      expect(decodedList[1]["value"], equals([0x0403]));

      expect(decodedList[2]["type"], equals(TLSExt.PSK_KEY_EXCHANGE_MODES));
      expect(decodedList[2]["value"], equals([1]));
    });
  });
}
