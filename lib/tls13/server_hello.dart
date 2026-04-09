import 'dart:typed_data';

import 'handshake_headers.dart';
import 'record_header.dart';

final Map<int, ClientHelloExtension Function(ByteReader)> extensionsMap = {
  EXTENSION_KEY_SHARE: (reader) {
    print("[DEBUG] Parsing KEY_SHARE extension with ${reader.remaining} bytes");
    return ServerHelloKeyShare.deserialize(reader);
  },
  EXTENSION_SUPPORTED_VERSIONS: (reader) {
    print(
      "[DEBUG] Parsing SUPPORTED_VERSIONS extension with ${reader.remaining} bytes",
    );
    return ExtensionSupportedVersions.deserializeByteReader(reader);
  },
  EXTENSION_PSK_KEY_EXCHANGE_MODES: (reader) {
    print(
      "[DEBUG] Parsing PSK_KEY_EXCHANGE_MODES extension with ${reader.remaining} bytes",
    );
    return ExtensionPSKKeyExchangeModes.deserializeByteReader(reader);
  },
};

class ByteReader {
  final Uint8List _data;
  int _off = 0;

  ByteReader(this._data) {
    print("[DEBUG] ByteReader created with ${_data.length} bytes");
  }

  int get remaining => _data.length - _off;

  Uint8List peek(int n) {
    print("[DEBUG] peek($n) at offset $_off remaining=$remaining");
    if (remaining < n) throw StateError('Need more data to peek $n bytes.');
    return _data.sublist(_off, _off + n);
  }

  Uint8List readBytes(int n) {
    print("[DEBUG] readBytes($n) at offset $_off remaining=$remaining");
    if (remaining < n)
      throw StateError('Need more data: wanted $n bytes, have $remaining.');
    final out = _data.sublist(_off, _off + n);
    _off += n;
    return out;
  }

  int readUint8() {
    final v = readBytes(1)[0];
    print("[DEBUG] readUint8 -> $v");
    return v;
  }

  int readInt8() {
    final v = readUint8();
    return v >= 0x80 ? v - 0x100 : v;
  }

  int readUint16be() {
    final bytes = readBytes(2);
    final value = ByteData.sublistView(bytes).getUint16(0, Endian.big);
    print("[DEBUG] readUint16be -> 0x${value.toRadixString(16)}");
    return value;
  }

  int readInt16be() {
    final bytes = readBytes(2);
    final value = ByteData.sublistView(bytes).getInt16(0, Endian.big);
    print("[DEBUG] readInt16be -> $value");
    return value;
  }
}

class ServerHello {
  final RecordHeader recordHeader;
  final HandshakeHeader handshakeHeader;
  final int serverVersion;
  final Uint8List serverRandom;
  final Uint8List sessionId;
  final int cipherSuite;
  final List<ClientHelloExtension> extensions;

  ServerHello({
    required this.recordHeader,
    required this.handshakeHeader,
    required this.serverVersion,
    required this.serverRandom,
    required this.sessionId,
    required this.cipherSuite,
    required this.extensions,
  });

  static ServerHello deserialize(ByteReader byteStream) {
    print("===== BEGIN ServerHello =====");

    final rh = RecordHeader.deserialize(byteStream.readBytes(5));
    print("[DEBUG] RecordHeader: type=${rh.rtype} size=${rh.size}");

    final hh = HandshakeHeader.deserialize(byteStream.readBytes(4));
    print("[DEBUG] HandshakeHeader: msgType=${hh.messageType} size=${hh.size}");

    final serverVersion = byteStream.readInt16be();
    print("[DEBUG] legacy_version = 0x${serverVersion.toRadixString(16)}");

    final serverRandom = byteStream.readBytes(32);
    print("[DEBUG] server_random = ${serverRandom}");

    final sessionIdLength = byteStream.readInt8();
    print("[DEBUG] session_id_length = $sessionIdLength");
    if (sessionIdLength < 0) {
      throw StateError('Invalid session_id_length: $sessionIdLength');
    }

    final sessionId = byteStream.readBytes(sessionIdLength);
    print("[DEBUG] session_id = $sessionId");

    final cipherSuite = byteStream.readInt16be();
    print("[DEBUG] cipher_suite = 0x${cipherSuite.toRadixString(16)}");

    final compression = byteStream.readUint8();
    print("[DEBUG] compression_method = $compression (should be 0)");

    var extensionsLength = byteStream.readUint16be();
    print("[DEBUG] extensions_total_length = $extensionsLength");

    final exts = <ClientHelloExtension>[];

    while (extensionsLength > 0) {
      print("---- Extension Block Remaining: $extensionsLength ----");

      final extType = byteStream.readUint16be();
      final extLen = byteStream.readUint16be();

      print(
        "[DEBUG] Extension type=0x${extType.toRadixString(16)} len=$extLen",
      );

      extensionsLength -= (4 + extLen);

      final extData = byteStream.readBytes(extLen);
      print("[DEBUG] Extension data bytes: $extData");

      final subReader = ByteReader(extData);

      final deserializer = extensionsMap[extType];
      if (deserializer != null) {
        print(
          "[DEBUG] Using registered deserializer for extType=0x${extType.toRadixString(16)}",
        );
        exts.add(deserializer(subReader));
      } else {
        print(
          "[DEBUG] No deserializer for extType=0x${extType.toRadixString(16)}, skipping",
        );
      }
    }

    print("===== END ServerHello =====");

    return ServerHello(
      recordHeader: rh,
      handshakeHeader: hh,
      serverVersion: serverVersion,
      serverRandom: serverRandom,
      sessionId: sessionId,
      cipherSuite: cipherSuite,
      extensions: exts,
    );
  }
}

// -----------------------------------------------------------
// SERVERHELLO KEY SHARE — Debug added, NO logic changes
// -----------------------------------------------------------
class ServerHelloKeyShare extends ClientHelloExtension {
  final int group;
  final Uint8List keyExchange;

  ServerHelloKeyShare({required this.group, required this.keyExchange})
    : super(EXTENSION_KEY_SHARE, keyExchange);

  static ServerHelloKeyShare deserialize(ByteReader r) {
    print("[DEBUG] ServerHelloKeyShare.deserialize starting");

    final group = r.readUint16be();
    final keyLen = r.readUint16be();

    print("[DEBUG] KeyShare group=0x${group.toRadixString(16)} keyLen=$keyLen");

    final keyExchange = r.readBytes(keyLen);

    print("[DEBUG] keyExchange bytes: $keyExchange");

    return ServerHelloKeyShare(group: group, keyExchange: keyExchange);
  }
}
