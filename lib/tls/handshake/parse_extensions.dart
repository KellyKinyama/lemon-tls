// import 'dart:typed_data';
// import 'handshake_common.dart';
// import 'ext_registry.dart';

// class ParsedExtension {
//   final int type;
//   final String name;
//   final Uint8List data;
//   final dynamic value;

//   ParsedExtension({
//     required this.type,
//     required this.name,
//     required this.data,
//     required this.value,
//   });
// }

// /// Dart translation of JS `parse_extensions(buf)`
// /// buf = Uint8List containing:  u16 length + repeated (type, length, data)
// List<ParsedExtension> parseExtensions(Uint8List buf) {
//   int off = 0;

//   // Read vec<u16> total length
//   final total = readU16(buf, off).item1;
//   off += 2;

//   final end = off + total;
//   final List<ParsedExtension> result = [];

//   while (off < end) {
//     // 1) Read extension type
//     final type = readU16(buf, off).item1;
//     off += 2;

//     // 2) Read extension payload length
//     final len = readU16(buf, off).item1;
//     off += 2;

//     // 3) Read payload bytes
//     final payload = readBytes(buf, off, len).item1;
//     off += len;

//     // 4) Resolve symbolic name
//     final name = extNameByCode(type);

//     // 5) Decode via registry if available
//     final decoder = exts[name]?.decode;
//     final value = decoder != null ? decoder(payload) : null;

//     result.add(
//       ParsedExtension(
//         type: type,
//         name: name,
//         data: payload,
//         value: value,
//       ),
//     );
//   }

//   return result;
// }