// // ============================================================================
// // tls_client_key_exchange.dart
// // TLS 1.2 ClientKeyExchange (ECDHE + RSA) builder & parser
// // Direct Dart translation of original JavaScript code
// // ============================================================================

// import 'dart:typed_data';

// import 'tls_utils.dart';
// import 'tls_vectors.dart';
// import 'tls_read.dart';

// /// ---------------------------------------------------------------------------
// /// buildClientKeyExchangeECDHE(pubkey)
// ///
// /// JS equivalent:
// ///   function build_client_key_exchange_ecdhe(pubkey) {
// ///       var p = toU8(pubkey||u8(0));
// ///       return veclen(1, p);
// ///   }
// ///
// /// Struct:
// ///   opaque ec_point<1..2^8-1>;
// /// ---------------------------------------------------------------------------
// Uint8List buildClientKeyExchangeECDHE(dynamic pubkey) {
//   final Uint8List p = toU8(pubkey ?? u8(0));
//   return veclen(1, p);
// }

// /// ---------------------------------------------------------------------------
// /// parseClientKeyExchangeECDHE(body)
// ///
// /// JS equivalent:
// ///   function parse_client_key_exchange_ecdhe(body) {
// ///       var off=0; var v; [v,off]=readVec(body,0,1); return v;
// ///   }
// ///
// /// Returns just the ec_point as Uint8List
// /// ---------------------------------------------------------------------------
// Uint8List parseClientKeyExchangeECDHE(Uint8List body) {
//   final r = readVec(body, 0, 1);
//   return r[0] as Uint8List;
// }

// /// ---------------------------------------------------------------------------
// /// buildClientKeyExchangeRSA(encPMS)
// ///
// /// JS equivalent:
// ///   function build_client_key_exchange_rsa(enc_pms) {
// ///       var e = toU8(enc_pms||u8(0));
// ///       return veclen(2, e);
// ///   }
// ///
// /// Struct:
// ///   EncryptedPreMasterSecret opaque<2>;
// /// ---------------------------------------------------------------------------
// Uint8List buildClientKeyExchangeRSA(dynamic encPms) {
//   final Uint8List e = toU8(encPms ?? u8(0));
//   return veclen(2, e);
// }

// /// ---------------------------------------------------------------------------
// /// parseClientKeyExchangeRSA(body)
// ///
// /// JS equivalent:
// ///   function parse_client_key_exchange_rsa(body) {
// ///       var off=0; var v; [v,off]=readVec(body,0,2); return v;
// ///   }
// ///
// /// Returns the encrypted PMS
// /// ---------------------------------------------------------------------------
// Uint8List parseClientKeyExchangeRSA(Uint8List body) {
//   final r = readVec(body, 0, 2);
//   return r[0] as Uint8List;
// }