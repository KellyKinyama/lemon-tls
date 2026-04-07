// ============================================================================
// tls_new_session_ticket.dart
// TLS 1.3 NewSessionTicket builder & parser
// Direct Dart translation of:
//   build_new_session_ticket()
//   parse_new_session_ticket()
// ============================================================================

import 'dart:typed_data';

import 'tls_utils.dart';
import 'tls_write.dart';
import 'tls_read.dart';
import 'tls_extensions.dart';

/// ---------------------------------------------------------------------------
/// Build TLS 1.3 NewSessionTicket
///
/// struct {
///   uint32 ticket_lifetime;
///   uint32 ticket_age_add;
///   opaque ticket_nonce<0..2^8-1>;
///   opaque ticket<1..2^16-1>;
///   Extension extensions<0..2^16-1>;
/// } NewSessionTicket;
/// ---------------------------------------------------------------------------
Uint8List buildNewSessionTicket(Map<String, dynamic> p) {
  final int lifetime = (p['ticket_lifetime'] ?? 0) & 0xFFFFFFFF;
  final int ageAdd = (p['ticket_age_add'] ?? 0) & 0xFFFFFFFF;

  final Uint8List nonce =
      toU8(p['ticket_nonce'] ?? Uint8List(0));

  final Uint8List ticket =
      toU8(p['ticket'] ?? Uint8List(0));

  final Uint8List extsBuf =
      (p['extensions'] is List)
          ? buildExtensions(p['extensions'])
          : (p['extensions'] is Uint8List
              ? p['extensions']
              : buildExtensions([]));

  final out = Uint8List(
    4 +                      // ticket_lifetime
    4 +                      // ticket_age_add
    1 + nonce.length +       // nonce
    2 + ticket.length +      // ticket
    extsBuf.length           // extensions
  );

  int off = 0;

  // ticket_lifetime (u32)
  off = w_u8(out, off, (lifetime >> 24) & 0xFF);
  off = w_u8(out, off, (lifetime >> 16) & 0xFF);
  off = w_u8(out, off, (lifetime >> 8) & 0xFF);
  off = w_u8(out, off, lifetime & 0xFF);

  // ticket_age_add (u32)
  off = w_u8(out, off, (ageAdd >> 24) & 0xFF);
  off = w_u8(out, off, (ageAdd >> 16) & 0xFF);
  off = w_u8(out, off, (ageAdd >> 8) & 0xFF);
  off = w_u8(out, off, ageAdd & 0xFF);

  // nonce
  off = w_u8(out, off, nonce.length);
  off = w_bytes(out, off, nonce);

  // ticket (vec<2>)
  off = w_u16(out, off, ticket.length);
  off = w_bytes(out, off, ticket);

  // extensions
  off = w_bytes(out, off, extsBuf);

  return out;
}

/// ---------------------------------------------------------------------------
/// Parse TLS 1.3 NewSessionTicket
///
/// Returns:
/// {
///   ticket_lifetime: int,
///   ticket_age_add: int,
///   ticket_nonce: Uint8List,
///   ticket: Uint8List,
///   extensions: List<ext objects>
/// }
/// ---------------------------------------------------------------------------
Map<String, dynamic> parseNewSessionTicket(Uint8List body) {
  int off = 0;

  // ticket_lifetime
  final lifetime =
      ((body[off] << 24) |
       (body[off + 1] << 16) |
       (body[off + 2] << 8) |
        body[off + 3]) &
      0xFFFFFFFF;
  off += 4;

  // ticket_age_add
  final ageAdd =
      ((body[off] << 24) |
       (body[off + 1] << 16) |
       (body[off + 2] << 8) |
        body[off + 3]) &
      0xFFFFFFFF;
  off += 4;

  // nonce
  final r1 = r_u8(body, off);
  final nlen = r1[0];
  off = r1[1];

  final r2 = r_bytes(body, off, nlen);
  final Uint8List nonce = r2[0];
  off = r2[1];

  // ticket
  final r3 = r_u16(body, off);
  final tlen = r3[0];
  off = r3[1];

  final r4 = r_bytes(body, off, tlen);
  final Uint8List ticket = r4[0];
  off = r4[1];

  // extensions
  final Uint8List extBuf =
      (off < body.length) ? body.sublist(off) : Uint8List(0);

  final exts =
      extBuf.isNotEmpty ? parseExtensions(extBuf) : [];

  return {
    'ticket_lifetime': lifetime,
    'ticket_age_add': ageAdd,
    'ticket_nonce': nonce,
    'ticket': ticket,
    'extensions': exts,
  };
}