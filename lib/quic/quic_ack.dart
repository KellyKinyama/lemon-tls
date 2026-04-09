// lib/quic_ack.dart
import 'dart:typed_data';

//
// =============================================================
// VarInt (RFC 9000 §16) – Minimal implementation
// =============================================================
Uint8List encodeVarInt(int v) {
  if (v < 0x40) {
    return Uint8List.fromList([v]);
  } else if (v < 0x4000) {
    return Uint8List.fromList([0x40 | (v >> 8), v & 0xff]);
  } else if (v < 0x4000_0000) {
    return Uint8List.fromList([
      0x80 | (v >> 24),
      (v >> 16) & 0xff,
      (v >> 8) & 0xff,
      v & 0xff,
    ]);
  } else {
    return Uint8List.fromList([
      0xC0 | (v >> 56),
      (v >> 48) & 0xff,
      (v >> 40) & 0xff,
      (v >> 32) & 0xff,
      (v >> 24) & 0xff,
      (v >> 16) & 0xff,
      (v >> 8) & 0xff,
      v & 0xff,
    ]);
  }
}

//
// =============================================================
// ACK Ranges
// =============================================================
class QuicAckRange {
  final int gap;
  final int rangeLength;

  QuicAckRange({required this.gap, required this.rangeLength});
}

//
// =============================================================
// ACK Frame with optional ECN support
// RFC 9000 §19.3
// =============================================================
class QuicAckFrame {
  final int largest;
  final int ackDelay;
  final int firstRange;
  final List<QuicAckRange> additionalRanges;

  // ✅ ECN counters
  final int? ect0;
  final int? ect1;
  final int? ce;

  QuicAckFrame({
    required this.largest,
    required this.ackDelay,
    required this.firstRange,
    required this.additionalRanges,
    this.ect0,
    this.ect1,
    this.ce,
  });

  bool get hasEcn => ect0 != null || ect1 != null || ce != null;

  Uint8List encode() {
    final out = BytesBuilder();

    // ✅ ACK type (0x02 = no ECN, 0x03 = ECN-enabled)
    out.addByte(hasEcn ? 0x03 : 0x02);

    out.add(encodeVarInt(largest));
    out.add(encodeVarInt(ackDelay));
    out.add(encodeVarInt(additionalRanges.length));
    out.add(encodeVarInt(firstRange));

    // Additional ranges (gap + length)
    for (final r in additionalRanges) {
      out.add(encodeVarInt(r.gap));
      out.add(encodeVarInt(r.rangeLength));
    }

    // ✅ Append ECN counts if present
    if (hasEcn) {
      out.add(encodeVarInt(ect0 ?? 0));
      out.add(encodeVarInt(ect1 ?? 0));
      out.add(encodeVarInt(ce ?? 0));
    }

    return out.toBytes();
  }
}

//
// =============================================================
// Build multi-range ACK from received PN set
// =============================================================
QuicAckFrame buildAckFromSet(
  Set<int> received, {
  int ackDelayMicros = 0,
  int? ect0,
  int? ect1,
  int? ce,
}) {
  if (received.isEmpty) {
    return QuicAckFrame(
      largest: 0,
      ackDelay: 0,
      firstRange: 0,
      additionalRanges: [],
      ect0: ect0,
      ect1: ect1,
      ce: ce,
    );
  }

  final sorted = received.toList()..sort();

  int largest = sorted.last;
  int idx = sorted.length - 1;

  int firstRangeLen = 0;

  // First range (largest continuous run downward)
  while (idx > 0 && (sorted[idx - 1] == sorted[idx] - 1)) {
    firstRangeLen++;
    idx--;
  }

  // Additional gap-based ranges
  List<QuicAckRange> ranges = [];
  int cursor = idx - 1;

  while (cursor >= 0) {
    int gap = sorted[cursor + 1] - sorted[cursor] - 1;
    if (gap < 0) gap = 0;

    int start = cursor;
    while (cursor > 0 && sorted[cursor - 1] == sorted[cursor] - 1) {
      cursor--;
    }

    int length = start - cursor;

    ranges.add(QuicAckRange(gap: gap, rangeLength: length));

    cursor--;
  }

  return QuicAckFrame(
    largest: largest,
    ackDelay: ackDelayMicros,
    firstRange: firstRangeLen,
    additionalRanges: ranges,
    ect0: ect0,
    ect1: ect1,
    ce: ce,
  );
}
