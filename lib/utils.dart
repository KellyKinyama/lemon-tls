import 'dart:convert';
import 'dart:typed_data';

Uint8List concatUint8Arrays(List<Uint8List> buffers) {
  final totalLength = buffers.fold<int>(0, (sum, buf) => sum + buf.length);
  final result = Uint8List(totalLength);
  int offset = 0;
  for (final buf in buffers) {
    result.setAll(offset, buf);
    offset += buf.length;
  }
  return result;
}

bool arraybufferEqual(List<int> buf1, Uint8List buf2) {
  //if (buf1 === buf2) {
  //return true;
  //}

  if (buf1.length != buf2.length) {
    return false;
  }

  // var view1 = new DataView(buf1);
  // var view2 = new DataView(buf2);

  for (var i = 0; i < buf1.length; i++) {
    if (buf1[i] != buf2[i]) {
      return false;
    }
  }

  return true;
}

// Simple list equality check for Uint8List
bool listEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

dynamic arraysEqual(List<int> a, List<int> b) {
  return listEquals(a, b);
  //if (a === b) return true;
  // if (a == null || b == null) return false;
  // if (a.length != b.length) return false;

  // // If you don't care about the order of the elements inside
  // // the array, you should sort both arrays here.
  // // Please note that calling sort on an array will modify that array.
  // // you might want to clone your array first.

  // for (var i = 0; i < a.length; ++i) {
  //   if(typeof a[i] != 'undefined' && typeof b[i] != 'undefined' && a[i]!=null && b[i]!=null && typeof a[i].byteLength == 'number' && typeof b[i].byteLength == 'number'){
  //     if(arraybufferEqual(a[i],b[i])==false){
  //       return false;
  //     }
  //   }else{
  //     if(typeof a[i]=='string' && typeof b[i]=='string'){
  //       if (a[i] != b[i]){
  //         return false;
  //       }
  //     }else if(a[i].constructor==RegExp && typeof b[i]=='string'){
  //       if(a[i].test(b[i])==false){
  //         return false;
  //       }
  //     }else if(typeof a[i]=='string' && b[i].constructor==RegExp){
  //       if(b[i].test(a[i])==false){
  //         return false;
  //       }
  //     //}else if(a[i] instanceof Object && b[i] instanceof Object && Object.keys(a[i]).length>0 && Object.keys(b[i]).length>0){
  //       //if(_this.objectEquals(a[i],b[i])==false){
  //       //	return false;
  //       //}
  //     }else{
  //       if (a[i] != b[i]){
  //         return false;
  //       }
  //     }

  //   }
  // }
  // return true;
}

/* =============================== Small utils ============================== */

Uint8List toU8(x) {
  if (x == null) return Uint8List(0);
  if (x is Uint8List) return x;
  if (x is String) return utf8.encode(x);
  return Uint8List(0);
}

/* ============================ Binary write helpers ============================ */
dynamic w_u8(buf, off, v) {
  buf[off++] = v & 0xFF;
  return off;
}

dynamic w_u16(buf, off, v) {
  buf[off++] = (v >>> 8) & 0xFF;
  buf[off++] = v & 0xFF;
  return off;
}

dynamic w_u24(buf, off, v) {
  buf[off++] = (v >>> 16) & 0xFF;
  buf[off++] = (v >>> 8) & 0xFF;
  buf[off++] = v & 0xFF;
  return off;
}

int w_bytes(Uint8List buf, int off, Uint8List b) {
  buf.setRange(off, off + buf.length, b);
  return off + b.length;
}

/* ============================ Binary read helpers ============================ */
(int, int) r_u8(Uint8List buf, int off) {
  return (buf[off] >> 0, off + 1);
}

(int, int) r_u16(Uint8List buf, int off) {
  var v = ((buf[off] << 8) | buf[off + 1]) >> 0;
  return (v, off + 2);
}

(int, int) r_u24(Uint8List buf, off) {
  // var v = ((buf[off] << 16) | (buf[off + 1] << 8) | buf[off + 2]) >> 0;
  var v = (buf[off] << 16) | (buf[off + 1] << 8) | buf[off + 2];
  return (v, off + 3);
}

(Uint8List, int) r_bytes(Uint8List buf, int off, int n) {
  Uint8List slice;
  if (buf is Uint8List || buf is List<int>) {
    // חיתוך אמיתי מתוך Uint8Array
    slice = buf.sublist(off, off + n);
    return (slice, off + n);
    // } else if (typeof Buffer != "undefined" && Buffer.isBuffer && Buffer.isBuffer(buf)) {
    //   // Node Buffer → slice מחזיר view, אז נעשה copy ל־Uint8Array
    //   var tmp = buf.slice(off, off + n);
    //   slice = Uint8List(tmp);
  } // else if (Array.isArray(buf)) {
  //   // מערך רגיל
  //   var tmp = buf.slice(off, off + n);
  //   slice = Uint8List(tmp);
  // }
  else {
    throw Exception("r_bytes: unsupported buffer type  ${buf.runtimeType})");
  }
  // return (slice.toList(), off + n);
}

/* ================================= Vectors ================================= */
dynamic veclen(int lenBytes, Uint8List inner) {
  var out, off = 0;

  if (lenBytes == 1) {
    out = new Uint8List(1 + inner.length);
    off = w_u8(out, off, inner.length);
    off = w_bytes(out, off, inner);
    return out;
  }

  if (lenBytes == 2) {
    out = Uint8List(2 + inner.length);
    off = w_u16(out, off, inner.length);
    off = w_bytes(out, off, inner);
    return out;
  }

  if (lenBytes == 3) {
    out = Uint8List(3 + inner.length);
    off = w_u24(out, off, inner.length);
    off = w_bytes(out, off, inner);
    return out;
  }

  throw Exception('veclen only supports 1/2/3');
}

dynamic readVec(Uint8List buf, int off, int lenBytes) {
  var n, off2 = off;

  if (lenBytes == 1) {
    (n, off2) = r_u8(buf, off2);
  } else if (lenBytes == 2) {
    (n, off2) = r_u16(buf, off2);
  } else {
    (n, off2) = r_u24(buf, off2);
  }

  var b;
  (b, off2) = r_bytes(buf, off2, n);
  return (b, off2);
}
