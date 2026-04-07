import "dart:convert";
import "dart:io";
import "dart:typed_data";

import 'package:basic_utils/basic_utils.dart';
// import fs from 'node:fs';
// import path from 'node:path';
// import
import "cert_utils.dart";
//crypto from 'node:crypto';

// dynamic looksLikePath(x) {
//   return typeof x === 'string' && (x.indexOf('\n') === -1) && (x.length < 4096) &&
//          (x.indexOf('-----BEGIN') === -1);
// }

dynamic readMaybeFile(x) {
  // if (x == null) return null;
  // if (looksLikePath(x)) return fs.readFileSync(path.resolve(String(x)));
  // if (Buffer.isBuffer(x)) return x;
  // if (x instanceof Uint8Array) return Buffer.from(x);
  // if (typeof x === 'string') return Buffer.from(x, 'utf8');
  // throw new Error('Unsupported input type (expected path/string/Buffer/Uint8Array).');
  File file = File(x);
  return file.readAsBytesSync();
}

bool isPEM(String pem) {
  var startsWith = [
    '-----BEGIN PUBLIC KEY-----',
    '-----BEGIN PRIVATE KEY-----',
    '-----BEGIN CERTIFICATE-----',
    '-----BEGIN EC PRIVATE KEY-----',
  ];

  for (var s in startsWith) {
    return (pem.startsWith(s) == true);
  }
  return false;
}

dynamic splitPEMBlocks(String pemText) {
  return decodePemToDer(pemText);
}

dynamic ensureArray(x) {
  return x == null ? [] : ((x is List || x is Uint8List) ? x : [x]);
}

dynamic normalizeCA(caOption) {
  var arr = ensureArray(caOption);
  var ders = [];
  for (var i = 0; i < arr.length; i++) {
    var raw = readMaybeFile(arr[i]);
    if (!raw) continue;
    if (isPEM(raw)) {
      var blocks = splitPEMBlocks(raw.toString('utf8'));
      for (var j = 0; j < blocks.length; j++) {
        if (blocks[j].type.indexOf('CERTIFICATE') != -1)
          ders.add(blocks[j].der);
      }
    } else {
      ders.add(Uint8List.fromList(raw));
    }
  }
  return ders;
}

dynamic makeX509FromDerOrPem(pem) {
  // return new crypto.X509Certificate(Buffer.from(buf));

  final out = X509Utils.x509CertificateFromPem(base64.encode(pem));
  return out;
}

dynamic makePrivateKeyFromDerOrPem(buf, passphrase) {
  if (isPEM(buf)) {
    return (encodeECPrivateKeyToRaw(CryptoUtils.ecPrivateKeyFromPem(buf)));
    // return crypto.createPrivateKey({ key: buf, format: 'pem', passphrase: passphrase });
  } else {
    // var der = Buffer.from(buf), keyObj = null;

    return (encodeECPrivateKeyToRaw(CryptoUtils.ecPrivateKeyFromDerBytes(buf)));
    // try {
    //   keyObj = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8', passphrase: passphrase });
    // } catch (e1) {
    //   try {
    //     keyObj = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs1', passphrase: passphrase });
    //   } catch (e2) {
    //     keyObj = crypto.createPrivateKey({ key: der, format: 'der', type: 'sec1', passphrase: passphrase });
    //   }
    // }
    // return keyObj;
  }
}

dynamic exportKeyPkcs8Der(keyObj) {
  return CryptoUtils.encodePrivateEcdsaKeyToPkcs8(keyObj);
  // return Uint8List.fromList(keyObj.export(format: 'der', type: 'pkcs8' ));
}

dynamic u8eq(a, b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) if (a[i] != b[i]) return false;
  return true;
}

dynamic dedupeDerArray(arr) {
  var out = [];
  for (var i = 0; i < arr.length; i++) {
    var keep = true;
    for (var j = 0; j < out.length; j++) {
      if (u8eq(arr[i], out[j])) {
        keep = false;
        break;
      }
    }
    if (keep) out.add(arr[i]);
  }
  return out;
}

/**
 * createSecureContext(options)
 * key/cert/ca יכולים להיות: path | Buffer | Uint8Array | string(PEM)
 * מחזיר:
 *  - certificateChain: [{ cert: Uint8Array }, ...]  // leaf תחילה, אח"כ intermediates
 *  - privateKey: Uint8Array                          // PKCS#8 DER
 *  - ca: Uint8Array[]                                // Trust store (לא משולח ללקוח)
 *  - ocsp: Uint8Array|null
 *  - ticketKeys: Uint8Array|null
 *  - certObjs, keyObj (עזרי debug/לוגיקה)
 */
dynamic createSecureContext(options) {
  if (!options) options = {};

  // --- תעודות (כולל שרשרת בתוך cert אם קיימת) ---
  var certBlocksDer = [];
  var certObjs = [];
  if (options.cert != null) {
    var cRaw = readMaybeFile(options.cert);
    if (isPEM(cRaw)) {
      var blocks = splitPEMBlocks(cRaw.toString('utf8'));
      for (var i = 0; i < blocks.length; i++) {
        if (blocks[i].type.indexOf('CERTIFICATE') != -1) {
          certBlocksDer.add(blocks[i].der);
          certObjs.add(makeX509FromDerOrPem(blocks[i].der));
        }
      }
    } else {
      var der = Uint8List.fromList(cRaw);
      certBlocksDer.add(der);
      certObjs.add(makeX509FromDerOrPem(der));
    }
  }

  // --- מפתח פרטי ---
  var keyObj = null;
  var privateKey = null;
  if (options.key != null) {
    var kRaw = readMaybeFile(options.key);
    keyObj = makePrivateKeyFromDerOrPem(kRaw, options.passphrase);
    privateKey = exportKeyPkcs8Der(keyObj);
  }

  // אימות בסיסי (כאשר לא משתמשים ב־PFX)
  if (!options.pfx) {
    if (certBlocksDer.length == 0)
      throw Exception('createSecureContext: missing cert.');
    if (!privateKey)
      throw Exception('createSecureContext: missing private key.');
  }

  // --- CA (Trust store) ---
  var ca = normalizeCA(options.ca);

  // --- OCSP stapling (אופציונלי) ---
  var ocsp = null;
  if (options.ocsp != null)
    ocsp = Uint8List.fromList(readMaybeFile(options.ocsp));

  // --- Ticket keys (אופציונלי) ---
  var ticketKeys = null;
  if (options.ticketKeys != null)
    ticketKeys = Uint8List.fromList(readMaybeFile(options.ticketKeys));
  // אפשרות: ליצור מפתחי ברירת מחדל כאן אם תרצה

  // --- בניית שרשרת לשיגור ללקוח (leaf → intermediates) ---
  var chainDer = dedupeDerArray(certBlocksDer);
  var certificateChain = [];
  for (var c = 0; c < chainDer.length; c++) {
    certificateChain.add((cert: chainDer[c]));
  }

  // מידע עזר לזיהוי סוג המפתח הציבורי של ה-leaf
  var leafPublicKeyType = null;
  if (certObjs.length > 0 && certObjs[0].publicKey) {
    try {
      leafPublicKeyType = certObjs[0].publicKey.asymmetricKeyType;
    } catch (e) {
      leafPublicKeyType = null;
    }
  }

  return (
    // חומר לשכבת ההנדשייק/רקורד:
    certificateChain: certificateChain, // [{ cert: DER(Uint8Array) }, ...]
    privateKey: privateKey, // PKCS#8 DER (Uint8Array)
    ca: ca, // Trust store (DER)
    ocsp: ocsp, // DER (אם הוגדר)
    ticketKeys: ticketKeys, // Uint8Array (אם הוגדר)
    // עזרי debug/לוגיקה:
    certObjs: certObjs, // [X509Certificate...]
    keyObj: keyObj, // KeyObject
    leafPublicKeyType: leafPublicKeyType,

    // פרמטרים פרוטוקוליים (אחסון; אתה מפרש בזמן ה-handshake):
    minVersion: options.minVersion ?? 'TLSv1.2',
    maxVersion: options.maxVersion ?? 'TLSv1.3',
    ciphers: options.ciphers ?? null,
    sigalgs: options.sigalgs ?? null,
    ecdhCurve: options.ecdhCurve ?? null,
    honorCipherOrder: !!options.honorCipherOrder,

    // תמיכה ב־PFX אם תרצה לטפל בזה בשכבה אחרת:
    pfx: options.pfx ? Uint8List.fromList(readMaybeFile(options.pfx)) : null,
    passphrase: options.passphrase ? options.passphrase : null,
  );
}

// export default createSecureContext;
