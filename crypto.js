/**
 * General mega crypto port
 */

var range = require('./tools').range;
var randomstring = require('./tools').randomstring;

var sjcl = require('sjcl');
var Aes = sjcl.cipher.aes;

var rsaasm = require('./vendor/rsaasm');
var BigNumber = rsaasm.BigNumber;
var Modulus = rsaasm.Modulus;

// string to array of 32-bit words (big endian)
var s2a = function (b) {
  var a = Array((b.length + 3) >> 2);

  for (var i = 0; i < b.length; i++) {
    a[i >> 2] |= (b.charCodeAt(i) << (24 - (i & 3) * 8));
  }

  return a;
};

// array of 32-bit words to string (big endian)
var a2s = function (a) {
  var b = '';

  for (var i = 0; i < a.length * 4; i++) {
    b = b + String.fromCharCode((a[i >> 2] >>> (24 - (i & 3) * 8)) & 255);
  }

  return b;
};

// convert user-supplied password array
var prepareKey = function (a) {
  var i, j, r, key;
  var aes = [];
  var pkey = [0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56];

  for (j = 0; j < a.length; j += 4) {
    key = [0, 0, 0, 0];
    for (i = 0; i < 4; i++) {
      if (i + j < a.length) {
        key[i] = a[i + j];
      }
    }
    aes.push(new Aes(key));
  }

  for (r = 65536; r--;) {
    for (j = 0; j < aes.length; j++) {
      pkey = aes[j].encrypt(pkey);
    }
  }

  return pkey;
};

var b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=';
var b64a = b64.split('');

// substitute standard base64 special characters to prevent JSON escaping, remove padding
var base64urlencode = function (data) {
  var o;
  var h;
  var bits;

  var enc = range(Math.ceil(data.length / 3)).map(function (_s, i) {
    o = Array.apply(null, Array(3)).map(function (_n, x) {
      return data.charCodeAt(x + i * 3);
    });

    bits = o[0] << 16 | o[1] << 8 | o[2];
    h = [(bits >> 18 & 0x3f), (bits >> 12 & 0x3f), (bits >> 6 & 0x3f), (bits & 0x3f)];
    // use hexets to index into b64, and append result to encoded string
    return b64a[h[0]] + b64a[h[1]] + b64a[h[2]] + b64a[h[3]];
  }).join('');

  return (data.length % 3) ? enc.slice(0, (data.length % 3) - 3) : enc;
};

var base64urldecode = function (data) {
  data += '=='.substr((2 - data.length * 3) & 3);

  /*  // http://kevin.vanzonneveld.net
  // +   original by: Tyler Akins (http://rumkin.com)
  // +   improved by: Thunder.m
  // +      input by: Aman Gupta
  // +   improved by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
  // +   bugfixed by: Onno Marsman
  // +   bugfixed by: Pellentesque Malesuada
  // +   improved by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
  // +      input by: Brett Zamir (http://brett-zamir.me)
  // +   bugfixed by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
  // *     example 1: base64_decode('S2V2aW4gdmFuIFpvbm5ldmVsZA==');
  // *     returns 1: 'Kevin van Zonneveld'
  // mozilla has this native
  // - but breaks in 2.0.0.12!
  //if (typeof this.window['atob'] === 'function') {
  //    return atob(data);
  //} */
  //
  //
  var o1;
  var o2;
  var o3;
  var h1;
  var h2;
  var h3;
  var h4;
  var bits;
  var i = 0;
  var ac = 0;
  var dec = '';
  var tmpArr = [];

  if (!data) {
    return data;
  }

  data += '';

  do { // unpack four hexets into three octets using index points in b64
    h1 = b64.indexOf(data.charAt(i++));
    h2 = b64.indexOf(data.charAt(i++));
    h3 = b64.indexOf(data.charAt(i++));
    h4 = b64.indexOf(data.charAt(i++));

    bits = h1 << 18 | h2 << 12 | h3 << 6 | h4;

    o1 = bits >> 16 & 0xff;
    o2 = bits >> 8 & 0xff;
    o3 = bits & 0xff;

    if (h3 === 64) {
      tmpArr[ac++] = String.fromCharCode(o1);
    } else if (h4 === 64) {
      tmpArr[ac++] = String.fromCharCode(o1, o2);
    } else {
      tmpArr[ac++] = String.fromCharCode(o1, o2, o3);
    }
  } while (i < data.length);

  dec = tmpArr.join('');

  return dec;
};

var stringhash = function (s, aes) {
  var s32 = s2a(s);
  var h32 = [0, 0, 0, 0];
  var i;

  for (i = 0; i < s32.length; i++) {
    h32[i & 3] ^= s32[i];
  }

  for (i = 16384; i--;) {
    h32 = aes.encrypt(h32);
  }

  return a2base64([h32[0], h32[2]]);
};

var a2base64 = function (a) {
  return base64urlencode(a2s(a));
};

var base642a = function (b) {
  return s2a(base64urldecode(b));
};

var encodePrivateKey = function (privk) {
  var plen = privk[3].length * 8;
  var qlen = privk[4].length * 8;
  var dlen = privk[2].length * 8;
  var ulen = privk[7].length * 8;

  var t = String.fromCharCode(qlen / 256) + String.fromCharCode(qlen % 256) + privk[4] +
    String.fromCharCode(plen / 256) + String.fromCharCode(plen % 256) + privk[3] +
    String.fromCharCode(dlen / 256) + String.fromCharCode(dlen % 256) + privk[2] +
    String.fromCharCode(ulen / 256) + String.fromCharCode(ulen % 256) + privk[7];

  while (t.length & 15) t += String.fromCharCode(randomstring(256));

  return t;
};

var decodePrivateKey = function (privk) {
  var privkey = [];

  // decompose private key
  for (var i = 0; i < 4; i++) {
    if (privk.length < 2) {
      break;
    }

    var l = (privk.charCodeAt(0) * 256 + privk.charCodeAt(1) + 7) >> 3;
    if (l > privk.length - 2) {
      break;
    }

    privkey[i] = new BigNumber(privk.substr(2, l));
    privk = privk.substr(l + 2);
  }

  // check format
  if (i !== 4 || privk.length >= 16) {
    return false;
  }

  // restore privkey components via the known ones
  var q = privkey[0];
  var p = privkey[1];
  var d = privkey[2];
  var u = privkey[3];
  var q1 = q.subtract(1);
  var p1 = p.subtract(1);
  var m = new Modulus(p.multiply(q));
  var e = new Modulus(p1.multiply(q1)).inverse(d);
  var dp = d.divide(p1).remainder;
  var dq = d.divide(q1).remainder;

  privkey = [m, e, d, p, q, dp, dq, u];
  for (i = 0; i < privkey.length; i++) {
    privkey[i] = rsaasm.bytes_to_string(privkey[i].toBytes());
  }

  return privkey;
};

var decryptKey = function (cipher, a) {
  if (a.length === 4) {
    return cipher.decrypt(a);
  }

  var x = [];
  for (var i = 0; i < a.length; i += 4) {
    x = x.concat(cipher.decrypt([a[i], a[i + 1], a[i + 2], a[i + 3]]));
  }
  return x;
};

var encryptKey = function (cipher, a) {
  if (!a) {
    a = [];
  }
  if (a.length === 4) {
    return cipher.encrypt(a);
  }
  var x = [];
  for (var i = 0; i < a.length; i += 4) {
    x = x.concat(cipher.encrypt([a[i], a[i + 1], a[i + 2], a[i + 3]]));
  }
  return x;
};

/**
 * Decrypts a ciphertext string with the supplied private key.
 *
 * @param {String} ciphertext
 *     Cipher text to decrypt.
 * @param {Array} privkey
 *     Private encryption key (in the usual internal format used).
 * @return {String}
 *     Decrypted clear text or false in case of an error
 */
// decrypts ciphertext string representing an MPI-formatted big number with the supplied privkey
// returns cleartext string
var RSADecrypt = function (ciphertext, privkey) {
  var l = (ciphertext.charCodeAt(0) * 256 + ciphertext.charCodeAt(1) + 7) >> 3;
  ciphertext = ciphertext.substr(2, l);

  try {
    var cleartext = rsaasm.bytes_to_string(rsaasm.RSA_RAW.decrypt(ciphertext, privkey));
  } catch (err) {
    throw new Error('RSA decryption failed: ' + err);
  }

  if (cleartext.length < privkey[0].length) {
    cleartext = Array(privkey[0].length - cleartext.length + 1).join(String.fromCharCode(0)) + cleartext;
  }

  // Old bogus padding workaround
  if (cleartext.charCodeAt(1) !== 0) {
    cleartext = String.fromCharCode(0) + cleartext;
  }

  return cleartext.substr(2);
};

// array of 32-bit words ArrayBuffer (big endian)
var a32ToAb = function (a) {
  var ab = new Uint8Array(4 * a.length);

  for (var i = 0; i < a.length; i++) {
    ab[4 * i] = a[i] >>> 24;
    ab[4 * i + 1] = a[i] >>> 16 & 255;
    ab[4 * i + 2] = a[i] >>> 8 & 255;
    ab[4 * i + 3] = a[i] & 255;
  }

  return ab;
};

// ArrayBuffer to binary with depadding
var abToStrDepad = function (ab) {
  var b = '';
  var ab8 = new Uint8Array(ab);

  for (var i = 0; i < ab8.length && ab8[i]; i++) {
    b = b + String.fromCharCode(ab8[i]);
  }

  return b;
};

// binary string to ArrayBuffer, 0-padded to AES block size
var str2ab = function (b) {
  var ab = new ArrayBuffer((b.length + 15) & -16);
  var u8 = new Uint8Array(ab);

  for (var i = b.length; i--;) {
    u8[i] = b.charCodeAt(i);
  }

  return ab;
};

var from8 = function (utf8) {
  return decodeURIComponent(escape(utf8));
};

// binary string to ArrayBuffer, 0-padded to AES block size
var base642ab = function (a) {
  return str2ab(base64urldecode(a));
};

// decrypt attributes block using AES-CBC, check for MEGA canary
// attr = ab, key as with enc_attr
// returns [Object] or false
var decodeAttr = function (attr, key) {
  var b;

  attr = rsaasm.AES_CBC.decrypt(attr,
    a32ToAb([key[0] ^ key[4], key[1] ^ key[5], key[2] ^ key[6], key[3] ^ key[7]]), false);
  b = abToStrDepad(attr);

  if (b.substr(0, 6) !== 'MEGA{"') {
    return false;
  }

  try {
    return JSON.parse(from8(b.substr(4)));
  } catch (e) {
    var m = b.match(/"n"\s*:\s*"((?:\\"|.)*?)(\.\w{2,4})?"/);
    var s = m && m[1];
    var l = (s && s.length) || 0;
    var j = ',';

    while (l--) {
      s = s.substr(0, l || 1);
    }

    if (~l) {
      try {
        var name = s + j + 'trunc' + Math.random().toString(16).slice(-4) + (m[2] || '');
        return JSON.parse(from8(b.substr(4).replace(m[0], '"n":"' + name + '"')));
      } catch (e) {}
    }

    return {
      n: 'MALFORMED_ATTRIBUTES'
    };
  }
};

module.exports.s2a = s2a;
module.exports.a2s = a2s;
module.exports.stringhash = stringhash;
module.exports.a2base64 = a2base64;
module.exports.base642a = base642a;
module.exports.prepareKey = prepareKey;
module.exports.base64urlencode = base64urlencode;
module.exports.base64urldecode = base64urldecode;
module.exports.decryptKey = decryptKey;
module.exports.encryptKey = encryptKey;
module.exports.encodePrivateKey = encodePrivateKey;
module.exports.decodePrivateKey = decodePrivateKey;
module.exports.RSADecrypt = RSADecrypt;
module.exports.decodeAttr = decodeAttr;
module.exports.base642ab = base642ab;
