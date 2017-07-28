/**
 * General mega crypto port
 */

var sjcl = require('sjcl');
var Aes = sjcl.cipher.aes;

// string to array of 32-bit words (big endian)
var str2a32 = function (b) {
  var a = Array((b.length + 3) >> 2);
  for (var i = 0; i < b.length; i++) {
    a[i >> 2] |= (b.charCodeAt(i) << (24 - (i & 3) * 8));
  }
  return a;
};

// array of 32-bit words to string (big endian)
var a32tostr = function (a) {
  var b = '';

  for (var i = 0; i < a.length * 4; i++) {
    b = b + String.fromCharCode((a[i >> 2] >>> (24 - (i & 3) * 8)) & 255);
  }

  return b.replace(/\0/g, '');
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

  var enc = Array.apply(null, Array(Math.ceil(data.length / 3))).map(function (_s, i) {
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
  var o;
  var h;
  var bits;

  return Array.apply(null, Array(Math.ceil(data.length / 4))).map(function (_s, i) {
    h = Array.apply(null, Array(4)).map(function (_n, x) {
      return b64.indexOf(data.charAt(x + i * 4));
    });

    bits = h[0] << 18 | h[1] << 12 | h[2] << 6 | h[3];

    o = [(bits >> 16 & 0xff), (bits >> 8 & 0xff), (bits & 0xff)];

    return String.fromCharCode(o[0], o[1], o[2]);
  }).join('').replace(/\0/g, '');
};

module.exports.str_to_a32 = str2a32;
module.exports.a32_to_str = a32tostr;
module.exports.prepare_key = prepareKey;
module.exports.base64urlencode = base64urlencode;
module.exports.base64urldecode = base64urldecode;
