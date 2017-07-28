/**
 * General mega crypto port
 */

var range = require('./tools').range;
var sjcl = require('sjcl');
var Aes = sjcl.cipher.aes;

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
  var o;
  var h;
  var bits;

  return range(Math.ceil(data.length / 4)).map(function (_s, i) {
    h = range(4).map(function (_n, x) {
      return b64.indexOf(data.charAt(x + i * 4));
    });

    bits = h[0] << 18 | h[1] << 12 | h[2] << 6 | h[3];

    o = [(bits >> 16 & 0xff), (bits >> 8 & 0xff), (bits & 0xff)];

    return String.fromCharCode(o[0], o[1], o[2]);
  }).join('').replace(/\0/g, '');
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

module.exports.s2a = s2a;
module.exports.a2s = a2s;
module.exports.stringhash = stringhash;
module.exports.a2base64 = a2base64;
module.exports.prepareKey = prepareKey;
module.exports.base64urlencode = base64urlencode;
module.exports.base64urldecode = base64urldecode;
