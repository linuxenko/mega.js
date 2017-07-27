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

module.exports.str_to_a32 = str2a32;
module.exports.prepare_key = prepareKey;
