/**
 * General mega crypto port
 */

// string to array of 32-bit words (big endian)
module.exports.str_to_a32 = function (b) {
  var a = Array((b.length + 3) >> 2);
  for (var i = 0; i < b.length; i++) {
    a[i >> 2] |= (b.charCodeAt(i) << (24 - (i & 3) * 8));
  }
  return a;
};
