var range = function (len) {
  return Array.apply(null, Array(len));
};

module.exports.randomstring = function (len) {
  len = len || 2 + Math.floor((Math.random() * 70));

  var bytes = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz';

  return range(len).map(function () {
    return bytes.charAt(Math.floor(Math.random() * bytes.length));
  }).join('');
};

module.exports.range = range;
