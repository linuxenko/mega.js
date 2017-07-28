module.exports.randomstring = function (len) {
  len = len || 2 + Math.floor((Math.random() * 70));

  var bytes = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz';

  return Array.apply(null, Array(len)).map(function (_s, i) {
    return bytes.charAt(Math.floor(Math.random() * bytes.length));
  }).join('');
};
