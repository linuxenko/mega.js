var crypt = require('./crypto');
var Aes = require('sjcl').cipher.aes;

module.exports.login = function (email, password) {
  var pw = crypt.prepareKey(crypt.s2a(password));
  var uh = crypt.stringhash(email, new Aes(pw));

  return {
    'a': 'us',
    'user': email,
    'uh': uh
  };
};
