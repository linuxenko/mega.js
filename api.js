var crypt = require('./crypto');
var Aes = require('sjcl').cipher.aes;

var RSADecrypt = require('./crypto').RSADecrypt;

module.exports.login = function (email, password) {
  var pw = crypt.prepareKey(crypt.s2a(password));
  var uh = crypt.stringhash(email, new Aes(pw));

  return {
    'a': 'us',
    'user': email,
    'uh': uh
  };
};

module.exports.getUser = function () {
  return {
    'a': 'ug'
  };
};

module.exports.getFiles = function () {
  return {
    'a': 'f',
    'c': 1
  };
};

module.exports.decodeFileNames = function (files) {
  var master = this.key;

  return files.map(function (file) {
    if (file.t === 1 || file.t === 0) {
      var key = null;
      var sec = file.k.split(':');

      if (file['u'] === sec[0]) {
        var attributes = crypt.base64urldecode(file['a']);
        key = crypt.decryptKey(new Aes(master), crypt.base642a(sec[1]));
        attributes = crypt.decodeAttr(attributes, key);

        if (attributes.n) {
          file.name = attributes.n;
        }

        return file;
      }
    }

    return file;
  });
};

module.exports.getsid = function (data, password) {
  if (typeof data.k !== 'string') {
    throw new Error('Wrong data');
  }

  var master = crypt.base642a(data.k);
  var pwAes = new Aes(crypt.prepareKey(crypt.s2a(password)));
  var masterAes;

  if (master.length !== 4) {
    throw new Error('Wrong master key');
  }

  master = crypt.decryptKey(pwAes, master);
  masterAes = new Aes(master);

  if (typeof data.tsid === 'string') {
    throw new Error('Tsid auth not implemented');
  } else if (typeof data.csid === 'string') {
    var csid = crypt.base64urldecode(data.csid);
    var privk = null;

    try {
      privk = crypt.decodePrivateKey(crypt.a2s(crypt.decryptKey(masterAes, crypt.base642a(data.privk))));
    } catch (err) {
      throw new Error('Error docoding private RSA key!', err);
    }

    if (privk) {
      return {
        key: master,
        sid: crypt.base64urlencode(RSADecrypt(csid, privk).substr(0, 43)),
        privk: privk
      };
    }
  }

  return false;
};
