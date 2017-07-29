/* var randomstring = require('./tools').randomstring; */

var api = require('./api');
var request = require('superagent');

var Mega = function (email, password) {
  this.host = 'https://g.api.mega.co.nz/cs';
  this.seqno = -Math.ceil(Math.random() * 0x1000000000);
  this.sid = null;
  this.lang = 'en';

  this.email = email;
  this.password = password;
};

Mega.prototype.login = function (email, password, cb) {
  if (arguments.length > 1) {
    this.email = email;
    this.password = password;
  } else {
    cb = arguments[0] || function () {};
  }

  this.request(api.login(this.email, this.password), function (err, res) {
    if (err || !res.body || !res.body[0]) {
      return cb(err);
    }

    var ksid = null;

    try {
      ksid = this.getsid(res.body[0], this.password);
    } catch (err) {
      return cb(err);
    }

    this.sid = ksid.sid;
    this.privk = ksid.privk;
    this.key = ksid.key;
    cb(null, res.body);
  }.bind(this));
};

Mega.prototype.getUser = function (cb) {
  this.request(api.getUser(), function (err, res) {
    if (err) {
      return cb(err);
    }

    cb(null, res.body);
  });
};

Mega.prototype.request = function (cmd, cb) {
  var url = this.host +
    '?id=' + (this.seqno++) +
    '&lang=' + this.lang;

  if (this.sid) {
    url += '&sid=' + this.sid;
  }

  request
    .post(url)
    .type('json')
    .send([cmd])
    .end(cb);
};

Mega.prototype.getsid = api.getsid;

module.exports = Mega;
