/* var randomstring = require('./tools').randomstring; */

var api = require('./api');
var request = require('superagent');

var Mega = function (email, password) {
  this.host = 'https://g.api.mega.co.nz/cs';
  this.seqno = String(Math.ceil(Math.random() * 0x1000000000)).substr(0, 10);
  this.sid = null;
  this.lang = 'en';

  this.email = email;
  this.password = password;
};

Mega.prototype.login = function (email, password, cb) {
  if (arguments.length > 1) {
    this.email = email;
    this.password = password;
  }

  this.request(api.login(this.email, this.password), function (err, res) {
    if (err) {
      cb(err, null);
    }
    console.log(res.body[0].csid);
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

module.exports = Mega;
