var expect = require('chai').expect;
var crypt = require('../crypto');
var randomstring = require('../tools').randomstring;

describe('Test crypto.js functions', function () {
  it('should create str_to_a32 arrays', function () {
    expect(crypt.s2a('123')).deep.equal([ 825373440 ]);
    expect(crypt.s2a('string')).deep.equal([ 1937011305, 1852243968 ]);
  });

  it('should pass a32 <-> str brute test', function () {
    for (var i = 1; i < 23; i++) {
      var s = randomstring(i);
      expect(crypt.a2s(crypt.s2a(s)).replace(/\0/g, '')).to.be.equal(s);
    }
  });

  it('should create prepareKey fn', function () {
    expect(crypt.prepareKey).to.be.a('function');
    expect(crypt.prepareKey(crypt.s2a('string'))).deep.equal(
      [ 620029680, 945057733, -2051893932, 299760322 ]);
  });

  it('should create base64urlencode fn', function () {
    expect(crypt.base64urlencode('longstring')).to.be.equal('bG9uZ3N0cmluZw');
    expect(crypt.base64urlencode('a')).to.be.equal('YQ');
    expect(crypt.base64urlencode('string')).to.be.equal('c3RyaW5n');
  });

  it('should create base64decode fn', function () {
    expect(crypt.base64urldecode('bG9uZ3N0cmluZw')).to.be.equal('longstring');
  });

  it('should base64* fns pass brute test', function () {
    for (var i = 1; i < 40; i++) {
      var s = randomstring(i);
      expect(crypt.base64urldecode(crypt.base64urlencode(s))).to.be.equal(s);
    }
    var btest = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=+*#$@!&*(&#?^%#.,~"\'';
    expect(crypt.base64urldecode(crypt.base64urlencode(btest))).to.be.equal(btest);
  });
});
