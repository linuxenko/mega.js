var expect = require('chai').expect;
var Mega = require('../');

try {
  require('localenvify')('../.env', {});
} catch (err) {
  console.log('browser-run');
}

describe('Test Mega', function () {
  it('should create appropriate environment', function () {
    expect(process.env.USERNAME).to.be.exist;
    expect(process.env.USER_PASSWORD).to.be.exist;
  });

  it('should create mega credentials', function () {
    var m = new Mega('test', 'test');
    expect(m).to.be.exist;
    expect(m.seqno.length).to.be.equal(10);
  });

  it('should make request', function () {
    var m = new Mega(process.env.USERNAME, process.env.USER_PASSWORD);
    m.login();
  });
});