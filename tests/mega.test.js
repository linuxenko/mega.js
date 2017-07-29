var expect = require('chai').expect;
var Mega = require('../');

try {
  require('localenvify')('../.env', {});
} catch (err) {
  console.log('browser-run');
}

var mega = new Mega();

describe('Test Mega', function () {
  this.timeout(20000);

  it('should create appropriate environment', function () {
    expect(process.env.USERNAME).to.be.a('string');
    expect(process.env.USER_PASSWORD).to.be.a('string');
  });

  it('should create mega credentials', function () {
    expect(mega).to.be.exist;
    expect(mega.seqno).to.be.a('number');
    expect(mega.email).not.to.be.exist;
    expect(mega.password).not.to.be.exist;
  });

  it('should successfully log user in', function (done) {
    mega.login(process.env.USERNAME, process.env.USER_PASSWORD, function (err, response) {
      expect(err).to.be.not.exist;
      expect(mega.email).to.be.equal(process.env.USERNAME);
      expect(mega.sid.length).to.equal(58);
      done();
    });
  });

  it('should successfully get user info', function (done) {
    expect(mega.sid).to.be.exist;
    expect(mega.email).to.be.equal(process.env.USERNAME);

    mega.getUser(function (err, info) {
      expect(err).to.be.not.exist;

      expect(info).to.be.an('array');
      expect(info[0].email).to.be.equal(process.env.USERNAME);
      done();
    });
  });
});
