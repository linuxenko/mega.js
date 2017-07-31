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
    if (process.env['_mega']) {
      var obj = JSON.parse(process.env['_mega']);

      Object.keys(obj).map(function (key) {
        mega[key] = obj[key];
      });

      mega.seqno++;

      console.log('_restore');
      return done();
    }

    mega.login(process.env.USERNAME, process.env.USER_PASSWORD, function (err, response) {
      expect(err).to.be.not.exist;
      expect(mega.email).to.be.equal(process.env.USERNAME);
      expect(mega.sid.length).to.equal(58);

      process.env['_mega'] = JSON.stringify(mega);
      done();
    });
  });

  it('should retrieve list of files', function (done) {
    mega.getFiles(function (err, files) {
      expect(err).to.be.not.exist;

      done();
    });
  });

  it('should successfully get user info', function (done) {
    if (process.env['_skip_getuser']) {
      console.log('_skip');
      done();
      return;
    }
    expect(mega.sid).to.be.exist;
    expect(mega.email).to.be.equal(process.env.USERNAME);

    mega.getUser(function (err, info) {
      expect(err).to.be.not.exist;

      expect(info).to.be.an('array');
      expect(info[0].email).to.be.equal(process.env.USERNAME);
      process.env['_skip_getuser'] = true;
      done();
    });
  });
});
