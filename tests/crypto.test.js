var expect = require('chai').expect;
var crypt = require('../crypto');

describe('Test crypto.js functions', function () {
  it('should create str_to_a32 arrays', function () {
    expect(crypt.str_to_a32('123')).deep.equal([ 825373440 ]);
    expect(crypt.str_to_a32('string')).deep.equal([ 1937011305, 1852243968 ]);
  });
});
