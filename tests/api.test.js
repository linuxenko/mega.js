var expect = require('chai').expect;
var Mega = require('../');

describe('Test Mega', function () {
  this.timeout(20000);

  it('should decrypt sid', function () {
    var m = new Mega(process.env.USERNAME, process.env.USER_PASSWORD);
    var res = m.getsid({csid: 'CACGlDC_WZyH3GlK0kadzaDWKlF_10aEZ840mDF7snX4oGCs4OC5RUN1xjeKV8CDS-H-2KoifCHnhLsTmm5n9e0YnYz-07lFCkk7MNIFADRChSj9815f1C_YTJ8GHVu2lmA0wz1TssY8tBfMrY2MOJYwjTZrX1xvs4nBbQaB3yPUkPcq2K6OQ7J28Ke5p6F0X9JkxzIobktyY8HTH26yxGsKhYIYSJjS03_Q7yW4-1s3GwdlTnUYe3KVxBUHAjwchpyFielkhjNe6kHWiMmpF2nn1191Hu1ymp7GY0bSYmpADSEewJ6vggJLcjgPet7-TEmeo8Xrn1egU1_uvDGt3foJ', privk: 'fY6lMQoLrY1y1tcQ5gMp-e5YiQEPPYXYdWRRkR4oFaxgUt1jmD2_IaKGt5UhVVOoJWqynoQVOa9AuRR8zwxPMxCDiFJSx5snpKNi61RzFJmaeTj9hkQmsOCdX0epySKRizBZCTB8H7F0tHOZ_VrhsRBeJtioke-cPNnnc2uA5nutTBaxQwKwhegd72qdziGisWTF5rFViBAsiP0SO2KLaFv69PDp8i-wKJX67b6twWgDagKQObvqjtUrdxnARbWZ-KrsmheOr-NcXy0TcUhstRiY-qy75kZxk6jgH7ncwXAy9qyYXVf7_upQc7pgGUCe-0ERmi7i1yXg2cXqcQ6qwwXbQ6NV6cUi9nQM92tVLKhX263dUMP1KqbEiaiA-gfZBTCKwPt-HfhY8LzMCghqtdgScs2KgD4UqVPVmVya-7fS8WBzElhC5HYkhMVnKEZdd2uGehazRW-wEQN1XToa8_mRKos3Z7uGFIEIsEeFbh6k0Z_AG9XCJfkztOZ0qVIG4BTFZ78_wRI-blqJsE12Ug9P0zY_JJW5F9T8Nxr5P_H9dIwCUQbV5f_lA4NcJe_oTbM3TANukjzkSpdgT34tDbn1KpIzHLAV0Eqnf9uSc8i5LYXkaeHXditxaa4xt3GvotDWcdjWf5hFiNa-ObekVe64oAVlcPlsHRGUjNr9OcWsNhrz54v3MVvJzmjfBUB_wLeXLX9dbkqNvkRI1QOJyIJzl9dHHdEbwk8Ijq7a_BtUlavL0aN0F0CjmRDgHcoJ2t9UUFMufdzQCPNMMVFmrg_nseRL_lvlmIvgjcxKIdaIycZM4XhBRAmW0w701vQNqe84NAyvF-GbAFTNBQcnrkQjFFcYgtPlM04cRFddV_g', k: 'XpUnZo43jzNNlhVC6Y-0Bw', u: 'OwdK5L5I1zI'}, process.env.USER_PASSWORD);

    expect(res.key.length).to.be.equal(4);
    expect(res.sid.length).to.be.equal(58);
    expect(res.privk.length).to.be.equal(8);
  });
});
