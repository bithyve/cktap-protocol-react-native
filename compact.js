var RIPEMD160 = require('ripemd160');
var sha256 = require('js-sha256');

function ripemd160(args = '') {
  return new RIPEMD160().update(args).digest('hex');
}

function hash160(args) {
  return ripemd160(sha256(args));
}

module.exports = hash160;
