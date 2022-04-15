var cbor = require('cbor');

function encodeNfcData(obj) {
  return cbor.encode(obj);
}
function decodeNfcData(obj) {
  return cbor.decode(obj);
}

module.exports = {
  encodeNfcData,
  decodeNfcData,
};
