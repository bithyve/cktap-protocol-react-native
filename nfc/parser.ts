const CBOR = require('@ellipticoin/cbor');

// transceive data format: CLA, INS, P1, P2, Data Len, Data (bytes array)
export const cborEncode = (obj: object) => {
  const data = CBOR.encode(obj);
  const parsed = JSON.parse(JSON.stringify(data)).data;
  return [0x00, 0xcb, 0x00, 0x00, parsed.length].concat(parsed);
};

export const decodeAndSplitResponse = (r: number[]) => {
  return {
    response: CBOR.decode(Buffer.from(r)),
    status: bytesToHex(Buffer.from(r.slice(r.length - 2))),
  };
};

// Convert a byte array or Buffer to a hex string
export const bytesToHex = (bytes: Buffer) => {
  try {
    for (var hex = [], i = 0; i < bytes.length; i++) {
      var current = bytes[i] < 0 ? bytes[i] + 256 : bytes[i];
      hex.push((current >>> 4).toString(16));
      hex.push((current & 0xf).toString(16));
    }
    return hex.join('');
  } catch (e) {
    console.log(e);
  }
};
