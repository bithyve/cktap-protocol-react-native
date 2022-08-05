import * as constants from '../constants';
import * as primitives from '../compat';
import * as utils from '../utils';

test('sha256s', () => {
  expect(Buffer.from(primitives.sha256s('abc')).toString('hex')).toBe(
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  );
});

test('hash160', () => {
  expect(primitives.hash160('abc').toString('hex')).toBe(
    'bb1be98c142444d7a56aa3981c3942a978e4dc33'
  );
});

test('btc_primitives', () => {
  const { priv, pub } = primitives.CT_pick_keypair();
  expect(pub).toStrictEqual(primitives.CT_priv_to_pubkey(priv));

  const md = Buffer.alloc(32);
  const s1 = primitives.CT_sign(priv, md);

  expect(s1.signature).toHaveLength(64);
  expect(primitives.CT_sig_verify(s1.signature, md, pub)).toBeTruthy();

  const got = primitives.CT_bip32_derive(
    Buffer.alloc(32, 'c'),
    Buffer.alloc(33, 2),
    [1, 2, 3]
  );
  expect(got.toString('hex')).toBe(
    '03666fbbeec7b96850a0a7ffb70c5df7ecc46c9a8992d231cbb17b7fd9eaffcb88'
  );

  const pk = Buffer.alloc(32, 'c');
  const pb = Buffer.alloc(33, 2);
  const ss = primitives.CT_ecdh(pb, pk);

  expect(Buffer.from(ss).toString('hex')).toBe(
    '104c5ef46959013cc52a2e6a5acc26b937f7cf910f0d804f7bf278ef1eb2d9ed'
  );
});

test('UInt8ArrayConversion', () => {
  const buf = Buffer.from([0, 1, 2, 3, 4]);
  let u8 = new Uint8Array(buf.length);
  for (let i = 0; i < buf.length; i++) {
    u8[i] = buf[i];
  }
  expect(utils.tou8(buf)).toEqual(u8);
  expect(utils.tou8(null)).toBeFalsy();
  expect(utils.tou8(u8)).toEqual(u8);
});

test('nonceGeneration', () => {
  const nonce = utils.pick_nonce();
  expect(nonce).toHaveLength(constants.USER_NONCE_SIZE);
  expect(nonce).toBeInstanceOf(Buffer);
  expect(new Set(nonce).size).toBeGreaterThan(2);
});

test('sessionKeyVerification', () => {
  const { pub } = primitives.CT_pick_keypair();
  const nonce = utils.pick_nonce();
  const { ag, sk } = utils.calc_xcvc('test', nonce, pub, '123456');
  expect(ag).toHaveProperty('epubkey');
  expect(ag).toHaveProperty('xcvc');
  expect(sk).toBeInstanceOf(Buffer);
  expect(sk).toHaveLength(32);
  expect(ag.xcvc).toBeInstanceOf(Buffer);
  expect(ag.xcvc).toHaveLength(6);
  expect(ag.epubkey).toBeInstanceOf(Buffer);
  expect(ag.epubkey).toHaveLength(33);
});
