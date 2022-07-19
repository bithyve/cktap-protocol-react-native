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

  // const s2 = primitives.CT_sign(priv, md, true)
  // expect(s2.signature).toHaveLength(65);
  // const chk = primitives.CT_sig_to_pubkey(md, s2)
  // expect(chk).toBe(pub);

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
