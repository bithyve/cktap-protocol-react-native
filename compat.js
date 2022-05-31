const RIPEMD160 = require('ripemd160');
const sha256 = require('js-sha256');
const { randomBytes } = require('crypto');
const secp256k1 = require('secp256k1');
const bip32 = require('bip32');
const base32 = require('buf-b32');

import { tou8 } from './utils';

function ripemd160(args = '') {
  return new RIPEMD160().update(args).digest();
}

function hash160(args) {
  return ripemd160(Buffer.from(sha256s(args)));
}

function sha256s(msg, hex = false) {
  var hash = sha256.create();
  const msg_digest = hash.update(msg).digest();
  return hex ? msg_digest.toString('hex') : msg_digest;
}

function base32Encode(buff) {
  return Buffer.from(base32.encode(tou8(buff)));
}

function rec_id_from_header(header) {
  let header_num = header & 0xff;
  if (header_num >= 39) header_num -= 12;
  else if (header_num >= 35) header_num -= 8;
  else if (header_num >= 31) header_num -= 4;
  const rec_id = header_num - 27;
  return rec_id;
}

function CT_pick_keypair() {
  // return {priv, pub}
  let priv;
  const compressed = true;
  do {
    priv = randomBytes(32);
  } while (!secp256k1.privateKeyVerify(priv));
  const pub = secp256k1.publicKeyCreate(priv, compressed);

  return { priv, pub };
}

function CT_priv_to_pubkey(priv) {
  // return compressed pubkey
  const compressed = true;
  return secp256k1.publicKeyCreate(priv, compressed);
}

function CT_sig_verify(sig, msg_digest, pub) {
  // returns True or False
  return secp256k1.ecdsaVerify(sig, msg_digest, pub);
}

function CT_sig_to_pubkey(msg_digest, sig) {
  // returns a pubkey (33 bytes)
  const header = sig.slice(0, 1)[0];
  const compact_sig = sig.slice(1);
  const rec_id = rec_id_from_header(header);
  return secp256k1.ecdsaRecover(compact_sig, rec_id, msg_digest);
}

function CT_ecdh(his_pubkey, my_privkey) {
  // returns a 32-byte session key, which is sha256s(compressed point)

  return secp256k1.ecdh(his_pubkey, my_privkey);
}

function CT_sign(privkey, msg_digest, recoverable = false) {
  // returns 64-byte sig

  return secp256k1.ecdsaSign(msg_digest, privkey);
}

function CT_bip32_derive(chain_code, master_priv_pub, subkey_path) {
  // return pubkey (33 bytes)
  let master;
  if (master_priv_pub.length === 32) {
    // master_priv_pub :: private_key
    master = bip32.fromPrivateKey(master_priv_pub, chain_code);
  } else {
    // master_priv_pub :: public_key
    master = bip32.fromPublicKey(master_priv_pub, chain_code);
  }

  let node = master;
  subkey_path.forEach((index) => {
    node = node.derive(index);
  });
  return node.publicKey;
}

export {
  sha256s,
  hash160,
  base32Encode,
  CT_pick_keypair,
  CT_priv_to_pubkey,
  CT_sig_verify,
  CT_sig_to_pubkey,
  CT_ecdh,
  CT_sign,
  CT_bip32_derive,
};
