var RIPEMD160 = require('ripemd160');
var sha256 = require('js-sha256');
var { ECPairFactory } = require('ecpair');
var ecc = require('tiny-secp256k1');
const ECPair = ECPairFactory(ecc);

function ripemd160(args = '') {
  return new RIPEMD160().update(args).digest('hex');
}

function hash160(args) {
  return ripemd160(sha256(args));
}

function CT_pick_keypair() {
  const keyPair = ECPair.makeRandom();
  const priv = keyPair.privateKey.toString('hex')
  const pub = keyPair.publicKey.toString('hex')
  return { priv, pub }
}

function CT_priv_to_pubkey(pk) {
  // return compressed pubkey
  throw new Error('Not implemented');
}

function CT_sig_verify(pub, msg_digest, sig) {
  // returns True or False
  if (sig.length != 64) {
    throw new Error('invalid sig length');
  }
  throw new Error('Not implemented');
}

function CT_sig_to_pubkey(msg_digest, sig) {
  // returns a pubkey (33 bytes)
  if (sig.length != 65) {
    throw new Error('invalid sig length');
  }
  throw new Error('Not implemented');
}

function CT_ecdh(his_pubkey, my_privkey) {
  // returns a 32-byte session key, which is sha256s(compressed point)
  throw new Error('Not implemented');
}

function CT_sign(privkey, msg_digest, recoverable = false) {
  // returns 64-byte sig
  throw new Error('Not implemented');
}

function CT_bip32_derive(chain_code, master_priv_pub, subkey_path) {
  // return pubkey (33 bytes)
  throw new Error('Not implemented');
}

module.exports = {
  hash160,
  CT_pick_keypair,
  CT_priv_to_pubkey,
  CT_sig_verify,
  CT_sig_to_pubkey,
  CT_ecdh,
  CT_sign,
  CT_bip32_derive,
};