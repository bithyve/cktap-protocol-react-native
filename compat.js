const RIPEMD160 = require('ripemd160');
const sha256 = require('js-sha256');
const { randomBytes } = require('crypto');
const secp256k1 = require('secp256k1');
const ecc = require('tiny-secp256k1');
const { BIP32Factory } = require('bip32');

function ripemd160(args = '') {
  return new RIPEMD160().update(args).digest('hex');
}

function hash160(args) {
  return ripemd160(sha256(args));
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

function CT_sig_verify(pub, msg_digest, sig) {
  // returns True or False

  return secp256k1.ecdsaVerify(sig, msg_digest, pub);
}

function CT_sig_to_pubkey(msg_digest, sig) {
  // returns a pubkey (33 bytes)

  return secp256k1.ecdsaRecover(sig.signature, sig.recid, msg_digest);
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
  const bip32 = BIP32Factory(ecc);

  let master;
  if (master_priv_pub.length === 32) {
    // master_priv_pub :: private_key
    master = bip32.fromPrivateKey(master_priv_pub, chain_code);
  } else {
    // master_priv_pub :: public_key
    master = bip32.fromPublicKey(master_priv_pub, chain_code);
  }

  let node;

  subkey_path.forEach((index) => {
    node = master.derive(index);
  });
  return node.publicKey;
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
