import { BIP32Interface, fromPrivateKey, fromPublicKey } from 'bip32';
import { Message, sha256 } from 'js-sha256';

import RIPEMD160 from 'ripemd160';
import { encode as b32Encode } from 'buf-b32';
import { randomBytes } from 'crypto';
import secp256k1 from 'secp256k1';
import { tou8 } from './utils';

/**
 * @param  {any} args
 * @returns any
 */
function ripemd160(args: any): any {
  return new RIPEMD160().update(args).digest();
}

/**
 * @param  {any} args
 * @returns any
 */
function hash160(args: any): any {
  return ripemd160(Buffer.from(sha256s(args)));
}

/**
 * @param  {Message} msg
 * @returns number[]
 */
function sha256s(msg: Message): number[] {
  var hash = sha256.create();
  const msg_digest = hash.update(msg).digest();
  return msg_digest;
}

/**
 * @param  {Buffer} buff
 * @returns Buffer (base-32 encoded)
 */
function base32Encode(buff: Buffer): Buffer {
  return Buffer.from(b32Encode(tou8(buff) as ArrayBufferView));
}
/**
 * @param  {number} header
 * @returns number
 */
function rec_id_from_header(header: number): number {
  let header_num = header & 0xff;
  if (header_num >= 39) header_num -= 12;
  else if (header_num >= 35) header_num -= 8;
  else if (header_num >= 31) header_num -= 4;
  const rec_id = header_num - 27;
  return rec_id;
}

/**
 * @returns {priv: Buffer, pub: Buffer}
 */
function CT_pick_keypair(): { priv: Buffer; pub: Buffer } {
  let priv;
  const compressed = true;
  do {
    priv = randomBytes(32);
  } while (!secp256k1.privateKeyVerify(priv));
  const pub = secp256k1.publicKeyCreate(priv, compressed);

  return { priv, pub };
}

/**
 * @param  {Uint8Array|Buffer} priv
 * @returns Buffer (compressed pubkey)
 */
function CT_priv_to_pubkey(priv: Uint8Array | Buffer): Buffer {
  const compressed = true;
  return secp256k1.publicKeyCreate(priv, compressed);
}

/**
 * @param  {Uint8Array} sig
 * @param  {Uint8Array} msg_digest
 * @param  {Uint8Array} pub
 * @returns boolean
 */
function CT_sig_verify(
  sig: Uint8Array,
  msg_digest: Uint8Array,
  pub: Uint8Array
): boolean {
  return secp256k1.ecdsaVerify(sig, msg_digest, pub);
}

/**
 * @param  {Uint8Array} msg_digest
 * @param  {Uint8Array} sig
 * @returns Buffer (pubkey 33 bytes)
 */
function CT_sig_to_pubkey(msg_digest: Uint8Array, sig: Uint8Array): Buffer {
  const header = sig.slice(0, 1)[0];
  const compact_sig = sig.slice(1);
  const rec_id = rec_id_from_header(header);
  return secp256k1.ecdsaRecover(compact_sig, rec_id, msg_digest);
}

/**
 * @param  {Uint8Array} his_pubkey
 * @param  {Uint8Array} my_privkey
 * @returns Buffer (32-byte session key, w/ is sha256s i.e. compressed point)
 */
function CT_ecdh(his_pubkey: Uint8Array, my_privkey: Uint8Array): Buffer {
  return secp256k1.ecdh(his_pubkey, my_privkey);
}

/**
 * @param  {Uint8Array} privkey
 * @param  {Uint8Array} msg_digest
 * @returns Buffer (64-byte signature)
 */
function CT_sign(privkey: Uint8Array, msg_digest: Uint8Array): Buffer {
  return secp256k1.ecdsaSign(msg_digest, privkey);
}

/**
 * @param  {Buffer} chain_code
 * @param  {Buffer} master_priv_pub
 * @param  {any[]} subkey_path
 * @returns Buffer (pubkey 33 bytes)
 */
function CT_bip32_derive(
  chain_code: Buffer,
  master_priv_pub: Buffer,
  subkey_path: any[]
): Buffer {
  let master: BIP32Interface;
  if (master_priv_pub.length === 32) {
    master = fromPrivateKey(master_priv_pub, chain_code); // master_priv_pub :: private_key
  } else {
    master = fromPublicKey(master_priv_pub, chain_code); // master_priv_pub :: public_key
  }

  let node = master;
  subkey_path.forEach((i: number) => {
    node = node.derive(i);
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
