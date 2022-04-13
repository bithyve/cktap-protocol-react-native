import { CARD_NONCE_SIZE, USER_NONCE_SIZE } from './constants';

// xor_bytes
// pick_nonce
// path2str
// str2path
// card_pubkey_to_ident
// verify_certs
// recover_pubkey
// recover_address
// force_bytes
import { bech32 } from 'bech32';
import { hash160 } from './compat';

function verify_master_pubkey(pub, sig, chain_code, my_nonce, card_nonce) {
  // using signature response from 'deriv' command, recover the master pubkey
  // for this slot
  // TODO: verify if b'string' has some sp meaning in python
  const msg = 'OPENDIME' + card_nonce + my_nonce + chain_code;

  if (msg.length !== 8 + CARD_NONCE_SIZE + USER_NONCE_SIZE + 32) {
    console.warn('verify_master_pubkey: invalid message length');
    return;
  }

  const ok = CT_sig_verify(pub, sha256s(msg), sig);
  if (!ok) {
    console.warn('verify_master_pubkey: bad sig in verify_master_pubkey');
    return;
  }

  return pub;
}

function render_address(pubkey, testnet = false) {
  // make the text string used as a payment address
  if (pubkey.length === 32)
    // actually a private key, convert
    pubkey = CT_priv_to_pubkey(pubkey);

  const HRP = !testnet ? 'bc' : 'tb';
  // TODO: check bech32 implementation
  // python: bech32.encode(HRP, 0, hash160(pubkey));
  return bech32.encode(HRP, [hash160(pubkey)], 0);
}

function verify_derive_address(chain_code, master_pub, testnet = false) {
  // # re-derive the address we should expect
  // # - this is "m/0" in BIP-32 nomenclature
  // # - accepts master public key (before unseal) or master private key (after)
  const pubkey = CT_bip32_derive(chain_code, master_pub, [0]);

  return render_address(pubkey, (testnet = testnet)), pubkey;
}

module.exports = { verify_derive_address, verify_master_pubkey };
