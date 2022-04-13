import { ADDR_TRIM, CARD_NONCE_SIZE, USER_NONCE_SIZE } from './constants';

import { bech32 } from 'bech32';
import { hash160 } from './compat';

// card_pubkey_to_ident
// verify_certs
// recover_pubkey

const BytesArray = (str) => {
  let bytes = [];
  for (var i = 0; i < str.length; ++i) {
    var code = str.charCodeAt(i);
    bytes = bytes.concat([code]);
  }
  return bytes;
};

function recover_address(status_resp, read_resp, my_nonce) {
  // [SC] Given the response from "status" and "read" commands, and the
  // nonce we gave for read command, reconstruct the card's verified payment
  // address. Check prefix/suffix match what's expected
  if (status_resp.get('tapsigner', false)) {
    console.warn('recover_address: tapsigner not supported');
    return;
  }

  const sl = status_resp['slots'][0];
  // TODO: verify if b'string' has some sp meaning in python
  // TODO: also veify BytesArray
  const msg =
    'OPENDIME' + status_resp['card_nonce'] + my_nonce + BytesArray(sl);
  if (msg.length !== 8 + CARD_NONCE_SIZE + USER_NONCE_SIZE + 32) {
    console.warn('recover_address: invalid message length');
    return;
  }

  const pubkey = read_resp['pubkey'];

  // Critical: proves card knows key
  const ok = CT_sig_verify(pubkey, sha256s(msg), read_resp['sig']);
  if (!ok) {
    console.warn('Bad sig in recover_address');
    return;
  }

  const expect = status_resp['addr'];
  const left = expect.slice(0, expect.find('_'));
  const right = expect.slice(expect.find('_') + 1);

  // Critical: counterfieting check
  const addr = render_address(pubkey, status_resp.get('testnet', false));
  if (
    !(
      addr.startswith(left) &&
      addr.endswith(right) &&
      (left.length == right.length) == ADDR_TRIM
    )
  ) {
    console.warn('Corrupt response');
    return;
  }

  return { pubkey, addr };
}

function force_bytes(foo) {
  // convert strings to bytes where needed
  // TODO: verify Buffer implementation
  return typeof foo == 'string' ? Buffer.from(foo, 'hex') : foo;
}

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

module.exports = {
  verify_derive_address,
  verify_master_pubkey,
  force_bytes,
  recover_address,
};
