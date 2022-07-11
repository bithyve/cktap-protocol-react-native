import { CT_sig_verify, hash160, sha256s } from './compat';
import { DERIVE_MAX_BIP32_PATH_DEPTH, SW_OKAY } from './constants';
import NfcManager, { NfcTech } from 'react-native-nfc-manager';
import {
  all_hardened,
  calc_xcvc,
  card_pubkey_to_ident,
  force_bytes,
  make_recoverable_sig,
  none_hardened,
  path2str,
  pick_nonce,
  recover_address,
  render_address,
  str2path,
  verify_certs,
  verify_derive_address,
  verify_master_pubkey,
  xor_bytes,
} from './utils';
import { init, send as transceive } from './nfc';

import { Platform } from 'react-native';
import base58 from 'bs58';

const { randomBytes } = require('crypto');

async function _send(cmd, args = {}) {
  const { status: stat_word, response: resp } = await transceive(cmd, args);
  return { stat_word, resp };
}
export class CKTapCard {
  constructor() {
    this.card_nonce = null;
    this.card_pubkey = null;
    this.card_ident = null;
    this.applet_version = null;
    this.birth_height = null;
    this.is_testnet = null;
    this.auth_delay = null;
    this.is_tapsigner = null;
    this.path = null;
    this.num_backups = null;
  }

  // wrap any number of logical commands or functions that need to run with this nfc wrapper
  async nfcWrapper(callback) {
    try {
      const supported = await NfcManager.isSupported();
      if (supported) {
        await NfcManager.start();
        await NfcManager.requestTechnology([NfcTech.IsoDep]);
        await this.selectApp();
        const resp = await callback();
        if (Platform.OS === 'ios') {
          await NfcManager.setAlertMessageIOS('Success');
        }
        await NfcManager.cancelTechnologyRequest();
        return resp;
      }
    } catch (e) {
      if (Platform.OS === 'ios') {
        NfcManager.setAlertMessageIOS('Something went wrong!');
      }
      NfcManager.cancelTechnologyRequest();
      if (
        ['Error: transceive fail', 'Error: Initialisation failed'].includes(
          e.toString()
        )
      ) {
        throw new Error(`[NFC] Please hold the card more stably or longer`);
      }
      throw e;
    }
  }

  async selectApp() {
    const { response } = await init();
    if (response['error']) {
      const msg = response['error'];
      const code = response['code'] || 500;
      throw new Error(`${code} on ${cmd}: ${msg}`);
    }
    if (response.card_nonce) {
      this.card_nonce = response['card_nonce'];
    }
  }

  async send(cmd, args = {}, raise_on_error = true) {
    //  Send a command, get response, but also catch some card state
    //  changes and mirror them in our state.
    //  - command is a short string, such as "status"
    //  - see the protocol spec for arguments here
    const { stat_word, resp } = await _send(cmd, args);
    if (stat_word !== SW_OKAY) {
      //  Assume error if ANY bad SW value seen; promote for debug purposes
      if (!resp['error']) {
        resp['error'] = `Got error SW value: ${stat_word}`;
      }
      resp['stat_word'] = stat_word;
    }

    if (resp.card_nonce) {
      //  many responses provide an updated card_nonce needed for
      //  the *next* comand. Track it.
      //  - only changes when "consumed" by commands that need CVC
      this.card_nonce = resp['card_nonce'];
    }

    if (raise_on_error && resp['error']) {
      const msg = resp['error'];
      const code = resp['code'] || 500;
      throw new Error(`${code} on ${cmd}: ${msg}`);
    }
    return resp;
  }

  async first_look() {
    // Call this at end of __init__ to load up details from card
    // - can be called multiple times
    const resp = await this.send('status');
    if (resp['error']) {
      throw new Error('Early filure');
    }
    if (resp['proto'] !== 1) {
      throw new Error('Unknown card protocol version');
    }
    if (resp['tampered']) {
      throw new Error('WARNING: Card has set tampered flag!');
    }

    this.card_pubkey = resp['pubkey'];
    this.card_ident = card_pubkey_to_ident(this.card_pubkey);

    this.applet_version = resp['ver'];
    this.birth_height = resp['birth'] || null;
    this.is_testnet = resp['testnet'] || false;
    this.auth_delay = resp['auth_delay'] || 0;
    this.is_tapsigner = resp['tapsigner'] || false;
    this.path = resp['path'] ? path2str(resp['path']) : null;
    this.num_backups = resp['num_backups'] || 'NA';
    const [active_slot, num_slots] = resp['slots'] || [0, 1];
    this.active_slot = active_slot;
    this.num_slots = num_slots;

    if (!resp['card_nonce']) {
      // this.send() will have captured from first status req
      return;
    }

    return this;
  }

  async send_auth(cmd, cvc, args = {}) {
    // Take CVC and do ECDH crypto and provide the CVC in encrypted form
    // - returns session key and usual auth arguments needed
    // - skip if CVC is null and just do normal stuff (optional auth on some cmds)
    // - for commands w/ encrypted arguments, you must provide to this function
    let session_key = null;
    let auth_args = null;
    if (cvc) {
      const { sk, ag } = calc_xcvc(cmd, this.card_nonce, this.card_pubkey, cvc);
      session_key = sk;
      auth_args = ag;
      args = { ...args, ...auth_args };
    }
    // A few commands take an encrypted argument (most are returning encrypted
    // results) and the caller didn't know the session key yet. So xor it for them.
    if (cmd === 'sign') {
      args.digest = xor_bytes(args.digest, session_key);
    } else if (cmd === 'change') {
      args.data = xor_bytes(args.data, session_key.slice(0, args.data.length));
    }
    const resp = await this.send(cmd, args);
    return { session_key, resp };
  }

  async address(faster = false, incl_pubkey = false, slot = null) {
    // Get current payment address for card
    // - does 100% full verification by default
    // - returns a bech32 address as a string
    if (this.is_tapsigner) {
      return;
    }

    // check certificate chain
    if (!this._certs_checked && !faster) {
      await this.certificate_check();
    }

    const st = await this.send('status');
    const cur_slot = st['slots'][0];
    if (slot === null) {
      slot = cur_slot;
    }

    if (!st.addr && cur_slot === slot) {
      //raise ValueError("Current slot is not yet setup.")
      throw new Error('Current slot is not yet setup.');
    }

    if (slot !== cur_slot) {
      // Use the unauthenticated "dump" command.
      const rr = await this.send('dump', { slot: Number(slot) });
      if (!incl_pubkey) {
        throw new Error('can only get pubkey on current slot');
      } else {
        return rr['addr'];
      }
    }

    // Use special-purpose "read" command
    const nonce = pick_nonce();
    const rr = await this.send('read', { nonce });

    const { pubkey, addr } = recover_address(st, rr, nonce);

    if (!faster) {
      // additional check: did card include chain_code in generated private key?
      const my_nonce = pick_nonce();
      const card_nonce = this.card_nonce;
      const resp = await this.send('derive', { nonce: my_nonce });
      const master_pub = verify_master_pubkey(
        resp['master_pubkey'],
        resp['sig'],
        resp['chain_code'],
        my_nonce,
        card_nonce
      );
      const { derived_addr, _ } = verify_derive_address(
        resp['chain_code'],
        master_pub,
        this.is_testnet
      );
      if (derived_addr != addr) {
        throw new Error('card did not derive address as expected');
      }
    }

    return { addr, pubkey: incl_pubkey ? pubkey : null };
  }

  async get_derivation() {
    // TAPSIGNER only: what's the current derivation path, which might be
    // just empty (aka 'm').
    if (!this.is_tapsigner) {
      return;
    }
    const status = await this.send('status');
    const path = status['path'];
    if (!path) {
      throw new Error('No private key picked yet.');
    }
    return path2str(path);
  }

  async set_derivation(path, cvc) {
    // TAPSIGNER only: what's the current derivation path, which might be
    // just empty (aka 'm').
    if (!this.is_tapsigner) {
      return;
    }
    const np = str2path(path);

    if (np.length > DERIVE_MAX_BIP32_PATH_DEPTH) {
      throw new Error(
        `No more than ${DERIVE_MAX_BIP32_PATH_DEPTH} path components allowed.`
      );
    }

    if (!all_hardened(np)) {
      throw new Error('All path components must be hardened');
    }

    const { session_key: _, resp } = await this.send_auth('derive', cvc, {
      path: np,
      nonce: pick_nonce(),
    });

    this.path = path;
    // XXX need FP of parent key and master (XFP)
    // XPUB would be better result here, but caller can use get_xpub() next
    return {
      length: np.length,
      chain_code: resp['chain_code'],
      pubkey: resp['pubkey'],
    };
  }

  async get_xfp(cvc) {
    // fetch master xpub, take pubkey from that and calc XFP
    if (!this.is_tapsigner) {
      return;
    }
    const { session_key: _, resp } = await this.send_auth('xpub', cvc, {
      master: true,
    });
    const xpub = resp['xpub'];
    return hash160(xpub.slice(-33));
  }

  async get_xpub(cvc, master = false) {
    // fetch XPUB, either derived or master one
    // - result is BIP-32 serialized and base58-check encoded
    if (!this.is_tapsigner) {
      return;
    }
    const { session_key: _, resp } = await this.send_auth('xpub', cvc, {
      master,
    });
    const xpub = resp['xpub'];
    // python: return base58.b58encode_check(xpub).decode('ascii')
    const xpubString = base58.encode(
      Buffer.concat([xpub, Buffer.from(sha256s(sha256s(xpub))).slice(0, 4)])
    );
    return xpubString;
  }

  async make_backup(cvc) {
    // read the backup file; gives ~100 bytes to be kept long term
    if (!this.is_tapsigner) {
      return;
    }
    const { session_key: _, resp } = await this.send_auth('backup', cvc);
    return resp['data'];
  }

  async change_cvc(old_cvc, new_cvc) {
    // Change CVC. Note: can be binary or ascii or digits, 6..32 long
    if (new_cvc.length < 6 || new_cvc.length > 32) {
      throw new Error('CVC must be 6 to 32 characters long');
    }
    return this.send_auth('change', old_cvc, { data: force_bytes(new_cvc) });
  }

  async certificate_check() {
    // Verify the certificate chain and the public key of the card
    // - assures this card was produced in Coinkite factory
    // - does not relate to payment addresses or slot usage
    // - raises on errors/failed validation
    const status = await this.send('status');
    const certs = await this.send('certs');
    const nonce = pick_nonce();
    const check = await this.send('check', { nonce });
    const rv = verify_certs(status, check, certs, nonce);
    this._certs_checked = true;

    return rv;
  }

  async get_status() {
    // read current status
    return this.send('status');
  }

  async unseal_slot(cvc) {
    // Unseal the current slot (can only be one)
    // - returns (privkey, slot_num)
    if (this.is_tapsigner) {
      return;
    }

    // only one possible value for slot number
    const target = this.active_slot;

    // but that slot must be used and sealed (note: unauthed req here)
    const rr = await this.send('dump', { slot: target });

    if (rr['sealed'] === false) {
      throw new Error(`Slot ${target} has already been unsealed.`);
    }

    if (rr['sealed'] != true) {
      throw new Error(`Slot ${target} has not been used yet.`);
    }

    const { session_key, resp } = await this.send_auth('unseal', cvc, {
      slot: target,
    });
    const pk = xor_bytes(session_key, resp['privkey']);

    return { pk, target };
  }

  async get_nfc_url() {
    // Provide the (dynamic) URL that you'd get if you tapped the card.
    const { url } = await this.send('nfc_url');
    return url;
  }

  async get_privkey(cvc, slot) {
    // Provide the private key of an already-unsealed slot (32 bytes)
    if (this.is_tapsigner) {
      return;
    }

    const { session_key, resp } = await this.send_auth('dump', cvc, {
      slot: Number(slot),
    });

    if (!resp['privkey'])
      if (resp['used'] === false) {
        throw new Error(`That slot [${slot}] is not yet used (no key yet)`);
      } else if (resp['sealed'] === true) {
        throw new Error(`That slot [${slot}] is not yet unsealed.`);
      } else {
        throw new Error(`Not sure of the key for that slot (${slot}).`);
      }

    return xor_bytes(session_key, resp['privkey']);
  }

  async get_slot_usage(slot, cvc = null) {
    // Get address and status for a slot, CVC is optional
    // returns:
    //   (address, status, detail_map)
    if (this.is_tapsigner) {
      return;
    }
    const { session_key, resp } = await this.send_auth('dump', cvc, {
      slot: Number(slot),
    });
    let status;
    let address = resp['addr'];

    if (resp['sealed'] === true) {
      status = 'sealed';
      if (slot === this.active_slot) {
        address = await this.address(true);
      }
    } else if (resp['sealed'] === false || resp['privkey']) {
      status = 'UNSEALED';
      if ('privkey' in resp) {
        const pk = xor_bytes(session_key, resp['privkey']);
        address = render_address(pk, this.is_testnet);
      }
    } else if (resp['used'] === false) {
      status = 'unused';
    } else {
      // unreachable.
      throw new Error(JSON.stringify(resp));
    }

    address = address || resp['addr'];

    return { address, status, resp };
  }

  async sign_digest(cvc, slot, digest, subpath = null) {
    /*
        Sign 32 bytes digest and return 65 bytes long recoverable signature.

        Uses derivation path based on current set derivation on card plus optional
        subpath parameter which if provided, will be added to card derivation path.
        Subpath can only be of length 2 and non-hardened components only.

        Returns non-deterministic recoverable signature (header[1b], r[32b], s[32b])
        */
    //  Expects the digest to be 32 bit Buffer and parsed by the wallet
    if (digest.length !== 32) {
      throw new Error('Digest must be exactly 32 bytes');
    }
    if (!this.is_tapsigner && subpath) {
      throw new Error("Cannot use 'subpath' option for SATSCARD");
    }
    // subpath validation
    const int_path = subpath !== null ? str2path(subpath) : [];
    if (int_path.length > 2) {
      throw new Error(`Length of path ${subpath} greater than 2`);
    }
    if (!none_hardened(int_path)) {
      throw new Error(`Subpath ${subpath} contains hardened components`);
    }
    if (this.is_tapsigner) {
      slot = 0;
    }
    for (var i = 0; i < 4; i++) {
      try {
        const { session_key: _, resp } = await this.send_auth('sign', cvc, {
          slot,
          digest,
          subpath: this.is_tapsigner ? int_path : null,
        });
        const expect_pub = resp['pubkey'];
        const sig = resp['sig'];
        if (!CT_sig_verify(sig, digest, expect_pub)) {
          continue;
        }
        const rec_sig = make_recoverable_sig(
          digest,
          sig,
          null,
          expect_pub,
          this.is_testnet
        );
        return rec_sig;
      } catch (error) {
        if (error.code === 205) {
          // unlucky number
          // status to update card nonce
          await this.send('status');
          continue;
        }
        throw new Error(error);
      }
    }
    // probability that we get here is very close to zero
    const msg = 'Failed to sign digest after 5 retries. Try again.';
    throw new Error(`500 on sign: ${msg}`);
  }

  async setup(cvc, chain_code, new_chain_code) {
    let target;
    if (this.is_tapsigner) {
      target = 0;
      if (!chain_code) {
        new_chain_code = true;
      }
    } else {
      target = this.active_slot;

      const resp = await this.send('dump', { slot: target });
      if (resp['used']) {
        throw new Error(
          `Slot ${target} is already used. Unseal it, and move to next`
        );
      }
    }
    const args = { slot: target };

    if (chain_code && new_chain_code) {
      throw new Error('Provide a chain code or make me pick one, not both');
    }
    if (new_chain_code) {
      args['chain_code'] = Buffer.from(sha256s(sha256s(randomBytes(128))));
    } else if (chain_code) {
      try {
        // chain_code = b2a_hex(chain_code);
        if (chain_code.length !== 32) {
          throw new Error('Chain code must be exactly 32 bytes');
        }
      } catch (e) {
        throw new Error('Need 64 hex digits (32 bytes) for chain code.');
      }
      args['chain_code'] = chain_code;
    } else if (target === 0) {
      // not expected case since factory setup on slot zero
      throw new Error('Chain code required for slot zero setup');
    }

    try {
      const { session_key: _, resp } = await this.send_auth('new', cvc, args);
      if (this.is_tapsigner) {
        console.log('TAPSIGNER ready for use');
      } else {
        console.log('SATSCARD ready for use');
        // only one field: new slot number
        this.active_slot = resp['slot'];
        return this.address();
      }
    } catch (e) {
      console.log(e);
      console.log('card failed to setup');
    }
  }

  async wait() {
    return this.send('wait');
  }

  async read(cvc) {
    return this.send_auth('read', cvc, { nonce: pick_nonce() });
  }
}
