import { CT_sig_to_pubkey } from './compat';

function all_keys(sig, md) {
  // generates all possible pubkeys from sig + digest
  return [...Array(4)].map((_, rec_id) => {
    try {
      return CT_sig_to_pubkey(md, Buffer.from([39 + rec_id]) + sig);
    } catch (e) {
      if (rec_id >= 2) {
        // because crypto I don't understand
        return;
      } else {
        throw new Error(e);
      }
    }
  });
}

function url_decoder(fragment) {
  //  Takes the URL (after the # part) and verifies it
  //   and returns dict of useful values, or raise on errors/frauds
  if (fragment.indexOf('#') || fragment.indexOf('?')) {
    throw new Error(
      'Fragment not parsed properrly. Pass only the dynamic content.'
    );
  }
  const msg = fragment.slice(0, fragment.lastIndexOf('=') + 1);
  const urlParams = new URLSearchParams(fragment);
  try {
    const nonce = Buffer.from(urlParams['n'], 'hex');
    const is_tapsigner = !!urlParams.get('t', false);
    if (nonce.length !== 8) {
      console.warn('invalid nonce length');
      return;
    }
    const slot_num = parseInt(urlParams.get('o', -1));
    const addr = urlParams.get('r', null);
    const sig = Buffer.from(urlParams['s'], 'hex');
    if (nonce.length !== 64) {
      console.warn('invalid sig length');
      return;
    }
    const card_ident = urlParams.get('c', null);

    const md = sha256s(msg.encode('ascii'));
    if (is_tapsigner) {
      if (!card_ident) {
        throw new Error('Missing card ident value');
      }
      card_ident = bytes.fromhex(card_ident);
      const full_card_ident = null;

      for (pubkey in all_keys(sig, md)) {
        expect = sha256s(pubkey);
        if (expect.slice(0, 8) == card_ident) {
          full_card_ident = card_pubkey_to_ident(pubkey);
          break;
        }
      }
      if (!full_card_ident) {
        throw new Error('Could not reconstruct card ident.');
      }
      return {
        // TODO: check hex converision and bytes conversion
        nonce: nonce.hex(),
        card_ident: full_card_ident,
        virgin: urlParams['u'] == 'U',
        is_tapsigner: true,
        tampered: urlParams['u'] == 'E',
      };
    } else {
      confirmed_addr = null;
      is_testnet = false;
      state =
        {
          S: 'Sealed',
          U: 'UNSEALED',
          E: 'Error/Tampered',
        }[urlParams['u']] || 'Unknown State';
      for (pubkey in all_keys(sig, md)) {
        if (addr !== null) {
          let got = render_address(pubkey, false);
          if (got.endswith(addr)) {
            confirmed_addr = got;
            break;
          }
          got = render_address(pubkey, true);
          if (got.endswith(addr)) {
            confirmed_addr = got;
            is_testnet = true;
            break;
          }
        }
      }
      if (addr && !confirmed_addr) {
        throw new Error('Could not reconstruct full payment address.');
      }
      rv = {
        state: state,
        addr: confirmed_addr,
        nonce: nonce.hex(),
        is_tapsigner: False,
        slot_num: slot_num,
        sealed: urlParams['u'] == 'S',
        tampered: urlParams['u'] == 'E',
      };
      if (is_testnet) {
        rv['testnet'] = true;
      }
      return rv;
    }
  } catch (e) {
    if (e.message.indexOf('undefined')) {
      throw new Error('Required field missing');
    }
    console.log(e);
  }
}

module.exports(url_decoder);
