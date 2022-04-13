import { SW_OKAY } from './constants';

function _send(cmd, args = {}) {
  let stat_word;
  let resp;
  return { stat_word, resp };
}

export class CKTapCard {
  constructor() {
    this.card_nonce = null;
  }

  send(cmd, raise_on_error = false, args = {}) {
    //  Send a command, get response, but also catch some card state
    //  changes and mirror them in our state.
    //  - command is a short string, such as "status"
    //  - see the protocol spec for arguments here
    const { stat_word, resp } = _send(cmd, args);

    if (stat_word !== SW_OKAY) {
      //  Assume error if ANY bad SW value seen; promote for debug purposes
      if (!resp['error']) {
        resp['error'] = 'Got error SW value: 0x%04x' % stat_word;
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
      const msg = resp.pop('error');
      const code = resp.pop('code', 500);
      throw new Error(`${code} on ${cmd}: ${msg}`);
    }

    return resp;
  }

  first_look() {
    // Call this at end of __init__ to load up details from card
    // - can be called multiple times
    const resp = this.send('status');
  }
}
