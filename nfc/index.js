import NfcManager, { NfcTech } from 'react-native-nfc-manager';
import { cborEncode, decodeAndSplitResponse } from './parser';

async function init() {
  try {
    await NfcManager.requestTechnology(NfcTech.IsoDep, {
      readerModeDelay: 2000,
    });
    const selectApp = [
      0x00, 0xa4, 0x04, 0x00, 0x0f, 0xf0, 0x43, 0x6f, 0x69, 0x6e, 0x6b, 0x69,
      0x74, 0x65, 0x43, 0x41, 0x52, 0x44, 0x76, 0x31,
    ];
    const selectResponse = await NfcManager.isoDepHandler.transceive(selectApp);
    const { response, status } = decodeAndSplitResponse(selectResponse);
    return { response, status };
  } catch (ex) {
    console.warn('Oops!', ex);
  }
}

async function send(cmd, args = {}) {
  try {
    args.cmd = cmd;
    const bytes = cborEncode(args);
    const delay = getDelay(cmd);
    delay && NfcManager.setTimeout(delay);
    const r = await NfcManager.transceive(bytes);
    const { response, status } = decodeAndSplitResponse(r);
    return { response, status };
  } catch (ex) {
    console.log(ex);
  }
}

const getDelay = (cmd) => {
  if (cmd === 'wait' || cmd === 'backup') {
    return 1000;
  } else {
    return 0;
  }
};

export { send, init };
