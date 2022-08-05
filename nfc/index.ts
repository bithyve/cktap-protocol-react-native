import { cborEncode, decodeAndSplitResponse } from './parser';

import { APP_ID } from '../constants';
import NfcManager from 'react-native-nfc-manager';
import { Platform } from 'react-native';

/**
 * Start a session with the cards with select-app command
 * The session is active until the rfc signal persists
 * This is lost once the card is far from the nfc receiver
 */
async function init() {
  try {
    const headers = Buffer.from('00a404000f', 'hex');
    const selectApp = Buffer.concat([headers, APP_ID]);
    const selectResponse = await NfcManager.isoDepHandler.transceive(
      selectApp.toJSON().data
    );
    const { response, status } = decodeAndSplitResponse(selectResponse);
    return { response, status };
  } catch (error) {
    throw new Error('Initialisation failed');
  }
}
/**
 * NFC transceiver for all commands sent to and from the cards
 * uses isoDepHandler
 * @param  {string} cmd
 * @param  {any} args
 */
async function send(cmd: string, args: any) {
  try {
    args.cmd = cmd;
    const bytes = cborEncode(args);
    const delay = getDelay(cmd);
    if (Platform.OS === 'android' && delay) {
      await NfcManager.setTimeout(delay);
    }
    const r = await NfcManager.isoDepHandler.transceive(bytes);
    const { response, status } = decodeAndSplitResponse(r);
    return { response, status };
  } catch (error) {
    throw error;
  }
}
/**
 * Android only
 * specific commands are expensive in time
 * let NFC listen in for extra few seconds for the response from the cards
 * @param  {string} cmd
 */
const getDelay = (cmd: string) => {
  const expensiveCommands = ['new', 'backup', 'wait'];
  if (expensiveCommands.includes(cmd)) {
    return 1000;
  } else {
    return 0;
  }
};

export { send, init };
