//check if there's a crypto-js equiv function to do this
function hexStringToByteArray(hexString) {
  if (hexString.length % 2 !== 0) {
    throw 'Must have an even number of hex digits to convert to bytes';
  } /* w w w.  jav  a2 s .  c o  m*/
  var numBytes = hexString.length / 2;
  var byteArray = new Uint8Array(numBytes);
  for (var i = 0; i < numBytes; i++) {
    byteArray[i] = parseInt(hexString.substr(i * 2, 2), 16);
  }
  return byteArray;
}
//
//  (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
//
//  System constants.
//

//  Number of key slots in SATSCARD
export const NUM_SLOTS = 10;

//  the "CVC" is the spending code on back of card.
//  - see also many text messages to user about this
//  - for TAPSIGNER, this is a minimum length (max 32)
export const CVC_LENGTH = 6;

//  no need to scan the blockchain before this point in time, since product didn't exist yet
//  - March 25/2022
export const PROJECT_EPOC_TIME_T = 1648215566;

//  length from start/end of bech32 address that is provided
//  - center part will be replaced with three underscores
export const ADDR_TRIM = 12;

//  require nonce sizes (bytes)
export const CARD_NONCE_SIZE = 16;
export const USER_NONCE_SIZE = 16;

//  published Coinkite factory root keys
export const FACTORY_ROOT_KEYS = {
  'Root Factory Certificate': hexStringToByteArray(
    '03028a0e89e70d0ec0d932053a89ab1da7d9182bdc6d2f03e706ee99517d05d9e1'
  ),

  //  obsolete dev value, but keeping for a little while longer
  'Root Factory Certificate (TESTING ONLY)': hexStringToByteArray(
    '027722ef208e681bac05f1b4b3cc478d6bf353ac9a09ff0c843430138f65c27bab'
  ),
};

//  our cards will provide this answer to reset (ATR)
//  TODO: need to check decoding
export const CARD_ATR = [59, 136, 128, 1].concat(decode('Coinkite')) + [49];
//  pthyon implementation: CARD_ATR = [59, 136, 128, 1] + list(b'Coinkite') + [49]

//  our Javacard applet has this APP ID
export const APP_ID = hexStringToByteArray('f0436f696e6b697465434152447631');

//  APDU CLA and INS fields for our one APDU, which uses CBOR data
export const CBOR_CLA = 0x00;
export const CBOR_INS = 0xcb;

//  Correct ADPU response from all commands: 90 00
export const SW_OKAY = 0x9000;

//  EOF
