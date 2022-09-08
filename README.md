# React Native

## Coinkite Tap Protocol library

A React Native JS library to enable easy communication
with **TAPSIGNER<sup>&trade;</sup>** and **SATSCARD<sup>&trade;</sup>**.

**-==[Request card development samples [here](https://coinkite.cards/dev)]==-**

## Documentation Links

See [the python library by Coinkite](https://github.com/coinkite/coinkite-tap-proto) for protocol specifications.

# Installation

`yarn add coinkite-tap-protocol`

## Supporting node core modules

This library uses a few node core modules like secp256k1, buffer, crypto etc. which react native doesn't support because they probably use C++ code bundled with the Node JS binary, not Javascript.

We suggest using [rn-nodify](https://github.com/tradle/rn-nodeify) to enable using node core modules after `yarn add coinkite-tap-protocol`

## Metro Plugin

rn-nodify needs stream-browserify for browser support.

`metro.config.js`

```sh
...
resolver: {
    extraNodeModules: {
      stream: require.resolve('stream-browserify'),
    },
  },
transformer: {
    ...
  },
...
```

## Peer dependencies

[react-native-nfc-manager](https://github.com/revtel/react-native-nfc-manager) is used for the NFC communications with the cards. Please refer to their docs for nfc integration.

## ~TDLR

1. add the post install script in your package.json
   `"postinstall": "rn-nodeify --install fs,dgram,process,path,console,crypto --hack"`

2. install the required modules
   `yarn add coinkite-tap-protocol rn-nodify stream-browserify react-native-nfc-manager`

3. update metro config resolver

```sh
extraNodeModules: {
    stream: require.resolve('stream-browserify'),
}
```

4. install respoective cocopod dependencies
   `cd ios && pod install`


# Usage

Create a Protocol calss to interact with the TAPSIGNER/SATSCARD.
```tsx
import { CKTapCard } from 'cktap-protocol-react-native';
.
.
.
const card:CKTapCard = useRef(new CKTapCard()).current;
```


The library provides a wrapper to initialte NFC and make batch calls to the TAPSIGNER/SATSCARD with a single NFC scan.
```tsx
const cardStatus = await card.nfcWrapper(async () => {
    // interact with the card here
    return card.first_look(); // scans the card for basic details and initialises with it
});
```


You can also batch commands in a single NFC scan
```tsx
const initiatedCard = await card.nfcWrapper(async () => {
    const cardStatus = await card.first_look();
    const isCardLegit = await card.certificate_check();
    if(isCardLegit){
        // run the setup command just once
        await card.setup(cvc); // setup the card with the CVC at the back of the card (don't forget to prompt the user to change it later)
    }
    return card;
});
```


Fetch the xpub, derivation path and fingerprint post setup
```tsx
const initiatedCard = await card.nfcWrapper(async () => {
    const cardStatus = await card.first_look();
    if (status.path) {
        const xpub = await card.get_xpub(cvc);
        const fingerprint = await card.get_xfp(cvc);
        return { xpub, derivationPath: cardStatus.path, fingerprint: fingerprint.toString('hex') };
    } else {
        await card.setup(cvc);
        const cardStatus = await card.first_look();
        const xpub = await card.get_xpub(cvc);
        const fingerprint = await card.get_xfp(cvc);
        return { xpub, derivationPath: cardStatus.path, fingerprint: fingerprint.toString('hex') };
    }
});
```


**NOTE**
* Place the card for the NFC scan before **card.nfcWrapper** is called. There is no need to remove the card until the wrapper completes the callback.
* iOS has it's own system NFC interaction to let the user know that the NFC is active.
* Android has no interaction as such. You can use your own modal/interaction which can open and close before/after the callback to card.nfcWrapper.
* [Demo app with detailed usage of the library](https://github.com/bithyve/Cktap-Demo).
