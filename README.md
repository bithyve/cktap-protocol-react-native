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

`metro.cofig.js`
```
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
```
extraNodeModules: {
    stream: require.resolve('stream-browserify'),
}
```
4. install respoective cocopod dependencies
`cd ios && pod install`
