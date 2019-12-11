# Trezor UTXO library (@trezor/utxo-lib)
[![Build Status](https://travis-ci.org/trezor/trezor-utxo-lib.png?branch=master)](https://travis-ci.org/trezor/trezor-utxo-lib)
[![NPM](https://img.shields.io/npm/v/@trezor/utxo-lib.svg)](https://www.npmjs.org/package/@trezor/utxo-lib)
[![Known Vulnerabilities](https://snyk.io/test/github/trezor/trezor-utxo-lib/badge.svg?targetFile=package.json)](https://snyk.io/test/github/trezor/trezor-utxo-lib?targetFile=package.json)

[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)

Originally a fork of [bitgo-utxo-lib](https://github.com/BitGo/bitgo-utxo-lib); we evolved this library to support the transaction parsing for Trezor.
Synchronized with upstream 1.5.0 version

## Trezor features
- Transaction.fromHex returns input values as string
- Transaction.getExtraData returns data necessary for Trezor signing process
- Komodo support
- Dash special transactions support
- Capricoin support
- Zcash testnet support (coin shortcut: TAZ)
- Peercoin support

Update from upstream:
- `git checkout trezor`
- `git fetch upstream`
- `git rebase upstream/master`
- update package.json `upstreamVersion` field

## Supported coins
- Bitcoin
- Bitcoin Cash
- Bitcoin Gold
- Bitcoin SV (Satoshi Vision)
- Dash
- Litecoin
- Zcash (Sapling compatible)

## Features
- Clean: Pure JavaScript, concise code, easy to read.
- Tested: Coverage > 90%, third-party integration tests.
- Compatible: Works on Node.js and all modern browsers.
- Powerful: Support for advanced features, such as multi-sig, HD Wallets.
- Secure: Strong random number generation, PGP signed releases, trusted developers.
- Principled: No support for browsers with RNG (IE < 11)
- Standardized: Node community coding style, Browserify, Node's stdlib and Buffers.
- Experiment-friendly: Mainnet and Testnet support.
- Multicoin support: Configurable behaviour based on [network](https://github.com/trezor/trezor-utxo-lib/blob/master/src/networks.js) objects.
- Backed by [BitGo](https://www.bitgo.com/info/)

## Installation
``` bash
npm install @trezor/utxo-lib
```

## Setup
### Node.js
``` javascript
var bitcoin = require('@trezor/utxo-lib')
```

### Browser
If you're familiar with how to use browserify, ignore this and proceed normally.
These steps are advisory only,  and may not be suitable for your application.

[Browserify](https://github.com/substack/node-browserify) is assumed to be installed for these steps.

For your project, create an `index.js` file
``` javascript
let bitcoin = require('@trezor/utxo-lib')

// your code here
function myFunction () {
	return bitcoin.ECPair.makeRandom().toWIF()
}

module.exports = {
	myFunction
}
```

Now, to compile for the browser:
``` bash
browserify index.js --standalone foo > app.js
```

You can now put `<script src="app.js" />` in your web page,  using `foo.myFunction` to create a new Bitcoin private key.

**NOTE**: If you uglify the javascript, you must exclude the following variable names from being mangled: `BigInteger`, `ECPair`, `Point`.
This is because of the function-name-duck-typing used in [typeforce](https://github.com/dcousens/typeforce).

Example:
``` bash
uglifyjs ... --mangle --reserved 'BigInteger,ECPair,Point'
```

**NOTE**: If you are using webpack you may run into a issue related to [blake2b-wasm dependency](https://github.com/mafintosh/blake2b-wasm/issues/9)
Until it get fixed you may need to set this line in your `webpack.config`
``` javascript
plugins: [
  new webpack.NormalModuleReplacementPlugin(/.blake2b$/, './blake2b.js'),
]
```

**NOTE**: This library tracks Node LTS features,  if you need strict ES5,  use [`--transform babelify`](https://github.com/babel/babelify) in conjunction with your `browserify` step (using an [`es2015`](http://babeljs.io/docs/plugins/preset-es2015/) preset).

**NOTE**: If you expect this library to run on an iOS 10 device, ensure that you are using [buffer@5.0.5](https://github.com/feross/buffer/pull/155) or greater.

## Examples
The below examples are implemented as integration tests, they should be very easy to understand.
Otherwise, pull requests are appreciated.
Some examples interact (via HTTPS) with a 3rd Party Blockchain Provider (3PBP).

### Bitcoin

### Running the test suite

``` bash
npm test
npm run-script coverage
```

## Complementing Libraries
- [BIP21](https://github.com/bitcoinjs/bip21) - A BIP21 compatible URL encoding utility library
- [BIP38](https://github.com/bitcoinjs/bip38) - Passphrase-protected private keys
- [BIP39](https://github.com/bitcoinjs/bip39) - Mnemonic generation for deterministic keys
- [BIP32-Utils](https://github.com/bitcoinjs/bip32-utils) - A set of utilities for working with BIP32
- [BIP66](https://github.com/bitcoinjs/bip66) - Strict DER signature decoding
- [BIP69](https://github.com/bitcoinjs/bip69) - Lexicographical Indexing of Transaction Inputs and Outputs
- [Base58](https://github.com/cryptocoinjs/bs58) - Base58 encoding/decoding
- [Base58 Check](https://github.com/bitcoinjs/bs58check) - Base58 check encoding/decoding
- [Bech32](https://github.com/bitcoinjs/bech32) - A BIP173 compliant Bech32 encoding library
- [coinselect](https://github.com/bitcoinjs/coinselect) - A fee-optimizing, transaction input selection module for bitcoinjs-lib.
- [merkle-lib](https://github.com/bitcoinjs/merkle-lib) - A performance conscious library for merkle root and tree calculations.
- [minimaldata](https://github.com/bitcoinjs/minimaldata) - A module to check bitcoin policy: SCRIPT_VERIFY_MINIMALDATA


## LICENSE [MIT](LICENSE)
