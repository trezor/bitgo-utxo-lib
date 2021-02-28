// https://en.bitcoin.it/wiki/List_of_address_prefixes
// Dogecoin BIP32 is a proposed standard: https://bitcointalk.org/index.php?topic=409731
var coins = require('./coins')

module.exports = {
  dash: {
    messagePrefix: '\x19DarkCoin Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x4c, // https://dash-docs.github.io/en/developer-reference#opcodes
    scriptHash: 0x10,
    wif: 0xcc,
    coin: coins.DASH
  },
  dashTest: {
    messagePrefix: '\x19DarkCoin Signed Message:\n',
    bip32: {
      public: 0x043587cf,
      private: 0x04358394
    },
    pubKeyHash: 0x8c, // https://dash-docs.github.io/en/developer-reference#opcodes
    scriptHash: 0x13,
    wif: 0xef, // https://github.com/dashpay/godashutil/blob/master/wif.go#L72
    coin: coins.DASH
  },
  bitcoincash: {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'bc',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x00,
    scriptHash: 0x05,
    wif: 0x80,
    coin: coins.BCH,
    forkId: 0x00
  },
  bitcoincashTestnet: {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'tb',
    bip32: {
      public: 0x043587cf,
      private: 0x04358394
    },
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0xef,
    coin: coins.BCH
  },
  bitcoinsv: {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'bc',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x00,
    scriptHash: 0x05,
    wif: 0x80,
    coin: coins.BSV,
    forkId: 0x00
  },
  bitcoinsvTestnet: {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'tb',
    bip32: {
      public: 0x043587cf,
      private: 0x04358394
    },
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0xef,
    coin: coins.BSV
  },
  zcash: {
    messagePrefix: '\x18ZCash Signed Message:\n',
    bech32: 'bc',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x1cb8,
    scriptHash: 0x1cbd,
    wif: 0x80,
    // This parameter was introduced in version 3 to allow soft forks, for version 1 and 2 transactions we add a
    // dummy value.
    consensusBranchId: {
      1: 0x00,
      2: 0x00,
      3: 0x5ba81b19,
      // 4: 0x76b809bb (old Sapling branch id). Blossom branch id becomes effective after block 653600
      4: 0x2bb40e60
    },
    coin: coins.ZEC
  },
  zcashTest: {
    messagePrefix: '\x18ZCash Signed Message:\n',
    bech32: 'tb',
    bip32: {
      public: 0x043587cf,
      private: 0x04358394
    },
    pubKeyHash: 0x1d25,
    scriptHash: 0x1cba,
    wif: 0xef,
    consensusBranchId: {
      1: 0x00,
      2: 0x00,
      3: 0x5ba81b19,
      // 4: 0x76b809bb (old Sapling branch id)
      4: 0x2bb40e60
    },
    coin: coins.TAZ
  },
  bitcoingold: {
    messagePrefix: '\x18Bitcoin Gold Signed Message:\n',
    bech32: 'btg',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x26,
    scriptHash: 0x17,
    wif: 0x80,
    coin: coins.BTG,
    forkId: 0x4F /* 79 */
  },
  litecoin: {
    messagePrefix: '\x19Litecoin Signed Message:\n',
    bech32: 'ltc',
    bip32: {
      public: 0x019da462,
      private: 0x019d9cfe
    },
    pubKeyHash: 0x30,
    scriptHash: 0x32,
    wif: 0xb0,
    coin: coins.LTC
  },
  litecoinTest: {
    messagePrefix: '\x19Litecoin Signed Message:\n',
    bech32: 'tltc',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x6f,
    scriptHash: 0x3a,
    wif: 0xb0,
    coin: coins.LTC
  },
  bitcoin: {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'bc',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x00,
    scriptHash: 0x05,
    wif: 0x80,
    coin: coins.BTC
  },
  testnet: {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'tb',
    bip32: {
      public: 0x043587cf,
      private: 0x04358394
    },
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0xef,
    coin: coins.BTC
  },
  capricoin: {
    messagePrefix: '\x18Capricoin Signed Message:\n',
    bech32: null,
    bip32: {
      public: 0x488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x1c,
    scriptHash: 0x23,
    wif: 0,
    coin: coins.CAPRICOIN
  },
  peercoin: {
    messagePrefix: '\x18Peercoin Signed Message:\n',
    bech32: 'pc',
    bip32: {
      public: 0x488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x37,
    scriptHash: 0x75,
    wif: 0,
    coin: coins.PEERCOIN
  },
  peercoinTest: {
    messagePrefix: '\x18Peercoin Signed Message:\n',
    bech32: 'tpc',
    bip32: {
      public: 0x43587cf,
      private: 0x04358394
    },
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0,
    coin: coins.PEERCOINTEST
  },
  komodo: {
    messagePrefix: '\x18Komodo Signed Message:\n',
    bech32: 'bc',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x3c,
    scriptHash: 0x05,
    wif: 0xbc,
    // This parameter was introduced in version 3 to allow soft forks, for version 1 and 2 transactions we add a
    // dummy value.
    consensusBranchId: {
      1: 0x00,
      2: 0x00,
      3: 0x5ba81b19,
      4: 0x76b809bb
    },
    coin: coins.KMD
  },
  decred: {
    messagePrefix: '\x17Decred Signed Message:\n',
    bip32: {
      public: 0x02fda926,
      private: 0x02fda4e8
    },
    pubKeyHash: 0x073f,
    scriptHash: 0x071a,
    wif: 0x22de,
    coin: coins.DCR
  },
  decredTest: {
    messagePrefix: '\x17Decred Signed Message:\n',
    bip32: {
      public: 0x043587d1,
      private: 0x04358397
    },
    pubKeyHash: 0x0f21,
    scriptHash: 0x0efc,
    wif: 0x230e,
    coin: coins.TDCR
  },
  decredSim: {
    messagePrefix: '\x17Decred Signed Message:\n',
    bip32: {
      public: 0x0420bd3d,
      private: 0x0420b903
    },
    pubKeyHash: 0x0e91,
    scriptHash: 0x0e6c,
    wif: 0x2307,
    coin: coins.SDCR
  }
}
