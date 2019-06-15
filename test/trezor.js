/* global describe, it */

var assert = require('assert')
var networks = require('../src/networks')

var fixturesTransaction = require('./fixtures/transaction')
var fixturesBufferutils = require('./fixtures/bufferutils.json')
var fixturesTrezor = require('./fixtures/trezor.json')
var Transaction = require('../src/transaction')
var bufferutils = require('../src/bufferutils')

// Additional tests for Trezor custom changes

describe('Trezor', function () {
  describe('Transaction: toHex with invalid output values', function () {
    const fixtures = fixturesTrezor.transaction.invalid
    Transaction.USE_STRING_VALUES = true
    fixtures.forEach(function (f) {
      it('throws on ' + f.description, function () {
        assert.throws(function () {
          var tx = Transaction.fromHex(f.hex)
          tx.outs.forEach(function (o) {
            o.value = f.value
          })
          tx.toHex()
        }, new RegExp(f.exception))
      })
    })
    Transaction.USE_STRING_VALUES = false
  })

  describe('Trezor Transaction: fromBuffer/fromHex with values as strings', function () {
    const fixtures = fixturesTrezor.transaction.valid
    fixtures.forEach(function (testData) {
      it('imports ' + testData.description, function () {
        Transaction.USE_STRING_VALUES = true
        const tx = Transaction.fromHex(testData.hex, testData.network)
        assert.strictEqual(tx.ins.length, testData.ins.length)
        tx.ins.forEach(function (input, i) {
          assert.strictEqual(input.hash.toString('hex'), testData.ins[i].hash)
          assert.strictEqual(input.index, testData.ins[i].index)
          assert.strictEqual(input.script.toString('hex'), testData.ins[i].script)
          assert.strictEqual(input.sequence, testData.ins[i].sequence)
        })

        assert.strictEqual(tx.outs.length, testData.outs.length)
        tx.outs.forEach(function (output, i) {
          assert.strictEqual(output.value, testData.outs[i].value.toString())
          assert.equal(output.script.toString('hex'), testData.outs[i].script)
        })

        if (testData.time) {
          assert.strictEqual(tx.timestamp, testData.time)
        }
        Transaction.USE_STRING_VALUES = false
      })
    })

    fixtures.forEach(function (testData) {
      it('exports ' + testData.description, function () {
        Transaction.USE_STRING_VALUES = true
        const tx = Transaction.fromHex(testData.hex, testData.network)
        assert.strictEqual(testData.hex, tx.toHex())
        Transaction.USE_STRING_VALUES = false
      })
    })

    fixtures.forEach(function (testData) {
      it('clone ' + testData.description, function () {
        Transaction.USE_STRING_VALUES = true
        const tx = Transaction.fromHex(testData.hex, testData.network)
        const clonedTx = tx.clone()
        assert.strictEqual(clonedTx.toHex(), testData.hex)
        Transaction.USE_STRING_VALUES = false
      })
    })
  })

  // copied from ./test/transaction.js
  describe('Zcash Transaction: fromBuffer/fromHex with values as strings', function () {
    const fixtures = fixturesTransaction.zcash.valid
    fixtures.forEach(function (testData) {
      it('imports ' + testData.description, function () {
        Transaction.USE_STRING_VALUES = true
        const tx = Transaction.fromHex(testData.hex, networks.zcashTest)
        assert.equal(tx.version, testData.version)
        assert.equal(tx.versionGroupId, parseInt(testData.versionGroupId, 16))
        assert.equal(tx.overwintered, testData.overwintered)
        assert.equal(tx.locktime, testData.locktime)
        assert.equal(tx.expiryHeight, testData.expiryHeight)
        assert.equal(tx.ins.length, testData.insLength)
        assert.equal(tx.outs.length, testData.outsLength)
        assert.equal(tx.joinsplits.length, testData.joinsplitsLength)
        assert.equal(tx.joinsplitPubkey.length, testData.joinsplitPubkeyLength)
        assert.equal(tx.joinsplitSig.length, testData.joinsplitSigLength)

        if (testData.valueBalance) {
          assert.equal(tx.valueBalance, testData.valueBalance)
        }
        if (testData.nShieldedSpend > 0) {
          for (var i = 0; i < testData.nShieldedSpend; ++i) {
            assert.equal(tx.vShieldedSpend[i].cv.toString('hex'), testData.vShieldedSpend[i].cv)
            assert.equal(tx.vShieldedSpend[i].anchor.toString('hex'), testData.vShieldedSpend[i].anchor)
            assert.equal(tx.vShieldedSpend[i].nullifier.toString('hex'), testData.vShieldedSpend[i].nullifier)
            assert.equal(tx.vShieldedSpend[i].rk.toString('hex'), testData.vShieldedSpend[i].rk)
            assert.equal(tx.vShieldedSpend[i].zkproof.sA.toString('hex') +
              tx.vShieldedSpend[i].zkproof.sB.toString('hex') +
              tx.vShieldedSpend[i].zkproof.sC.toString('hex'), testData.vShieldedSpend[i].zkproof)
            assert.equal(tx.vShieldedSpend[i].spendAuthSig.toString('hex'), testData.vShieldedSpend[i].spendAuthSig)
          }
        }
        Transaction.USE_STRING_VALUES = false
      })
    })

    fixtures.forEach(function (testData) {
      it('exports ' + testData.description, function () {
        Transaction.USE_STRING_VALUES = true
        const tx = Transaction.fromHex(testData.hex, networks.zcashTest)
        const hexTx = tx.toHex()
        assert.equal(testData.hex, hexTx)
        Transaction.USE_STRING_VALUES = false
      })
    })

    fixtures.forEach(function (testData) {
      it('clone ' + testData.description, function () {
        Transaction.USE_STRING_VALUES = true
        const tx = Transaction.fromHex(testData.hex, networks.zcashTest)
        const clonedTx = tx.clone()
        assert.equal(clonedTx.toHex(), testData.hex)
        Transaction.USE_STRING_VALUES = false
      })
    })
  })

  describe('Dash Testnet Transaction: fromBuffer/fromHex values as strings', function () {
    const fixtures = fixturesTransaction.dasht.valid
    fixtures.forEach(function (testData) {
      it('imports ' + testData.description, function () {
        Transaction.USE_STRING_VALUES = true
        const tx = Transaction.fromHex(testData.hex, networks.dashTest)
        assert.equal(tx.version, testData.version)
        if (tx.version === 3) {
          assert.equal(tx.type, testData.type)
        }
        assert.equal(tx.locktime, testData.locktime)
        assert.equal(tx.ins.length, testData.vin.length)
        assert.equal(tx.outs.length, testData.vout.length)
        tx.outs.forEach(function (output, i) {
          const fixtureValue = Math.round(testData.vout[i].value * 100000000)
          assert.strictEqual(output.value, fixtureValue.toString())
          assert.equal(output.script.toString('hex'), testData.vout[i].scriptPubKey.hex)
        })
        if (tx.isDashSpecialTransaction()) {
          assert.equal(tx.extraPayload.toString('hex'), testData.extraPayload)
        }
        Transaction.USE_STRING_VALUES = false
      })
    })

    fixtures.forEach(function (testData) {
      it('exports ' + testData.description, function () {
        Transaction.USE_STRING_VALUES = true
        const tx = Transaction.fromHex(testData.hex, networks.dashTest)
        const hexTx = tx.toHex()
        assert.equal(testData.hex, hexTx)
        Transaction.USE_STRING_VALUES = false
      })
    })

    fixtures.forEach(function (testData) {
      it('clone ' + testData.description, function () {
        Transaction.USE_STRING_VALUES = true
        const tx = Transaction.fromHex(testData.hex, networks.dashTest)
        const clonedTx = tx.clone()
        assert.equal(clonedTx.toHex(), testData.hex)
        Transaction.USE_STRING_VALUES = false
      })
    })
  })

  describe('Transaction: getExtraData - Dash', function () {
    const fixtures = fixturesTransaction.dasht.valid
    const trezorFixtures = fixturesTrezor.transaction.extraData.dasht
    // const fixtures = fixturesTransaction.dasht.valid.filter(t => typeof t.extraPayload === 'string')
    fixtures.forEach(function (testData, i) {
      it('imports ' + testData.description, function () {
        Transaction.USE_STRING_VALUES = true
        const tx = Transaction.fromHex(testData.hex, networks.dashTest)
        const extra = tx.getExtraData()
        const extraData = extra ? extra.toString('hex') : null
        assert.equal(extraData, trezorFixtures[i])
        Transaction.USE_STRING_VALUES = false
      })
    })
  })

  describe('Transaction: getExtraData - Zcash', function () {
    const fixtures = fixturesTransaction.zcash.valid
    const trezorFixtures = fixturesTrezor.transaction.extraData.zcash
    fixtures.forEach(function (testData, i) {
      it('imports ' + testData.description, function () {
        Transaction.USE_STRING_VALUES = true
        const tx = Transaction.fromHex(testData.hex, networks.zcashTest)
        const extra = tx.getExtraData()
        const extraData = extra ? extra.toString('hex') : null
        assert.equal(extraData, trezorFixtures[i])
        Transaction.USE_STRING_VALUES = false
      })
    })
  })

  describe('bufferutils: writeUInt64LEasString', function () {
    const fixtures = fixturesTrezor.bufferutils.writeUInt64LEasString
    fixtures.forEach(function (f) {
      it('encodes ' + f.description + ' correctly', function () {
        var buffer = Buffer.alloc(8, 0)
        bufferutils.writeUInt64LEasString(buffer, f.dec, 0)
        assert.strictEqual(buffer.toString('hex'), f.hex64)
      })
    })
  })

  describe('bufferutils: readUInt64LEasString', function () {
    fixturesBufferutils.valid.forEach(function (f) {
      it('decodes ' + f.hex64 + ' correctly', function () {
        var buffer = Buffer.from(f.hex64, 'hex')
        var string = bufferutils.readUInt64LEasString(buffer, 0)
        assert.strictEqual(string, f.dec.toString())
      })
    })

    fixturesTrezor.bufferutils.readUInt64LEasString.forEach(function (f) {
      it('decodes ' + f.description + ' correctly', function () {
        var buffer = Buffer.from(f.hex64, 'hex')
        var string = bufferutils.readUInt64LEasString(buffer, 0)
        assert.strictEqual(string, f.dec.toString())
      })
    })
  })
})
