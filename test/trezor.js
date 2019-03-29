// Additional tests for Trezor custom changes

/* global describe, it */

var assert = require('assert')
var networks = require('../src/networks')

var fixturesTransaction = require('./fixtures/transaction')
var fixturesBufferutils = require('./fixtures/bufferutils.json')
var Transaction = require('../src/transaction')
var bufferutils = require('../src/bufferutils')

describe('Trezor', function () {
  describe('Transaction: fromBuffer/fromHex for DOGE (values as string)', function () {
    const fixtures = fixturesTransaction.doge.valid
    fixtures.forEach(function (testData) {
      it('imports ' + testData.description, function () {
        Transaction.USE_STRING_VALUES = true
        const tx = Transaction.fromHex(testData.hex, networks.doge)
        assert.equal(tx.ins.length, testData.ins.length)
        assert.equal(tx.outs.length, testData.outs.length)
        tx.ins.forEach(function (input, i) {
          assert.equal(input.hash.toString('hex'), testData.ins[i].hash)
          assert.equal(input.index, testData.ins[i].index)
          assert.equal(input.script.toString('hex'), testData.ins[i].script)
          assert.equal(input.sequence, testData.ins[i].sequence)
        })

        tx.outs.forEach(function (output, i) {
          assert.equal(output.value, testData.outs[i].value)
          assert.equal(output.script.toString('hex'), testData.outs[i].script)
        })
        Transaction.USE_STRING_VALUES = false
      })
    })

    fixtures.forEach(function (testData) {
      it('exports ' + testData.description, function () {
        Transaction.USE_STRING_VALUES = true
        const tx = Transaction.fromHex(testData.hex, networks.doge)
        const hashTx = tx.getId()
        const hexTx = tx.toHex()
        assert.equal(testData.hex, hexTx)
        assert.equal(testData.hash, hashTx)
        Transaction.USE_STRING_VALUES = false
      })
    })

    fixtures.forEach(function (testData) {
      it('clone ' + testData.description, function () {
        Transaction.USE_STRING_VALUES = true
        const tx = Transaction.fromHex(testData.hex, networks.doge)
        const clonedTx = tx.clone()
        assert.equal(clonedTx.toHex(), testData.hex)
        Transaction.USE_STRING_VALUES = false
      })
    })
  })

  describe('Transaction: fromBuffer/fromHex for Capricoin (timestamp)', function () {
    const fixtures = fixturesTransaction.capricoin
    fixtures.forEach(function (testData) {
      it('imports ' + testData.description, function () {
        const tx = Transaction.fromHex(testData.hex, networks.capricoin)
        assert.equal(tx.timestamp, testData.time)
      })
    })

    fixtures.forEach(function (testData) {
      it('exports ' + testData.description, function () {
        const tx = Transaction.fromHex(testData.hex, networks.capricoin)
        const hashTx = tx.getId()
        const hexTx = tx.toHex()
        assert.equal(testData.hex, hexTx)
        assert.equal(testData.hash, hashTx)
      })
    })

    fixtures.forEach(function (testData) {
      it('clone ' + testData.description, function () {
        const tx = Transaction.fromHex(testData.hex, networks.capricoin)
        const clonedTx = tx.clone()
        assert.equal(clonedTx.timestamp, testData.time)
      })
    })
  })

  describe('Transaction: getExtraData - Dash', function () {
    const fixtures = fixturesTransaction.dasht.valid.filter(t => typeof t.extraPayload === 'string')
    fixtures.forEach(function (testData) {
      it('imports ' + testData.description, function () {
        const tx = Transaction.fromHex(testData.hex, networks.dashTest)
        const extra = tx.getExtraData().toString('hex')
        assert.equal(extra, '26' + testData.extraPayload) // additional data required by Trezor
      })
    })
  })

  describe('Transaction: getExtraData - Zcash', function () {
    const fixtures = fixturesTransaction.zcash.valid
    fixtures.forEach(function (testData) {
      it('imports ' + testData.description, function () {
        const tx = Transaction.fromHex(testData.hex, networks.zcashTest)

        tx.getExtraData()
      })
    })
  })

  describe('bufferutils: writeUInt64LEasString', function () {
    const fixtures = fixturesBufferutils.writeUInt64LEasString.valid
    fixtures.forEach(function (f) {
      it('encodes ' + f.description + ' correctly', function () {
        var buffer = Buffer.alloc(8, 0)
        bufferutils.writeUInt64LEasString(buffer, f.dec, 0)
        assert.strictEqual(buffer.toString('hex'), f.hex64)
      })
    })
  })

  describe('bufferutils: readUInt64LEasString', function () {
    const fixtures = fixturesBufferutils
    fixtures.valid.forEach(function (f) {
      it('decodes ' + f.hex64 + ' correctly', function () {
        var buffer = Buffer.from(f.hex64, 'hex')
        var string = bufferutils.readUInt64LEasString(buffer, 0)
        assert.strictEqual(string, f.dec.toString())
      })
    })

    fixtures.readUInt64LEasString.valid.forEach(function (f) {
      it('decodes ' + f.description + ' correctly', function () {
        var buffer = Buffer.from(f.hex64, 'hex')
        var string = bufferutils.readUInt64LEasString(buffer, 0)
        assert.strictEqual(string, f.dec.toString())
      })
    })
  })
})
