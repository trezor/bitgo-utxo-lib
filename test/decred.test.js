/* global describe, it */

var assert = require('assert')
var baddress = require('../src/address')
var ecpair = require('../src/ecpair')
var networks = require('../src/networks')
var TransactionBuilder = require('../src/transaction_builder')
var Transaction = require('../src/transaction')

describe('TransactionBuilder', function () {
  var network = networks.decred
  it('decred sign transaction ', function () {
    var buf = Buffer.alloc(32)
    buf[31] = 1
    const pair = ecpair.fromPrivateKeyBuffer(buf, network)
    const spk = baddress.toOutputScript(pair.getAddress(), network)
    var txb = new TransactionBuilder(network)
    txb.addDecredInput(
      '87a157f3fd88ac7907c05fc55e271dc4acdc5605d187d646604ca8c0e9382e03',
      0,
      0,
      Transaction.DEFAULT_SEQUENCE
    )
    txb.addOutput(Buffer.from('ba76a914c398efa9c392ba6013c5e04ee729755ef7f58b3288ac', 'hex'), 100000000)
    txb.addOutput(Buffer.from('6a1e948c765a6914d43f2a7ac177da2c2f6b52de3d7c0000000000000000443f', 'hex'), 0)
    txb.addOutput(Buffer.from('bd76a914c398efa9c392ba6013c5e04ee729755ef7f58b3288ac', 'hex'), 0)
    txb.addDecredWitness(0, 100010000, 0, 0, null)

    const sigHash = txb.tx.hashForDecredSignature(0, spk, Transaction.SIGHASH_ALL).toString('hex')
    assert.equal('cfbfc27d9e4388a5079531dd2df2ec5c9a7f2a0c945dbb63bb8ad72557861feb', sigHash)

    txb.signDecred(0, pair, pair.getPublicKeyBuffer(), spk, Transaction.SIGHASH_ALL)

    var tx = txb.build()
    var hex = tx.toHex()
    assert.equal(hex, '0100000001032e38e9c0a84c6046d687d10556dcacc41d275ec55fc00779ac88fdf357a1870000000000ffffffff0300e1f5050000000000001aba76a914c398efa9c392ba6013c5e04ee729755ef7f58b3288ac00000000000000000000206a1e948c765a6914d43f2a7ac177da2c2f6b52de3d7c0000000000000000443f000000000000000000001abd76a914c398efa9c392ba6013c5e04ee729755ef7f58b3288ac0000000000000000011008f6050000000000000000000000006a47304402201e1e16589e4f09d0f2c8f139530bddccb794cb47da60da1b30b102b1e11b64ab02205db674db41e8e435749b3a49e092ad13484d286059212547ae8a9bdadb4350f301210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
  })
})
