// OP_SSTXCHANGE OP_DUP OP_HASH160 {pubKeyHash} OP_EQUALVERIFY OP_CHECKSIG

var bscript = require('../../script')
var types = require('../../types')
var typeforce = require('typeforce')
var OPS = require('bitcoin-ops')
// Decred specific stake submission OP code.
const OP_SSTXCHANGE = 0xbd

function check (script) {
  var buffer = bscript.compile(script)

  return buffer.length === 26 &&
    buffer[0] === OP_SSTXCHANGE &&
    buffer[1] === OPS.OP_DUP &&
    buffer[2] === OPS.OP_HASH160 &&
    buffer[3] === 0x14 &&
    buffer[24] === OPS.OP_EQUALVERIFY &&
    buffer[25] === OPS.OP_CHECKSIG
}
check.toJSON = function () { return 'pubKeyHash output' }

function encode (pubKeyHash) {
  typeforce(types.Hash160bit, pubKeyHash)

  return bscript.compile([
    OP_SSTXCHANGE,
    OPS.OP_DUP,
    OPS.OP_HASH160,
    pubKeyHash,
    OPS.OP_EQUALVERIFY,
    OPS.OP_CHECKSIG
  ])
}

function decode (buffer) {
  typeforce(check, buffer)

  return buffer.slice(4, 24)
}

module.exports = {
  check: check,
  decode: decode,
  encode: encode
}
