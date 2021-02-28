// OP_SSTX OP_HASH160 {scriptHash} OP_EQUAL

var bscript = require('../../script')
var types = require('../../types')
var typeforce = require('typeforce')
var OPS = require('../../ops').ops

function check (script) {
  var buffer = bscript.compile(script)

  return buffer.length === 24 &&
    buffer[0] === OPS.OP_SSTX &&
    buffer[1] === OPS.OP_HASH160 &&
    buffer[2] === 0x14 &&
    buffer[23] === OPS.OP_EQUAL
}
check.toJSON = function () { return 'pubKeyHash output' }

function encode (scriptHash) {
  typeforce(types.Hash160bit, scriptHash)

  return bscript.compile([
    OPS.OP_SSTX,
    OPS.OP_HASH160,
    scriptHash,
    OPS.OP_EQUAL
  ])
}

function decode (buffer) {
  typeforce(check, buffer)

  return buffer.slice(3, 23)
}

module.exports = {
  check: check,
  decode: decode,
  encode: encode
}
