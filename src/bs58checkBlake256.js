var Buffer = require('safe-buffer').Buffer
var bblake256 = require('./crypto').blake256
var bs58 = require('bs58')

function decodeBlake256 (address) {
  var buffer = bs58.decode(address)
  if (buffer.length !== 26) throw new Error(address + ' invalid address length')
  var payload
  try {
    payload = decode(buffer)
  } catch (e) {
    throw new Error(address + ' ' + e.message)
  }
  return payload
}

function decodeBlake256Key (key) {
  var buffer = bs58.decode(key)
  return decode(buffer)
}

function decode (buffer) {
  var want = buffer.slice(-4)
  var payload = buffer.slice(0, -4)
  var got = bblake256(bblake256(payload)).slice(0, 4)

  if (want[0] ^ got[0] |
      want[1] ^ got[1] |
      want[2] ^ got[2] |
      want[3] ^ got[3]) throw new Error('invalid checksum')

  return payload
}

function encodeBlake256 (payload) {
  var checksum = bblake256(bblake256(payload)).slice(0, 4)
  return bs58.encode(Buffer.concat([payload, checksum]))
}

module.exports = {
  encodeBlake256: encodeBlake256,
  decodeBlake256: decodeBlake256,
  decodeBlake256Key: decodeBlake256Key
}
