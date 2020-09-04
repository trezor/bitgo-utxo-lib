var OPS = require('bitcoin-ops')
// The following are Decred OP codes.
OPS.OP_SSTX = 0xba
OPS.OP_SSTXCHANGE = 0xbd
OPS.OP_SSGEN = 0xbb
OPS.OP_SSRTX = 0xbc

var map = {}
for (var op in OPS) {
  var code = OPS[op]
  map[code] = op
}

module.exports = {
  ops: OPS,
  reversed: map
}
