// Coins supported by bitgo-bitcoinjs-lib
const typeforce = require('typeforce')

const coins = {
  BCH: 'bch',
  BSV: 'bsv',
  BTC: 'btc',
  BTG: 'btg',
  LTC: 'ltc',
  ZEC: 'zec',
  DASH: 'dash',
  CAPRICOIN: 'cpc',
  KMD: 'kmd'
}

coins.isBitcoin = function (network) {
  return typeforce.value(coins.BTC)(network.coin)
}

coins.isBitcoinCash = function (network) {
  return typeforce.value(coins.BCH)(network.coin)
}

coins.isBitcoinSV = function (network) {
  return typeforce.value(coins.BSV)(network.coin)
}

coins.isBitcoinGold = function (network) {
  return typeforce.value(coins.BTG)(network.coin)
}

coins.isDash = function (network) {
  return typeforce.value(coins.DASH)(network.coin)
}

coins.isLitecoin = function (network) {
  return typeforce.value(coins.LTC)(network.coin)
}

coins.isZcash = function (network) {
    return typeforce.value(coins.ZEC)(network.coin) || this.isKomodo(network);
}

coins.isKomodo = function (network) {
    return typeforce.value(coins.KMD)(network.coin)
}

coins.isCapricoin = function (network) {
  return typeforce.value(coins.CAPRICOIN)(network.coin)
}

coins.isValidCoin = typeforce.oneOf(
  coins.isBitcoin,
  coins.isBitcoinCash,
  coins.isBitcoinSV,
  coins.isBitcoinGold,
  coins.isLitecoin,
  coins.isZcash,
  coins.isCapricoin,
  coins.isKomodo
)

module.exports = coins
