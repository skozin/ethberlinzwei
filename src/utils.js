import BigNumber from 'bignumber.js'
import * as ethUtil from 'ethereumjs-util'

export function signUint256(num, privateKeyBuf) {
  const buf = Buffer.from(new BigNumber(num).toString(16).padStart(64, '0'), 'hex')
  return signBuf(buf, privateKeyBuf)
}

export function signBuf(buf, privateKeyBuf) {
  const sig = ethUtil.ecsign(ethUtil.sha256(buf), privateKeyBuf)
  return concatSignature(sig)
}

export function concatSignature(sig) {
  let {v, r, s} = sig

  r = ethUtil.fromSigned(r)
  s = ethUtil.fromSigned(s)

  r = ethUtil.setLengthLeft(ethUtil.toUnsigned(r), 32).toString('hex')
  s = ethUtil.setLengthLeft(ethUtil.toUnsigned(s), 32).toString('hex')
  v = ethUtil.stripHexPrefix(ethUtil.intToHex(v))

  return ethUtil.addHexPrefix(r.concat(s, v).toString('hex'))
}
