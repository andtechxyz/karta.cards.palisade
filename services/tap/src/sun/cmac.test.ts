import { describe, it, expect } from 'vitest';
import { aesCmac } from './cmac.js';

// NIST SP 800-38B Appendix D — AES-128 CMAC test vectors.
//
// Same vectors palisade-sun's CMAC port was cross-checked against; if any of
// these regress, the SUN verifier silently breaks for real cards.

const KEY = Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex');

const VECTORS = [
  { name: 'M len 0',  msg: Buffer.alloc(0),                                    mac: 'bb1d6929e95937287fa37d129b756746' },
  { name: 'M len 16', msg: Buffer.from('6bc1bee22e409f96e93d7e117393172a', 'hex'), mac: '070a16b46b4d4144f79bdd9dd04a287c' },
  {
    name: 'M len 40',
    msg: Buffer.from(
      '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411',
      'hex',
    ),
    mac: 'dfa66747de9ae63030ca32611497c827',
  },
  {
    name: 'M len 64',
    msg: Buffer.from(
      '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710',
      'hex',
    ),
    mac: '51f0bebf7e3b9d92fc49741779363cfe',
  },
];

describe('aesCmac — NIST SP 800-38B vectors', () => {
  for (const v of VECTORS) {
    it(v.name, () => {
      expect(aesCmac(KEY, v.msg).toString('hex')).toBe(v.mac);
    });
  }
});
