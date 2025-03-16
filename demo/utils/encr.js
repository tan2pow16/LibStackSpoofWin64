'use strict';

const fs = require('fs');
const path = require('path');

/*
 * Copyright (c) 2025, tan2pow16.
 *  All rights reserved.
 * 
 * The core of this scheme is derived from reversing the following sample:
 *  https://www.virustotal.com/gui/file/9f61bc7fd1fe047076e2140d4b42b8bae1f671091f9d15e330e7c4c094a6c6e7
 * I added a custom checksum and modified part of the algo to make the output a bit more scrambled.
 * Please note that this is likely not a standard cryptography algorithm and should be seen as insecure.
 * Do NOT use this to encrypt confidential data.
 */

const CRYPTOR_MAGIC = 0xCCCCCCCC;

function rol32(x, y)
{
  return (((x << y) & 0xFFFFFFFF) | (x >>> (0x20 - y))) >>> 0;
}

function hydrate_key(hex_key)
{
  if(!hex_key || !hex_key.length || typeof(hex_key) !== 'string')
  {
    throw new Error('Key must be a string.');
  }

  const dword_cnt = 0x10;

  let cache = Buffer.from(hex_key, 'hex');
  if(cache.length !== (hex_key.length >>> 1))
  {
    throw new Error('Key must be a HEX string.');
  }
  else if(!cache.length || (cache.length & 0x3))
  {
    throw new Error('Invalid key.');
  }

  let ret = new Uint32Array(dword_cnt);
  for(let i = 0 ; i < dword_cnt ; i++)
  {
    ret[i] = rol32(cache.readUInt32LE((i << 2) % cache.length), i);
  }
  return ret;
}

function encrypt(hydrated_key, buf)
{
  if(!hydrated_key || hydrated_key.constructor.name !== 'Uint32Array' || !hydrated_key.length)
  {
    throw new Error('Invalid scheduled key.');
  }

  if(!buf || !buf.length || buf.constructor.name !== 'Buffer')
  {
    throw new Error('Binary input must be a Buffer.');
  }

  let chksum = CRYPTOR_MAGIC;
  if(buf.length & 0x7)
  {
    let padding = Buffer.allocUnsafe(8 - (buf.length & 0x7));
    padding.fill(0);
    buf = Buffer.concat([buf, padding]);
  }

  let i, j, k, x, y, z, n;
  for(i = 0 ; i < buf.length ; i += 8)
  {
    x = buf.readUInt32LE(i);
    y = buf.readUInt32LE(i + 4);

    n = (x + y) >>> 0;

    for(j = 0 ; j < hydrated_key.length ; j++)
    {
      k = hydrated_key[j] ^ (i >>> 3);

      z = x;
      x = y;
      y = (z ^ rol32(k + x, k & 0x1F) ^ k) >>> 0;
    }

    chksum += (x ^ y);
    chksum ^= n;
    chksum >>>= 0;

    buf.writeUInt32LE(x, i);
    buf.writeUInt32LE(y, i + 4);
  }

  let header = Buffer.allocUnsafe(8);
  header.writeUInt32LE(CRYPTOR_MAGIC, 0);
  header.writeUInt32LE(chksum, 4);

  return Buffer.concat([header, buf]);
}

function __main__(args)
{
  if(args.length != 3)
  {
    console.log('Usage: node %s <path/to/shellcode.bin> <hex-key> <path/to/output.enc>', path.basename(__filename));
    return;
  }

  let hydrated = hydrate_key(args[1]);
  let buf = fs.readFileSync(args[0]);
  let enc = encrypt(hydrated, buf);
  fs.writeFileSync(args[2], enc);
}

if(require.main === module)
{
  __main__(process.argv.slice(2));
}
