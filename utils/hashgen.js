'use strict';

const crypto = require('crypto');
const fs = require('fs');

/*
 * Copyright (c) 2025, tan2pow16.
 *  All rights reserved.
 */

function salted_djb2(salt, str)
{
  let ret = 0x1505;
  for(let i = 0 ; i < salt.length ; i++)
  {
    ret = (((ret << 5) + ret + salt[i]) & 0xFFFFFFFF) >>> 0;
  }

  if(!str)
  {
    // Hash of salt, aka the modded DJB2 seed.
    //  The use of salt instead of some random DWORD seed is to make sure the
    //  calc remains as "robust" as the original design. Though DJB2 is an
    //  insecure hash lol.
    return ret;
  }

  let buf = Buffer.from(str, 'ascii');
  for(let i = 0 ; i < buf.length ; i++)
  {
    ret = (((ret << 5) + ret + buf[i]) & 0xFFFFFFFF) >>> 0;
  }
  return ret;
}

function __main__()
{
  // Make sure DLL names are in ALL LOWER CASES!
  //  Also make sure the function names are grouped with the DLL it belongs to!
  let list = JSON.parse(fs.readFileSync(`${__dirname}/../src/hash-apis.json`));

  let salt = Buffer.allocUnsafe(4);
  crypto.randomFillSync(salt);

  let lines = [
    '// These are dynamically generated to evade hash signatures check.',
    '// Modify `hash-apis.json` instead, as this file gets overwritten at build time.',
    '',
    `#define DJB2_MODDED_SEED 0x${salted_djb2(salt).toString(16)}`,
    ''
  ];

  let dlls = Object.keys(list);
  for(let dll of dlls)
  {
    let apis = list[dll];
    dll = dll.toLowerCase();

    let dll_hash = salted_djb2(salt, dll);
    lines.push(`#define ${dll.replace('.', '')}_MODDED_DJB2 0x${dll_hash.toString(16)}`);

    let dll_hash_shl32 = BigInt(dll_hash) << 32n;
    for(let api of apis)
    {
      let hash = salted_djb2(salt, api);
      lines.push(`#define ${api}_MODDED_DJB2 0x${hash.toString(16)}`);

      let qhash = dll_hash_shl32 | BigInt(hash);
      lines.push(`#define ${api}_MODDED_DJB2_WITH_LIB 0x${qhash.toString(16)}`);
    }
  }

  lines.push('');

  fs.writeFileSync(`${__dirname}/../src/generated.h`, lines.join('\n'));
}

if(require.main === module)
{
  __main__();
}
