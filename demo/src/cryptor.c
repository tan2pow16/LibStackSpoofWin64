#include "cryptor.h"

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

BYTE hex_key_decode(const char *hex_key, DWORD *out_key)
{
  BYTE i, j, k, b, *_out_key;
  _out_key = (void *)out_key;

  i = 0;
  while(1)
  {
    j = i << 1;
    if(!hex_key[j])
    {
      // A valid key must be an array of DWORDs.
      if(i & 0x3)
      {
        return 0;
      }
      return (i >> 2); // A DWORD is 4-byte in size.
    }

    if(i >= 0x40)
    {
      return 0;
    }

    b = 0;
    for(k = 0 ; k < 2 ; k++, j++)
    {
      b <<= 4;
      if(hex_key[j] < 0x30)
      {
        // Not a hex
        return 0;
      }
      else if(hex_key[j] <= 0x39)
      {
        b |= (hex_key[j] - 0x30);
      }
      else if(hex_key[j] < 0x41)
      {
        // Not a hex
        return 0;
      }
      else if(hex_key[j] <= 0x46)
      {
        b |= (hex_key[j] + 10 - 0x41);
      }
      else if(hex_key[j] < 0x61)
      {
        // Not a hex
        return 0;
      }
      else if(hex_key[j] <= 0x66)
      {
        b |= (hex_key[j] + 10 - 0x61);
      }
      else
      {
        // Not a hex
        return 0;
      }
    }
    _out_key[i++] = b;
  }
}

inline DWORD rol32(DWORD x, BYTE y)
{
  return (x << y) | (x >> (0x20 - y));
}

void ghetto_schedule_key(const DWORD *key, BYTE key_dw_len, HydratedKey *hydrated_key)
{
  DWORD *_key;
  BYTE i;

  _key = (void *)key;
  for(i = 0 ; i < 0x10 ; i++)
  {
    hydrated_key->dat[i] = rol32(key[i % key_dw_len], i);
  }
}

void ghetto_decrypt(const HydratedKey *hydrated_key, DWORD64 *crypted, DWORD64 *output, DWORD enc_qw_len, PDWORD opt_chksum_out)
{
  DWORD i, k, x, y, z, *ptr;
  BYTE j;
  DWORD chksum;

  chksum = CRYPTOR_MAGIC;
  for(i = 0 ; i < enc_qw_len ; i++)
  {
    ptr = (void *)&crypted[i];
    x = ptr[0];
    y = ptr[1];

    chksum += (x ^ y);

    for(j = 0x10 ; j > 0 ; )
    {
      k = hydrated_key->dat[--j] ^ i;
      z = rol32(k + x, k & 0x1F) ^ k ^ y;

      y = x;
      x = z;
    }

    ptr = (void *)&output[i];
    ptr[0] = x;
    ptr[1] = y;

    chksum ^= (x + y);
  }

  if(opt_chksum_out)
  {
    *opt_chksum_out = chksum;
  }
}

BOOL ghetto_decrypt_shellcode(const HydratedKey *hydrated_key, DWORD64 *crypted, DWORD enc_qw_len)
{
  DWORD64 x;
  DWORD chksum;

  if(enc_qw_len <= 1)
  {
    return 0;
  }

  x = *crypted;
  if((x & 0xFFFFFFFF) != CRYPTOR_MAGIC)
  {
    return 0;
  }

  ghetto_decrypt(hydrated_key, &crypted[1], crypted, enc_qw_len - 1, &chksum);

  if((x >> 0x20) != chksum)
  {
    return 0;
  }

  return 1;
}