#include <windows.h>

/*
 * Copyright (c) 2025, tan2pow16.
 *  All rights reserved.
 */

#define CRYPTOR_MAGIC 0xCCCCCCCC

typedef struct _HydratedKey
{
  DWORD dat[0x10];
} HydratedKey;

// Return the length in DWORD.
BYTE hex_key_decode(const char *hex_key, DWORD *out_key);
void ghetto_schedule_key(const DWORD *key, BYTE key_dw_len, HydratedKey *hydrated_key);
void ghetto_decrypt(const HydratedKey *hydrated_key, DWORD64 *crypted, DWORD64 *output, DWORD enc_qw_len, PDWORD opt_chksum_out);
BOOL ghetto_decrypt_shellcode(const HydratedKey *hydrated_key, DWORD64 *crypted, DWORD enc_qw_len);
