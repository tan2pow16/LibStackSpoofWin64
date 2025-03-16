#include <Windows.h>

#include "generated.h"

HMODULE GetModuleHandleH(IN UINT32 uModuleHash);
FARPROC GetProcAddressH(IN HMODULE hModule, IN UINT32 uApiHash);
FARPROC api_full_resolve64(UINT64 full_hash);
