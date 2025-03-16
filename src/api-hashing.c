// This file is modded from the project https://github.com/Maldev-Academy/MaldevAcademyLdr.1

#include "api-hashing.h"

#define kernel32dll_DJB2 kernel32dll_MODDED_DJB2
#define LoadLibraryA_DJB2 LoadLibraryA_MODDED_DJB2

typedef struct _LSA_UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING, * PUNICODE_STR;

typedef PVOID PACTIVATION_CONTEXT;

typedef struct _LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  ULONG Flags;
  WORD LoadCount;
  WORD TlsIndex;
  union {
    LIST_ENTRY HashLinks;
    struct {
      PVOID SectionPointer;
      ULONG CheckSum;
    };
  };
  union {
    ULONG TimeDateStamp;
    PVOID LoadedImports;
  };
  PACTIVATION_CONTEXT EntryPointActivationContext;
  PVOID PatchInformation;
  LIST_ENTRY ForwarderLinks;
  LIST_ENTRY ServiceTagLinks;
  LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
  ULONG                   Length;
  ULONG                   Initialized;
  PVOID                   SsHandle;
  LIST_ENTRY              InLoadOrderModuleList;
  LIST_ENTRY              InMemoryOrderModuleList;
  LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
  BOOLEAN                 InheritedAddressSpace;
  BOOLEAN                 ReadImageFileExecOptions;
  BOOLEAN                 BeingDebugged;
  BOOLEAN                 Spare;
  HANDLE                  Mutant;
  PVOID                   ImageBase;
  PPEB_LDR_DATA           LoaderData;
  PVOID                   ProcessParameters;
  PVOID                   SubSystemData;
  PVOID                   ProcessHeap;
  PVOID                   FastPebLock;
  PVOID                   FastPebLockRoutine;
  PVOID                   FastPebUnlockRoutine;
  ULONG                   EnvironmentUpdateCount;
  PVOID*       KernelCallbackTable;
  PVOID                   EventLogSection;
  PVOID                   EventLog;
  PVOID                   FreeList;
  ULONG                   TlsExpansionCounter;
  PVOID                   TlsBitmap;
  ULONG                   TlsBitmapBits[0x2];
  PVOID                   ReadOnlySharedMemoryBase;
  PVOID                   ReadOnlySharedMemoryHeap;
  PVOID*       ReadOnlyStaticServerData;
  PVOID                   AnsiCodePageData;
  PVOID                   OemCodePageData;
  PVOID                   UnicodeCaseTableData;
  ULONG                   NumberOfProcessors;
  ULONG                   NtGlobalFlag;
  BYTE                    Spare2[0x4];
  LARGE_INTEGER           CriticalSectionTimeout;
  ULONG                   HeapSegmentReserve;
  ULONG                   HeapSegmentCommit;
  ULONG                   HeapDeCommitTotalFreeThreshold;
  ULONG                   HeapDeCommitFreeBlockThreshold;
  ULONG                   NumberOfHeaps;
  ULONG                   MaximumNumberOfHeaps;
  PVOID**     ProcessHeaps;
  PVOID                   GdiSharedHandleTable;
  PVOID                   ProcessStarterHelper;
  PVOID                   GdiDCAttributeList;
  PVOID                   LoaderLock;
  ULONG                   OSMajorVersion;
  ULONG                   OSMinorVersion;
  ULONG                   OSBuildNumber;
  ULONG                   OSPlatformId;
  ULONG                   ImageSubSystem;
  ULONG                   ImageSubSystemMajorVersion;
  ULONG                   ImageSubSystemMinorVersion;
  ULONG                   GdiHandleBuffer[0x22];
  ULONG                   PostProcessInitRoutine;
  ULONG                   TlsExpansionBitmap;
  BYTE                    TlsExpansionBitmapBits[0x80];
  ULONG                   SessionId;
} PEB, * PPEB;

/*
*   An implementation of the 'djb2' string hashing algorithm
*   From : https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringDjb2.cpp
*/
static DWORD HashStringDjb2A(IN LPCSTR String)
{
  ULONG Hash = DJB2_MODDED_SEED;
  INT c = 0;

  while (c = *String++)
    Hash = ((Hash << 5) + Hash) + c;

  return Hash;
}

#define DJB2HASH(STR)    ( HashStringDjb2A( (LPCSTR)STR ) )

// replaces the 'memcpy' function
static VOID Memcpy(IN PVOID pDestination, IN PVOID pSource, SIZE_T sLength) 
{

  PBYTE D = (PBYTE)pDestination;
  PBYTE S = (PBYTE)pSource;

  while (sLength--)
    *D++ = *S++;
}

typedef HMODULE (WINAPI* fnLoadLibraryA)(IN LPCSTR lpLibFileName);

FARPROC GetProcAddressH(IN HMODULE hModule, IN UINT32 uApiHash) {
  PBYTE        pBase        = (PBYTE)hModule;
  PIMAGE_NT_HEADERS    pImgNtHdrs      = NULL;
  PIMAGE_EXPORT_DIRECTORY    pImgExportDir      = NULL;
  PDWORD        pdwFunctionNameArray    = NULL;
  PDWORD        pdwFunctionAddressArray    = NULL;
  PWORD        pwFunctionOrdinalArray    = NULL;
  DWORD        dwImgExportDirSize    = 0x00;

  if (!hModule || !uApiHash) {
    return NULL;
  }

  pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + ((PIMAGE_DOS_HEADER)pBase)->e_lfanew);
  if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
    return NULL;

  pImgExportDir    = (PIMAGE_EXPORT_DIRECTORY)(pBase + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  dwImgExportDirSize  = pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
  pdwFunctionNameArray  = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
  pdwFunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
  pwFunctionOrdinalArray  = (PWORD) (pBase + pImgExportDir->AddressOfNameOrdinals);


  for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
  
    CHAR*  pFunctionName    = (CHAR*)(pBase + pdwFunctionNameArray[i]);
    PVOID  pFunctionAddress  = (PVOID)(pBase + pdwFunctionAddressArray[pwFunctionOrdinalArray[i]]);

    if (DJB2HASH(pFunctionName) == uApiHash) {
      
      // Forwarded functions support:
      if ((((ULONG_PTR)pFunctionAddress) >= ((ULONG_PTR)pImgExportDir)) &&
        (((ULONG_PTR)pFunctionAddress) < ((ULONG_PTR)pImgExportDir) + dwImgExportDirSize)
        ) {
        CHAR  cForwarderName  [MAX_PATH]  = { 0 };
        DWORD  dwDotOffset      = 0x00;
        PCHAR  pcFunctionMod      = NULL;
        PCHAR  pcFunctionName      = NULL;

        Memcpy(cForwarderName, pFunctionAddress, strlen((PCHAR)pFunctionAddress));

        for (int i = 0; i < strlen((PCHAR)cForwarderName); i++) {

          if (((PCHAR)cForwarderName)[i] == '.') {
            dwDotOffset = i;         
            cForwarderName[i] = 0; 
            break;
          }
        }

        pcFunctionMod  = cForwarderName;
        pcFunctionName  = cForwarderName + dwDotOffset + 1;

        fnLoadLibraryA pLoadLibraryA = (fnLoadLibraryA)GetProcAddressH(GetModuleHandleH(kernel32dll_DJB2), LoadLibraryA_DJB2);
        if (pLoadLibraryA)
          return GetProcAddressH(pLoadLibraryA(pcFunctionMod), DJB2HASH(pcFunctionName));
      }

      return (FARPROC)pFunctionAddress;
    }

  }

  return NULL;
}

HMODULE GetModuleHandleH(IN UINT32 uModuleHash) {
  PPEB      pPeb = NULL;
  PPEB_LDR_DATA    pLdr = NULL;
  PLDR_DATA_TABLE_ENTRY  pDte = NULL;

  pPeb = (PPEB)__readgsqword(0x60);
  pLdr = (PPEB_LDR_DATA)(pPeb->LoaderData);
  pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

  // Return the handle of the local .exe image
  if (!uModuleHash)
    return (HMODULE)(pDte->InInitializationOrderLinks.Flink);

  while (pDte) {

    if (pDte->FullDllName.Buffer && pDte->FullDllName.Length < MAX_PATH) {

      CHAR  cLDllName[MAX_PATH] = { 0 };
      DWORD  x          = 0x00;

      while (pDte->FullDllName.Buffer[x]) {

        CHAR  wC = pDte->FullDllName.Buffer[x];

        // Convert to lowercase
        if (wC >= 'A' && wC <= 'Z')
          cLDllName[x] = wC - 'A' + 'a';
        // Copy other characters (numbers, special characters ...)
        else
          cLDllName[x] = wC;

        x++;
      }

      cLDllName[x] = '\0';

      if (DJB2HASH(pDte->FullDllName.Buffer) == uModuleHash || DJB2HASH(cLDllName) == uModuleHash)
        return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
    }

    // Move to the next node in the linked list
    pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
  }

  return NULL;
}

FARPROC api_full_resolve64(UINT64 full_hash)
{
  HMODULE m;

  m = GetModuleHandleH(full_hash >> 0x20);
  if(!m)
  {
    return NULL;
  }
  return GetProcAddressH(m, full_hash & 0xFFFFFFFF);
}
