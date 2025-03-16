#include <windows.h>

ULONG CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunction, const void *ImageBase, PDWORD64 size_output);
ULONG CalculateFunctionStackSizeWrapper(PVOID ReturnAddress, PDWORD64 size_output);
