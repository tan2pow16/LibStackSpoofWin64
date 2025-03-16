// Modded from https://github.com/susMdT/LoudSunRun

#include "api-hashing.h"
#include "camouflage.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) == 0)
#define STATUS_SUCCESS   ((NTSTATUS)0x00000000L)
#define true 1
#define MAX_STACK_SIZE 12000
#define RBP_OP_INFO 0x5

/* God Bless Vulcan Raven*/
typedef struct
{
    LPCWSTR dllPath;
    ULONG offset;
    ULONG totalStackSize;
    BOOL requiresLoadLibrary;
    BOOL setsFramePointer;
    PVOID returnAddress;
    BOOL pushRbp;
    ULONG countOfCodes;
    BOOL pushRbpIndex;
} StackFrame, * PStackFrame;

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;

typedef union _UNWIND_CODE {
    struct {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
    /*  UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1];
    *   union {
    *       OPTIONAL ULONG ExceptionHandler;
    *       OPTIONAL ULONG FunctionEntry;
    *   };
    *   OPTIONAL ULONG ExceptionData[]; */
} UNWIND_INFO, * PUNWIND_INFO;

/* Credit to VulcanRaven project for the original implementation of these two*/
// Modded: Return value now only holds the NTSTATUS. Output value will be put into the passed in pointer.
ULONG CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunction, const void *_ImageBase, PDWORD64 size_output)
{
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation = 0;
    ULONG operationInfo = 0;
    ULONG index = 0;
    ULONG frameOffset = 0;
    StackFrame stackFrame = { 0 };
    DWORD64 ImageBase = (DWORD64)_ImageBase;

    // [0] Sanity check incoming pointer.
    if (!pRuntimeFunction)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // [1] Loop over unwind info.
    // NB As this is a PoC, it does not handle every unwind operation, but
    // rather the minimum set required to successfully mimic the default
    // call stacks included.
    pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + ImageBase);
    while (index < pUnwindInfo->CountOfCodes)
    {
        unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;
        // [2] Loop over unwind codes and calculate
        // total stack space used by target Function.
        switch (unwindOperation) {
        case UWOP_PUSH_NONVOL:
            // UWOP_PUSH_NONVOL is 8 bytes.
            stackFrame.totalStackSize += 8;
            // Record if it pushes rbp as
            // this is important for UWOP_SET_FPREG.
            if (RBP_OP_INFO == operationInfo)
            {
                stackFrame.pushRbp = true;
                // Record when rbp is pushed to stack.
                stackFrame.countOfCodes = pUnwindInfo->CountOfCodes;
                stackFrame.pushRbpIndex = index + 1;
            }
            break;
        case UWOP_SAVE_NONVOL:
            //UWOP_SAVE_NONVOL doesn't contribute to stack size
            // but you do need to increment index.
            index += 1;
            break;
        case UWOP_ALLOC_SMALL:
            //Alloc size is op info field * 8 + 8.
            stackFrame.totalStackSize += ((operationInfo * 8) + 8);
            break;
        case UWOP_ALLOC_LARGE:
            // Alloc large is either:
            // 1) If op info == 0 then size of alloc / 8
            // is in the next slot (i.e. index += 1).
            // 2) If op info == 1 then size is in next
            // two slots.
            index += 1;
            frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
            if (operationInfo == 0)
            {
                frameOffset *= 8;
            }
            else
            {
                index += 1;
                frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
            }
            stackFrame.totalStackSize += frameOffset;
            break;
        case UWOP_SET_FPREG:
            // This sets rsp == rbp (mov rsp,rbp), so we need to ensure
            // that rbp is the expected value (in the frame above) when
            // it comes to spoof this frame in order to ensure the
            // call stack is correctly unwound.
            stackFrame.setsFramePointer = true;
            break;
        default:
            //printf("[-] Error: Unsupported Unwind Op Code\n");
            return STATUS_ASSERTION_FAILURE;
        }

        index += 1;
    }

    // If chained unwind information is present then we need to
    // also recursively parse this and add to total stack size.
    if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO))
    {
        index = pUnwindInfo->CountOfCodes;
        if (0 != (index & 1))
        {
            index += 1;
        }
        pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
        return CalculateFunctionStackSize(pRuntimeFunction, _ImageBase, size_output);
    }

    // Add the size of the return address (8 bytes).
    stackFrame.totalStackSize += 8;

    *size_output = stackFrame.totalStackSize;
    return STATUS_SUCCESS;
}

typedef PRUNTIME_FUNCTION (WINAPI* fnRtlLookupFunctionEntry)(DWORD64 ControlPc, PDWORD64 ImageBase, PUNWIND_HISTORY_TABLE HistoryTable);

// Modded: When the calculation fails, the fake frame size is defaulted to 0x10 bytes.
ULONG CalculateFunctionStackSizeWrapper(PVOID ReturnAddress, PDWORD64 size_output)
{
    NTSTATUS ret;
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;
    DWORD64 ImageBase = 0;
    PUNWIND_HISTORY_TABLE pHistoryTable = NULL;
    fnRtlLookupFunctionEntry pRtlLookupFunctionEntry;

    // [0] Sanity check return address.
    if (!ReturnAddress)
    {
        return STATUS_INVALID_PARAMETER;
    }

    pRtlLookupFunctionEntry = (fnRtlLookupFunctionEntry)api_full_resolve64(RtlLookupFunctionEntry_MODDED_DJB2_WITH_LIB);
    // [1] Locate RUNTIME_FUNCTION for given Function.
    pRuntimeFunction = pRtlLookupFunctionEntry((DWORD64)ReturnAddress, &ImageBase, pHistoryTable);
    if (NULL == pRuntimeFunction)
    {
        //printf("[!] STATUS_ASSERTION_FAILURE\n");
        return STATUS_ASSERTION_FAILURE;
    }

    // [2] Recursively calculate the total stack size for
    // the Function we are "returning" to.
    ret = CalculateFunctionStackSize(pRuntimeFunction, (void *)ImageBase, size_output);
    if(ret) // Parsing failed.
    {
        // Default to a fake frame size of 0x10 instead of crashing the program.
        *size_output = 0x10;
    }
    return ret;
}
