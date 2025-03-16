#include <stdint.h>

#include "generated.h"

// Members started with "_" should not be used in your code.
// "syscall_id" is only used when the trampoline target is a syscall instruction.
// All other members MUST be initialized before a trampoline call!
typedef struct _StackSpoofContext
{
  void *_trampoline_epilogue;
  void *_real_ret_addr;
  void *_preserve_rbx;
  void *_preserve_rdi;
  uint64_t fake_frame_size_2;
  void *fake_ret_addr_2;
  uint64_t fake_frame_size_1;
  uint64_t fake_frame_size_3;
  void *fake_ret_addr_3;
  uint64_t syscall_id;
  void *jmp_ptr_rbx_gadget_addr;
  void *_preserve_rsi;
  void *_preserve_r12;
  void *_preserve_r13;
  void *_preserve_r14;
  void *_preserve_r15;
} StackSpoofContext;

void *stackspoof_trampoline(
  void *arg1,
  void *arg2,
  void *arg3,
  void *arg4,
  StackSpoofContext *ctx,
  void *target_func_addr,
  uint64_t stack_args_count,
  void *arg5s,
  ...
);

void *find_jmp_ptr_rbx(void *base_addr, size_t size_limit);

// The first arg is actually a DWORD. I just make casts in the generated headers to make it more streamlined in use.
//  Following args are the actual args to the target function.
// Note: the trampoline can only take up to 20 arguments. Calling the trampoline with too many arguments may result in the
//  function failing to jump to the target and return -1.
void *stack_spoof_call_api(uint8_t args_cnt, uint64_t api_hash, ...);
void *stack_spoof_call_fptr(uint8_t args_cnt, void *fptr, ...);
