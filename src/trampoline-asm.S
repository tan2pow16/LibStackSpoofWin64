# Copyright (c) 2025, tan2pow16.
#  All rights reserved.

 .text
 .globl stack_spoof_call_fptr
 #
 # Stack structure:
 #  Stack args | @ S+0x150 | BP+0x30 <0x80 MAX>
 #  [RESERVED RCX, RDX, R8, R9] @ S+0x130 | BP+0x10 <0x20>
 #  [RET ADDR] @ S+0x128 | BP+8 <8>
 #  [RBP bkup] @ S+0x120 | BP+0 <8>
 #  SpoofCallContext @ S+0xA0 | BP-80 <0x80>
 #  callee_stack_args @ S+0x20 | BP-0x100 <0x80 MAX>
 #  reserved4callee @ S+0x0 | BP-0x120 <0x20>
 #
stack_spoof_call_fptr:
 push  %rbp
 movq  %rsp, %rbp
 subq  $0x120, %rsp

 movq  %r9, 0x28(%rbp)
 movq  %r8, 0x20(%rbp)
 # movq  %rdx, 0x18(%rbp) # %rdx = target function ptr. Will be saved in the stack right after prologue so I don't make an extra copy here.
 movzx %cl, %rcx
 movq  %rcx, 0x10(%rbp)   # %cl = args count of the target function

 movq  %rdx, 0x28(%rsp)   # 6th arg <- target func ptr, save it first. Later misc calls won't touch it so its fine.

 leaq  -0x80(%rbp), %rcx
 call  setup_camouflage

 leaq  -0x80(%rbp), %rax
 movq  %rax, 0x20(%rsp)   # 5th arg <- spoof ctx

 xorq  %r9, %r9           # Prepare the 7th arg for the spoofer prologue (stack args count for the target)

 movq  0x10(%rbp), %rax   # The value is clamped to 0x100 at this point. There cannot be that many args lol  
 movzx %al, %rax
 cmpl  $0x4, %eax
 jle   _spoof_call_prepare_reg_args
 cmpl  $0x10, %eax
 jle   _spoof_call_prepare_stack_args
 xorq  %rax, %rax         # Too many arguments for the stack frame of this function.
 decq  %rax               # Return -1
 jmp   _spoof_call_ret

 # Prepare stack args
_spoof_call_prepare_stack_args:
 subl  $0x4, %eax
 movl  %eax, %r9d

 leaq  0x38(%rsp), %rdx   # Starting from the 8th arg of the spoofer prologue
 leaq  0x40(%rbp), %r8    # The 7th arg passed to this function (1 push + 1 ret addr + 4 * qword reserved space + 2 * qword skipped stack args)
_spoof_call_prepare_reg_args_loop:
 movq  (%r8), %rcx
 movq  %rcx, (%rdx)
 addq  $0x8, %r8
 addq  $0x8, %rdx
 decl  %eax
 jnz   _spoof_call_prepare_reg_args_loop

_spoof_call_prepare_reg_args:
 movq  %r9, 0x30(%rsp)    # Number of stack args, required by the spoofer trampoline prologue
 movq  0x20(%rbp), %rcx   # Recover the args from the saved stack
 movq  0x28(%rbp), %rdx
 movq  0x30(%rbp), %r8
 movq  0x38(%rbp), %r9    # Supposedly the 5th arg to this func, or the 4rd arg to the target. The stack should be full of crap that even if the argument does not exist, it wouldn't be a overflow read.
 call  stackspoof_trampoline

_spoof_call_ret:
 addq  $0x120, %rsp
 pop   %rbp
 ret

# ================================ #

 .globl stack_spoof_call_api
stack_spoof_call_api:
 push  %rbp
 movq  %rsp, %rbp
 subq  $0x20, %rsp

 movq  %r9, 0x28(%rbp)
 movq  %r8, 0x20(%rbp)
 movq  %rcx, 0x10(%rbp)

 movq  %rdx, %rcx         # 64-bit full hash
 call  api_full_resolve64
 movq  %rax, %rdx

 movq  0x10(%rbp), %rcx
 movq  0x20(%rbp), %r8
 movq  0x28(%rbp), %r9

 addq  $0x20, %rsp
 popq  %rbp
 jmp   stack_spoof_call_fptr  # Tail call

# ================================ #

 .def setup_camouflage; .scl 2; .type 32; .endef
 .def api_full_resolve64; .scl 2; .type 32; .endef
 .def stackspoof_trampoline; .scl 2; .type 32; .endef
