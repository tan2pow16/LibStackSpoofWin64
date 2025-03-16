# Modded from https://github.com/susMdT/LoudSunRun/blob/main/test.asm

 .text
 .globl stackspoof_trampoline
stackspoof_trampoline:
# trampoline_prologue
  pop    %rax
  mov    %rdi, %r10
  mov    %rsi, %r11
  mov    0x20(%rsp), %rdi
  mov    0x28(%rsp), %rsi
  mov    %r10, 0x18(%rdi)
  mov    %r11, 0x58(%rdi)
  mov    %r12, 0x60(%rdi)
  mov    %r13, 0x68(%rdi)
  mov    %r14, 0x70(%rdi)
  mov    %r15, 0x78(%rdi)
  mov    %rax, %r12
  xor    %r11, %r11
  mov    0x30(%rsp), %r13
  mov    $0x200, %r14d
  add    $0x8, %r14
  add    0x38(%rdi), %r14
  add    0x30(%rdi), %r14
  add    0x20(%rdi), %r14
  sub    $0x20, %r14
  mov    %rsp, %r10
  add    $0x30, %r10
_trampoline_stack_args_cpy_loop:
  xor    %r15, %r15
  cmp    %r13, %r11
  je     _trampoline_spinup
  sub    $0x8, %r14
  mov    %rsp, %r15
  sub    %r14, %r15
  add    $0x8, %r10
  pushq  (%r10)
  popq   (%r15)
  add    $0x1, %r11
  jmp    _trampoline_stack_args_cpy_loop
_trampoline_spinup:
  sub    $0x200, %rsp
  pushq  $0x0
  sub    0x38(%rdi), %rsp
  mov    0x40(%rdi), %r11
  mov    %r11, (%rsp)
  sub    0x20(%rdi), %rsp
  mov    0x28(%rdi), %r11
  mov    %r11, (%rsp)
  sub    0x30(%rdi), %rsp
  mov    0x50(%rdi), %r11
  mov    %r11, (%rsp)
  mov    %rsi, %r11
  mov    %r12, 0x8(%rdi)
  mov    %rbx, 0x10(%rdi)
  lea    _trampoline_epilogue(%rip), %rbx
  mov    %rbx, (%rdi)
  mov    %rdi, %rbx
  mov    %rcx, %r10
  mov    0x48(%rdi), %rax
  jmpq   *%r11
_trampoline_epilogue:
  mov    %rbx, %rcx
  add    $0x200, %rsp
  add    0x30(%rbx), %rsp
  add    0x20(%rbx), %rsp
  add    0x38(%rbx), %rsp
  mov    0x10(%rcx), %rbx
  mov    0x18(%rcx), %rdi
  mov    0x58(%rcx), %rsi
  mov    0x60(%rcx), %r12
  mov    0x68(%rcx), %r13
  mov    0x70(%rcx), %r14
  mov    0x78(%rcx), %r15
  jmpq   *0x8(%rcx)
