/*
   american fuzzy lop - injectable parts
   -------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Copyright 2013, 2014, 2015 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This file houses the assembly-level instrumentation injected into fuzzed
   programs. The instrumentation stores XORed pairs of data: identifiers of the
   currently executing branch and the one that executed immediately before.

   TL;DR: the instrumentation does shm_trace_map[cur_loc ^ prev_loc]++

   The code is designed for 32-bit and 64-bit x86 systems. Both modes should
   work everywhere except for Apple systems. Apple does relocations differently
   from everybody else, so since their OSes have been 64-bit for a longer while,
   I didn't go through the mental effort of porting the 32-bit code.

   In principle, similar code should be easy to inject into any well-behaved
   binary-only code (e.g., using DynamoRIO). Conditional jumps offer natural
   targets for instrumentation, and should offer comparable probe density.

 */

#ifndef _HAVE_AFL_AS_H
#define _HAVE_AFL_AS_H

#include "config.h"
#include "types.h"

/* 
   ------------------
   Performances notes
   ------------------

   Contributions to make this code faster are appreciated! Here are some
   rough notes that may help with the task:

   - Only the trampoline_fmt and the non-setup __afl_maybe_log code paths are
     really worth optimizing; the setup / fork server stuff matters a lot less
     and should be mostly just kept readable.

   - We're aiming for modern CPUs with out-of-order execution and large
     pipelines; the code is mostly follows intuitive, human-readable
     instruction ordering, because "textbook" manual reorderings make no
     substantial difference.

   - Interestingly, instrumented execution isn't a lot faster if we store a
     variable pointer to the setup, log, or return routine and then do a reg
     call from within trampoline_fmt. It does speed up non-instrumented
     execution quite a bit, though, since that path just becomes
     push-call-ret-pop.

   - There is also not a whole lot to be gained by doing SHM attach at a
     fixed address instead of retrieving __afl_area_ptr. Although it allows us
     to have a shorter log routine inserted for conditional jumps and jump
     labels (for a ~10% perf gain), there is a risk of bumping into other
     allocations created by the program or by tools such as ASAN.

   - popf is *awfully* slow, which is why we're doing the lahf / sahf +
     overflow test trick. Unfortunately, this forces us to taint eax / rax, but
     this dependency on a commonly-used register still beats the alternative of
     using pushf / popf.

     One possible optimization is to avoid touching flags by using a circular
     buffer that stores just a sequence of current locations, with the XOR stuff
     happening offline. Alas, this doesn't seem to have a huge impact:

     https://groups.google.com/d/msg/afl-users/MsajVf4fRLo/2u6t88ntUBIJ

   - Preforking one child a bit sooner, and then waiting for the "go" command
     from within the child, doesn't offer major performance gains; fork() seems
     to be relatively inexpensive these days. Preforking multiple children does
     help, but badly breaks the "~1 core per fuzzer" design, making it harder to
     scale up. Maybe there is some middle ground.

   Perhaps of note: in the 64-bit version for all platforms except for Apple,
   the instrumentation is done slightly differently than on 32-bit, with
   __afl_prev_loc and __afl_area_ptr being local to the object file (.lcomm),
   rather than global (.comm). This is to avoid GOTRELPC lookups in the critical
   code path, which AFAICT, are otherwise unavoidable if we want gcc -shared to
   work; simple relocations between .bss and .text won't work on most 64-bit
   platforms in such a case.

   (Fun fact: on Apple systems, .lcomm can segfault the linker.)

   The side effect is that state transitions are measured in a somewhat
   different way, with previous tuple being recorded separately within the scope
   of every .c file. This should have no impact in any practical sense.

   Another side effect of this design is that getenv() will be called once per
   every .o file when running in non-instrumented mode; and since getenv() tends
   to be optimized in funny ways, we need to be very careful to save every
   oddball register it may touch.

 */

static const u8* trampoline_fmt_32 =

  "\n"
  "/* --- AFL TRAMPOLINE (32-BIT) --- */\n"
  "\n"
  ".align 4\n"
  "\n"
  "leal -16(%%esp), %%esp\n"
  "movl %%edi,  0(%%esp)\n"
  "movl %%edx,  4(%%esp)\n"
  "movl %%ecx,  8(%%esp)\n"
  "movl %%eax, 12(%%esp)\n"
  "movl $0x%08x, %%ecx\n"             // 向ecx中存入识别代码块的随机桩代码id
  "call __afl_maybe_log\n"            //调用__afl_maybe_log函数
  "movl 12(%%esp), %%eax\n"
  "movl  8(%%esp), %%ecx\n"
  "movl  4(%%esp), %%edx\n"
  "movl  0(%%esp), %%edi\n"
  "leal 16(%%esp), %%esp\n"
  "\n"
  "/* --- END --- */\n"
  "\n";
//在插桩过程中保护原有现场
static const u8* trampoline_fmt_64 =

  "\n"
  "/* --- AFL TRAMPOLINE (64-BIT) --- */\n"
  "\n"
  ".align 4\n"
  "\n"
  "leaq -(128+24)(%%rsp), %%rsp\n"    //将栈顶抬高128+24个字节
  "movq %%rdx,  0(%%rsp)\n"           //保存在_afl_maybe_loop中会被覆盖的rdx、rcx、rax寄存器压栈
  "movq %%rcx,  8(%%rsp)\n"           //只有在mov rcx, xxx这里不同，其xxx的取值就是随机数R(MAP_SIZE),以此来标识与区分每个分支点，然后传入__afl_maybe_log作为第二个参数调用这个函数
  "movq %%rax, 16(%%rsp)\n"     
  "movq $0x%08x, %%rcx\n"             //64位下使用的寄存器是rcx；代码块编号当作参数放入rcx；将rcx的值设置为fprintf()函数要打印的变量内容
  "call __afl_maybe_log\n"            //调用__afl_maybe_log函数
  "movq 16(%%rsp), %%rax\n"           //恢复寄存器
  "movq  8(%%rsp), %%rcx\n"
  "movq  0(%%rsp), %%rdx\n"
  "leaq (128+24)(%%rsp), %%rsp\n"     //恢复栈顶位置
  "\n"
  "/* --- END --- */\n"
  "\n";

//和forkserver相关
static const u8* main_payload_32 = 

  "\n"
  "/* --- AFL MAIN PAYLOAD (32-BIT) --- */\n"
  "\n"
  ".text\n"
  ".att_syntax\n"
  ".code32\n"
  ".align 8\n"
  "\n"

  "__afl_maybe_log:\n"
  "\n"
  "  lahf\n"
  "  seto %al\n"
  "\n"
  "  /* Check if SHM region is already mapped. */\n"
  "\n"
  "  movl  __afl_area_ptr, %edx\n"                    //首先检查_afl_area_ptr是否为0，即是否共享内存已经被设置了。换句话说，只有第一个__afl_maybe_log会执行这个if里的代码
  "  testl %edx, %edx\n"
  "  je    __afl_setup\n"
  "\n"
  "__afl_store:\n"
  "\n"
  "  /* Calculate and store hit for the code location specified in ecx. There\n"
  "     is a double-XOR way of doing this without tainting another register,\n"
  "     and we use it on 64-bit systems; but it's slower for 32-bit ones. */\n"
  "\n"
#ifndef COVERAGE_ONLY
  "  movl __afl_prev_loc, %edi\n"
  "  xorl %ecx, %edi\n"
  "  shrl $1, %ecx\n"
  "  movl %ecx, __afl_prev_loc\n"
#else
  "  movl %ecx, %edi\n"
#endif /* ^!COVERAGE_ONLY */
  "\n"
#ifdef SKIP_COUNTS
  "  orb  $1, (%edx, %edi, 1)\n"
#else
  "  incb (%edx, %edi, 1)\n"
#endif /* ^SKIP_COUNTS */
  "\n"
  "__afl_return:\n"
  "\n"
  "  addb $127, %al\n"
  "  sahf\n"
  "  ret\n"
  "\n"
  ".align 8\n"
  "\n"
  "__afl_setup:\n"
  "\n"
  "  /* Do not retry setup if we had previous failures. */\n"
  "\n"
  "  cmpb $0, __afl_setup_failure\n"        //如果_afl_area_ptr为0，即共享内存还没被设置，则判断_afl_setup_failure是否为真，如果为真，则代表setup失败，直接返回
  "  jne  __afl_return\n"
  "\n"
  "  /* Map SHM, jumping to __afl_setup_abort if something goes wrong.\n"
  "     We do not save FPU/MMX/SSE registers here, but hopefully, nobody\n"
  "     will notice this early in the game. */\n"
  "\n"
  "  pushl %eax\n"
  "  pushl %ecx\n"
  "\n"
  "  pushl $.AFL_SHM_ENV\n"
  "  call  getenv\n"
  "  addl  $4, %esp\n"
  "\n"
  "  testl %eax, %eax\n"
  "  je    __afl_setup_abort\n"
  "\n"
  "  pushl %eax\n"
  "  call  atoi\n"
  "  addl  $4, %esp\n"
  "\n"
  "  pushl $0          /* shmat flags    */\n"
  "  pushl $0          /* requested addr */\n"
  "  pushl %eax        /* SHM ID         */\n"
  "  call  shmat\n"
  "  addl  $12, %esp\n"
  "\n"
  "  cmpl $-1, %eax\n"
  "  je   __afl_setup_abort\n"
  "\n"
  "  /* Store the address of the SHM region. */\n"
  "\n"
  "  movl %eax, __afl_area_ptr\n"
  "  movl %eax, %edx\n"
  "\n"
  "  popl %ecx\n"
  "  popl %eax\n"
  "\n"
  "__afl_forkserver:\n"
  "\n"
  "  /* Enter the fork server mode to avoid the overhead of execve() calls. */\n"
  "\n"
  "  pushl %eax\n"
  "  pushl %ecx\n"
  "  pushl %edx\n"
  "\n"
  "  /* Phone home and tell the parent that we're OK. (Note that signals with\n"
  "     no SA_RESTART will mess it up). If this fails, assume that the fd is\n"
  "     closed because we were execve()d from an instrumented binary, or because\n" 
  "     the parent doesn't want to use the fork server. */\n"
  "\n"
  "  pushl $4          /* length    */\n"
  "  pushl $__afl_temp /* data      */\n"
  "  pushl $" STRINGIFY((FORKSRV_FD + 1)) "  /* file desc */\n"
  "  call  write\n"
  "  addl  $12, %esp\n"
  "\n"
  "  cmpl  $4, %eax\n"
  "  jne   __afl_fork_resume\n"
  "\n"
  "__afl_fork_wait_loop:\n"
  "\n"
  "  /* Wait for parent by reading from the pipe. Abort if read fails. */\n"
  "\n"
  "  pushl $4          /* length    */\n"
  "  pushl $__afl_temp /* data      */\n"
  "  pushl $" STRINGIFY(FORKSRV_FD) "        /* file desc */\n"
  "  call  read\n"
  "  addl  $12, %esp\n"
  "\n"
  "  cmpl  $4, %eax\n"
  "  jne   __afl_die\n"
  "\n"
  "  /* Once woken up, create a clone of our process. This is an excellent use\n"
  "     case for syscall(__NR_clone, 0, CLONE_PARENT), but glibc boneheadedly\n"
  "     caches getpid() results and offers no way to update the value, breaking\n"
  "     abort(), raise(), and a bunch of other things :-( */\n"
  "\n"
  "  call fork\n"
  "\n"
  "  cmpl $0, %eax\n"
  "  jl   __afl_die\n"
  "  je   __afl_fork_resume\n"
  "\n"
  "  /* In parent process: write PID to pipe, then wait for child. */\n"
  "\n"
  "  movl  %eax, __afl_fork_pid\n"
  "\n"
  "  pushl $4              /* length    */\n"
  "  pushl $__afl_fork_pid /* data      */\n"
  "  pushl $" STRINGIFY((FORKSRV_FD + 1)) "      /* file desc */\n"
  "  call  write\n"
  "  addl  $12, %esp\n"
  "\n"
  "  pushl $0             /* no flags  */\n"
  "  pushl $__afl_temp    /* status    */\n"
  "  pushl __afl_fork_pid /* PID       */\n"
  "  call  waitpid\n"
  "  addl  $12, %esp\n"
  "\n"
  "  cmpl  $0, %eax\n"
  "  jle   __afl_die\n"
  "\n"
  "  /* Relay wait status to pipe, then loop back. */\n"
  "\n"
  "  pushl $4          /* length    */\n"
  "  pushl $__afl_temp /* data      */\n"
  "  pushl $" STRINGIFY((FORKSRV_FD + 1)) "  /* file desc */\n"
  "  call  write\n"
  "  addl  $12, %esp\n"
  "\n"
  "  jmp __afl_fork_wait_loop\n"
  "\n"
  "__afl_fork_resume:\n"
  "\n"
  "  /* In child process: close fds, resume execution. */\n"
  "\n"
  "  pushl $" STRINGIFY(FORKSRV_FD) "\n"
  "  call  close\n"
  "\n"
  "  pushl $" STRINGIFY((FORKSRV_FD + 1)) "\n"
  "  call  close\n"
  "\n"
  "  addl  $8, %esp\n"
  "\n"
  "  popl %edx\n"
  "  popl %ecx\n"
  "  popl %eax\n"
  "  jmp  __afl_store\n"
  "\n"
  "__afl_die:\n"
  "\n"
  "  xorl %eax, %eax\n"
  "  call _exit\n"
  "\n"
  "__afl_setup_abort:\n"
  "\n"
  "  /* Record setup failure so that we don't keep calling\n"
  "     shmget() / shmat() over and over again. */\n"
  "\n"
  "  incb __afl_setup_failure\n"
  "  popl %ecx\n"
  "  popl %eax\n"
  "  jmp __afl_return\n"
  "\n"
  ".AFL_VARS:\n"
  "\n"
  "  .comm   __afl_area_ptr, 4, 32\n"
  "  .comm   __afl_setup_failure, 1, 32\n"
#ifndef COVERAGE_ONLY
  "  .comm   __afl_prev_loc, 4, 32\n"
#endif /* !COVERAGE_ONLY */
  "  .comm   __afl_fork_pid, 4, 32\n"
  "  .comm   __afl_temp, 4, 32\n"
  "\n"
  ".AFL_SHM_ENV:\n"
  "  .asciz \"" SHM_ENV_VAR "\"\n"
  "\n"
  "/* --- END --- */\n"
  "\n";

/* The OpenBSD hack is due to lahf and sahf not being recognized by some
   versions of binutils: http://marc.info/?l=openbsd-cvs&m=141636589924400

   The Apple code is a bit different when calling libc functions because
   they are doing relocations differently from everybody else. We also need
   to work around the crash issue with .lcomm and the fact that they don't
   recognize .string. */

#ifdef __APPLE__
#  define CALL_L64(str)		"call _" str "\n"
#else
#  define CALL_L64(str)		"call " str "@PLT\n"
#endif /* ^__APPLE__ */

static const u8* main_payload_64 = 

  "\n"
  "/* --- AFL MAIN PAYLOAD (64-BIT) --- */\n"
  "\n"
  ".text\n"
  ".att_syntax\n"
  ".code64\n"
  ".align 8\n"
  "\n"
  "__afl_maybe_log:\n"
  "\n"
#if defined(__OpenBSD__)  || (defined(__FreeBSD__) && (__FreeBSD__ < 9))
  "  .byte 0x9f /* lahf */\n"
#else
  //对于FLAGS寄存器，在高8位中只有OF（溢出）标志位会受影响，对flags寄存器的保存恢复：
  //lahf用于将标志寄存器的低八位送入AH，即将标志寄存器FLAGS中的SF、ZF、AF、PF、CF五个标志位分别传送到累加器AH的对应位（八位中有三位是无效的）
  "  lahf\n"   //使用 lahf 指令（加载状态标志位到AH）将EFLAGS寄存器的低八位复制到 AH，被复制的标志位包括：符号标志位（SF）、零标志位（ZF）、辅助进位标志位（AF）、奇偶标志位（PF）和进位标志位（CF），使用该指令可以方便地将标志位副本保存在变量中
#endif /* ^__OpenBSD__, etc */
  "  seto  %al\n"   //使用 seto 指令溢出置位.保存OF标志位至al,如OF=1, al=11111111=127
  "\n"
  "  /* Check if SHM region is already mapped. */\n"
  "\n"
  "  movq  __afl_area_ptr(%rip), %rdx\n"
  "  testq %rdx, %rdx\n"
  "  je    __afl_setup\n"
  "\n"
  "__afl_store:\n"        //经过两次异或之后，再将 _afl_prev_loc 右移一位作为新的 _afl_prev_loc，最后再共享内存中存储当前插桩位置的地方计数加一
  "\n"
  "  /* Calculate and store hit for the code location specified in rcx. */\n"
  "\n"
#ifndef COVERAGE_ONLY
  "  xorq __afl_prev_loc(%rip), %rcx\n"
  "  xorq %rcx, __afl_prev_loc(%rip)\n"
  "  shrq $1, __afl_prev_loc(%rip)\n"
#endif /* ^!COVERAGE_ONLY */
  "\n"
#ifdef SKIP_COUNTS
  "  orb  $1, (%rdx, %rcx, 1)\n"
#else
  "  incb (%rdx, %rcx, 1)\n"
#endif /* ^SKIP_COUNTS */
  "\n"
  "__afl_return:\n"
  "\n"
  "  addb $127, %al\n"      //恢复OF中标志位
#if defined(__OpenBSD__)  || (defined(__FreeBSD__) && (__FreeBSD__ < 9))
  "  .byte 0x9e /* sahf */\n"
#else
  "  sahf\n"            //将AH中的值恢复至flags低8位
#endif /* ^__OpenBSD__, etc */
  "  ret\n"
  "\n"
  ".align 8\n"
  "\n"
  "__afl_setup:\n"          //该部分的主要作用为初始化 __afl_area_ptr ，且只在运行到第一个桩时进行本次初始化
  "\n"
  "  /* Do not retry setup if we had previous failures. */\n"
  "\n"
  "  cmpb $0, __afl_setup_failure(%rip)\n"
  "  jne __afl_return\n"
  "\n"
  "  /* Check out if we have a global pointer on file. */\n"
  "\n"
#ifndef __APPLE__
  "  movq  __afl_global_area_ptr@GOTPCREL(%rip), %rdx\n"
  "  movq  (%rdx), %rdx\n"
#else
  "  movq  __afl_global_area_ptr(%rip), %rdx\n"
#endif /* !^__APPLE__ */
  "  testq %rdx, %rdx\n"      //检查 __afl_global_area_ptr 文件指针是否为NULL
  "  je    __afl_setup_first\n"
  "\n"
  "  movq %rdx, __afl_area_ptr(%rip)\n"   //如果不为NULL，将 __afl_global_area_ptr 的值赋给 __afl_area_ptr，然后跳转到 __afl_store
  "  jmp  __afl_store\n" 
  "\n"
  "__afl_setup_first:\n"
  "\n"
  "  /* Save everything that is not yet saved and that may be touched by\n"
  "     getenv() and several other libcalls we'll be relying on. */\n"
  "\n"
  "  leaq -352(%rsp), %rsp\n"
  "\n"
  "  movq %rax,   0(%rsp)\n"    //保存所有寄存器的值，包括 xmm 寄存器组
  "  movq %rcx,   8(%rsp)\n"
  "  movq %rdi,  16(%rsp)\n"
  "  movq %rsi,  32(%rsp)\n"
  "  movq %r8,   40(%rsp)\n"
  "  movq %r9,   48(%rsp)\n"
  "  movq %r10,  56(%rsp)\n"
  "  movq %r11,  64(%rsp)\n"
  "\n"
  "  movq %xmm0,  96(%rsp)\n"
  "  movq %xmm1,  112(%rsp)\n"
  "  movq %xmm2,  128(%rsp)\n"
  "  movq %xmm3,  144(%rsp)\n"
  "  movq %xmm4,  160(%rsp)\n"
  "  movq %xmm5,  176(%rsp)\n"
  "  movq %xmm6,  192(%rsp)\n"
  "  movq %xmm7,  208(%rsp)\n"
  "  movq %xmm8,  224(%rsp)\n"
  "  movq %xmm9,  240(%rsp)\n"
  "  movq %xmm10, 256(%rsp)\n"
  "  movq %xmm11, 272(%rsp)\n"
  "  movq %xmm12, 288(%rsp)\n"
  "  movq %xmm13, 304(%rsp)\n"
  "  movq %xmm14, 320(%rsp)\n"
  "  movq %xmm15, 336(%rsp)\n"
  "\n"
  "  /* Map SHM, jumping to __afl_setup_abort if something goes wrong. */\n"
  "\n"
  "  /* The 64-bit ABI requires 16-byte stack alignment. We'll keep the\n"
  "     original stack ptr in the callee-saved r12. */\n"
  "\n"                                                                //进行 rsp 的对齐
  "  pushq %r12\n"
  "  movq  %rsp, %r12\n"
  "  subq  $16, %rsp\n"
  "  andq  $0xfffffffffffffff0, %rsp\n"
  "\n"
  "  leaq .AFL_SHM_ENV(%rip), %rdi\n"         //获取环境变量 __AFL_SHM_ID，该环境变量保存的是共享内存的ID
  CALL_L64("getenv")
  "\n"
  "  testq %rax, %rax\n"
  "  je    __afl_setup_abort\n"               //如果获取成功，调用 _shmat ，启用对共享内存的访问；如果启用失败跳转到 __afl_setup_abort
  "\n"
  "  movq  %rax, %rdi\n"
  CALL_L64("atoi")
  "\n"
  "  xorq %rdx, %rdx   /* shmat flags    */\n"
  "  xorq %rsi, %rsi   /* requested addr */\n"
  "  movq %rax, %rdi   /* SHM ID         */\n"
  CALL_L64("shmat")
  "\n"
  "  cmpq $-1, %rax\n"
  "  je   __afl_setup_abort\n"
  "\n"
  "  /* Store the address of the SHM region. */\n"      //将 _shmat 返回的共享内存地址存储在 __afl_area_ptr 和 __afl_global_area_ptr 变量中
  "\n"
  "  movq %rax, %rdx\n"
  "  movq %rax, __afl_area_ptr(%rip)\n"
  "\n"
#ifdef __APPLE__
  "  movq %rax, __afl_global_area_ptr(%rip)\n"
#else
  "  movq __afl_global_area_ptr@GOTPCREL(%rip), %rdx\n"
  "  movq %rax, (%rdx)\n"
#endif /* ^__APPLE__ */
  "  movq %rax, %rdx\n"
  "\n"
  "__afl_forkserver:\n"             //这一段实现的主要功能是向 FORKSRV_FD+1 （也就是198+1）号描述符（即状态管道）中写 __afl_temp 中的4个字节，告诉 fork server 已经成功启动
  "\n"
  "  /* Enter the fork server mode to avoid the overhead of execve() calls. We\n"
  "     push rdx (area ptr) twice to keep stack alignment neat. */\n"
  "\n"
  "  pushq %rdx\n"
  "  pushq %rdx\n"
  "\n"
  "  /* Phone home and tell the parent that we're OK. (Note that signals with\n"
  "     no SA_RESTART will mess it up). If this fails, assume that the fd is\n"
  "     closed because we were execve()d from an instrumented binary, or because\n"
  "     the parent doesn't want to use the fork server. */\n"
  "\n"
  "  movq $4, %rdx               /* length    */\n"
  "  leaq __afl_temp(%rip), %rsi /* data      */\n"
  "  movq $" STRINGIFY((FORKSRV_FD + 1)) ", %rdi       /* file desc */\n"
  CALL_L64("write")
  "\n"
  "  cmpq $4, %rax\n"
  "  jne  __afl_fork_resume\n"
  "\n"
  "__afl_fork_wait_loop:\n"
  "\n"
  "  /* Wait for parent by reading from the pipe. Abort if read fails. */\n"      //等待fuzzer通过控制管道发送过来的命令，读入到 __afl_temp 中
  "\n"
  "  movq $4, %rdx               /* length    */\n"
  "  leaq __afl_temp(%rip), %rsi /* data      */\n"
  "  movq $" STRINGIFY(FORKSRV_FD) ", %rdi             /* file desc */\n"
  CALL_L64("read")
  "  cmpq $4, %rax\n"
  "  jne  __afl_die\n"
  "\n"
  "  /* Once woken up, create a clone of our process. This is an excellent use\n"
  "     case for syscall(__NR_clone, 0, CLONE_PARENT), but glibc boneheadedly\n"
  "     caches getpid() results and offers no way to update the value, breaking\n"
  "     abort(), raise(), and a bunch of other things :-( */\n"
  "\n"
  CALL_L64("fork")
  "  cmpq $0, %rax\n"
  "  jl   __afl_die\n"
  "  je   __afl_fork_resume\n"      //子进程执行 __afl_fork_resume
  "\n"
  "  /* In parent process: write PID to pipe, then wait for child. */\n"
  "\n"
  "  movl %eax, __afl_fork_pid(%rip)\n"
  "\n"
  "  movq $4, %rdx                   /* length    */\n"
  "  leaq __afl_fork_pid(%rip), %rsi /* data      */\n"
  "  movq $" STRINGIFY((FORKSRV_FD + 1)) ", %rdi             /* file desc */\n"
  CALL_L64("write")
  "\n"
  "  movq $0, %rdx                   /* no flags  */\n"
  "  leaq __afl_temp(%rip), %rsi     /* status    */\n"
  "  movq __afl_fork_pid(%rip), %rdi /* PID       */\n"     //将子进程的pid赋给 __afl_fork_pid，并写到状态管道中通知父进程
  CALL_L64("waitpid")       //等待子进程执行完成，写入状态管道告知 fuzzer
  "  cmpq $0, %rax\n"
  "  jle  __afl_die\n"
  "\n"
  "  /* Relay wait status to pipe, then loop back. */\n"
  "\n"
  "  movq $4, %rdx               /* length    */\n"
  "  leaq __afl_temp(%rip), %rsi /* data      */\n"
  "  movq $" STRINGIFY((FORKSRV_FD + 1)) ", %rdi         /* file desc */\n"
  CALL_L64("write")
  "\n"
  "  jmp  __afl_fork_wait_loop\n"     //重新执行下一轮 __afl_fork_wait_loop
  "\n"
  "__afl_fork_resume:\n"
  "\n"
  "  /* In child process: close fds, resume execution. */\n"      //关闭子进程中的fd，恢复子进程的寄存器状态
  "\n"
  "  movq $" STRINGIFY(FORKSRV_FD) ", %rdi\n"
  CALL_L64("close")
  "\n"
  "  movq $" STRINGIFY((FORKSRV_FD + 1)) ", %rdi\n"
  CALL_L64("close")
  "\n"
  "  popq %rdx\n"
  "  popq %rdx\n"
  "\n"
  "  movq %r12, %rsp\n"
  "  popq %r12\n"
  "\n"
  "  movq  0(%rsp), %rax\n"
  "  movq  8(%rsp), %rcx\n"
  "  movq 16(%rsp), %rdi\n"
  "  movq 32(%rsp), %rsi\n"
  "  movq 40(%rsp), %r8\n"
  "  movq 48(%rsp), %r9\n"
  "  movq 56(%rsp), %r10\n"
  "  movq 64(%rsp), %r11\n"
  "\n"
  "  movq  96(%rsp), %xmm0\n"
  "  movq 112(%rsp), %xmm1\n"
  "  movq 128(%rsp), %xmm2\n"
  "  movq 144(%rsp), %xmm3\n"
  "  movq 160(%rsp), %xmm4\n"
  "  movq 176(%rsp), %xmm5\n"
  "  movq 192(%rsp), %xmm6\n"
  "  movq 208(%rsp), %xmm7\n"
  "  movq 224(%rsp), %xmm8\n"
  "  movq 240(%rsp), %xmm9\n"
  "  movq 256(%rsp), %xmm10\n"
  "  movq 272(%rsp), %xmm11\n"
  "  movq 288(%rsp), %xmm12\n"
  "  movq 304(%rsp), %xmm13\n"
  "  movq 320(%rsp), %xmm14\n"
  "  movq 336(%rsp), %xmm15\n"
  "\n"
  "  leaq 352(%rsp), %rsp\n"
  "\n"
  "  jmp  __afl_store\n"          //跳转到 __afl_store 执行
  "\n"
  "__afl_die:\n"
  "\n"
  "  xorq %rax, %rax\n"
  CALL_L64("_exit")
  "\n"
  "__afl_setup_abort:\n"
  "\n"
  "  /* Record setup failure so that we don't keep calling\n"
  "     shmget() / shmat() over and over again. */\n"
  "\n"
  "  incb __afl_setup_failure(%rip)\n"
  "\n"
  "  movq %r12, %rsp\n"
  "  popq %r12\n"
  "\n"
  "  movq  0(%rsp), %rax\n"
  "  movq  8(%rsp), %rcx\n"
  "  movq 16(%rsp), %rdi\n"
  "  movq 32(%rsp), %rsi\n"
  "  movq 40(%rsp), %r8\n"
  "  movq 48(%rsp), %r9\n"
  "  movq 56(%rsp), %r10\n"
  "  movq 64(%rsp), %r11\n"
  "\n"
  "  movq  96(%rsp), %xmm0\n"
  "  movq 112(%rsp), %xmm1\n"
  "  movq 128(%rsp), %xmm2\n"
  "  movq 144(%rsp), %xmm3\n"
  "  movq 160(%rsp), %xmm4\n"
  "  movq 176(%rsp), %xmm5\n"
  "  movq 192(%rsp), %xmm6\n"
  "  movq 208(%rsp), %xmm7\n"
  "  movq 224(%rsp), %xmm8\n"
  "  movq 240(%rsp), %xmm9\n"
  "  movq 256(%rsp), %xmm10\n"
  "  movq 272(%rsp), %xmm11\n"
  "  movq 288(%rsp), %xmm12\n"
  "  movq 304(%rsp), %xmm13\n"
  "  movq 320(%rsp), %xmm14\n"
  "  movq 336(%rsp), %xmm15\n"
  "\n"
  "  leaq 352(%rsp), %rsp\n"
  "\n"
  "  jmp __afl_return\n"
  "\n"
  ".AFL_VARS:\n"
  "\n"

#ifdef __APPLE__

  "  .comm   __afl_area_ptr, 8\n"         //__afl_area_ptr  存储共享内存的首地址
#ifndef COVERAGE_ONLY
  "  .comm   __afl_prev_loc, 8\n"         //__afl_prev_loc  存储上一个位置，即上一次R(MAP_SIZE)生成的随机数的值
#endif /* !COVERAGE_ONLY */
  "  .comm   __afl_fork_pid, 4\n"         //__afl_fork_pid  存储fork出来的子进程的pid
  "  .comm   __afl_temp, 4\n"             //__afl_temp      临时buffer
  "  .comm   __afl_setup_failure, 1\n"

#else

  "  .lcomm   __afl_area_ptr, 8\n"
#ifndef COVERAGE_ONLY
  "  .lcomm   __afl_prev_loc, 8\n"
#endif /* !COVERAGE_ONLY */
  "  .lcomm   __afl_fork_pid, 4\n"
  "  .lcomm   __afl_temp, 4\n"
  "  .lcomm   __afl_setup_failure, 1\n"      //标志位，如果置位则直接退出

#endif /* ^__APPLE__ */

  "  .comm    __afl_global_area_ptr, 8, 8\n"   //全局指针
  "\n"
  ".AFL_SHM_ENV:\n"
  "  .asciz \"" SHM_ENV_VAR "\"\n"
  "\n"
  "/* --- END --- */\n"
  "\n";

#endif /* !_HAVE_AFL_AS_H */
