/*
   american fuzzy lop - LLVM instrumentation bootstrap
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is the rewrite of afl-as.h's main_payload.

*/
/*
  主要是重写了 afl-as.h 文件中的 main_payload 部分，方便调用
*/
//AFL LLVM_Mode中存在着三个特殊的功能：deferred instrumentation, persistent mode,trace-pc-guard mode。这三个功能的源码位于afl-llvm-rt.o.c中

#include "../config.h"
#include "../types.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>

/* This is a somewhat ugly hack for the experimental 'trace-pc-guard' mode.
   Basically, we need to make sure that the forkserver is initialized after
   the LLVM-generated runtime initialization pass, not before. */

#ifdef USE_TRACE_PC
#  define CONST_PRIO 5
#else
#  define CONST_PRIO 0
#endif /* ^USE_TRACE_PC */


/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to run.
   It will end up as .comm, so it shouldn't be too wasteful. */

u8  __afl_area_initial[MAP_SIZE];
u8* __afl_area_ptr = __afl_area_initial;    //存储共享内存的首地址

__thread u32 __afl_prev_loc;    //存储上一个位置，即上一次R(MAP_SIZE)生成的随机数的值

//persistent mode的一些特点：它并不是通过fork出子进程去进行fuzz的，而是认为当前我们正在fuzz的API是无状态的，当API重置后，一个长期活跃的进程就可以被重复使用，这样可以消除重复执行fork函数以及OS相关所需要的开销
/* Running in persistent mode? */

static u8 is_persistent;


/* SHM setup. */

static void __afl_map_shm(void) {
  //通过读取环境变量SHM_ENV_VAR来获取共享内存，然后将地址赋值给__afl_area_ptr。否则，默认的__afl_area_ptr指向的是一个数组
  u8 *id_str = getenv(SHM_ENV_VAR);      // 读取环境变量 SHM_ENV_VAR 获取id

  /* If we're running under AFL, attach to the appropriate region, replacing the
     early-stage __afl_area_initial region that is needed to allow some really
     hacky .init code to work correctly in projects such as OpenSSL. */

  if (id_str) {   // 成功读取id

    u32 shm_id = atoi(id_str);
    //__afl_area_ptr: 存储共享内存的首地址
    __afl_area_ptr = shmat(shm_id, NULL, 0);      // 获取shm地址，赋给 __afl_area_ptr

    /* Whooooops. */

    if (__afl_area_ptr == (void *)-1) _exit(1);     // 异常则退出

    /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */

    __afl_area_ptr[0] = 1;      // 进行设置

  }

}


/* Fork server logic. */

static void __afl_start_forkserver(void) {

  static u8 tmp[4];
  s32 child_pid;
  //首先设置child_stopped为0，然后通过FORKSRV_FD + 1向状态管道写入4个字节，告知AFL fuzz已经准备好了
  u8  child_stopped = 0;

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;
  //然后进入fuzz loop循环
  while (1) {

    u32 was_killed;
    int status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */
    //通过read从控制管道FORKSRV_FD读取4个字节，如果当前管道中没有内容，就会堵塞在这里，如果读到了，就代表AFL命令我们fork server去执行一次fuzz
    //调用 read 从控制管道读取4字节，判断子进程是否超时。如果管道内读取失败，发生阻塞，读取成功则表示AFL指示forkserver执行fuzz
    if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);

    /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */
    // 处于persistent mode且子进程已被killed
    if (child_stopped && was_killed) {
      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) _exit(1);
    }
    //如果child_stopped为0，则直接fork出一个子进程去进行fuzz
    if (!child_stopped) {

      /* Once woken up, create a clone of our process. */

      child_pid = fork();     //重新fork
      if (child_pid < 0) _exit(1);

      /* In child process: close fds, resume execution. */
      //然后此时对于子进程就会关闭和控制管道和状态管道相关的fd，然后return跳出fuzz loop，恢复正常执行
      if (!child_pid) {

        close(FORKSRV_FD);      //关闭fd
        close(FORKSRV_FD + 1);
        return;
  
      }

    } else {    //如果child_stopped为1，这是对于persistent mode的特殊处理，此时子进程还活着，只是被暂停了，所以可以通过kill(child_pid, SIGCONT)来简单的重启，然后设置child_stopped为0

      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */

      kill(child_pid, SIGCONT);
      child_stopped = 0;

    }

    /* In parent process: write PID to pipe, then wait for child. */
    //然后fork server向状态管道FORKSRV_FD + 1写入子进程的pid，然后等待子进程结束，注意这里对于persistent mode，我们会设置waitpid的第三个参数为WUNTRACED，代表若子进程进入暂停状态，则马上返回
    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);
    
    if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0)
      _exit(1);

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */
    //WIFSTOPPED(status)宏确定返回值是否对应于一个暂停子进程，因为在persistent mode里子进程会通过SIGSTOP信号来暂停自己，并以此指示运行成功，所以在这种情况下，我们需要再进行一次fuzz，就只需要和上面一样，通过SIGCONT信号来唤醒子进程继续执行即可，不需要再进行一次fuzz
    if (WIFSTOPPED(status)) child_stopped = 1;

    /* Relay wait status to pipe, then loop back. */
    //当子进程结束以后，向状态管道FORKSRV_FD + 1写入4个字节，通知AFL这次target执行结束了
    if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);

  }

}


/* A simplified persistent mode handler, used as explained in README.llvm. */

int __afl_persistent_loop(unsigned int max_cnt) {

  static u8  first_pass = 1;
  static u32 cycle_cnt;
  //首先判读是否为第一次执行循环，如果是第一次
  if (first_pass) {

    /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
       On subsequent calls, the parent will take care of that, but on the first
       iteration, it's our job to erase any trace of whatever happened
       before the loop. */
    //如果 is_persistent 为1，清空 __afl_area_ptr，设置 __afl_area_ptr[0] 为1，__afl_prev_loc 为0
    if (is_persistent) {

      memset(__afl_area_ptr, 0, MAP_SIZE);
      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;
    }

    cycle_cnt  = max_cnt;
    first_pass = 0;
    return 1;

  } 
  //如果不是第一次执行循环，在 persistent mode 下，且 --cycle_cnt 大于1
  if (is_persistent) {

    if (--cycle_cnt) {

      raise(SIGSTOP);           //发出信号 SIGSTOP 让当前进程暂停

      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;

      return 1;

    } else {        //如果 cycle_cnt 为0，设置__afl_area_ptr指向数组 __afl_area_initial

      /* When exiting __AFL_LOOP(), make sure that the subsequent code that
         follows the loop is not traced. We do that by pivoting back to the
         dummy output region. */

      __afl_area_ptr = __afl_area_initial;

    }

  }

  return 0;

}


/* This one can be called from user code when deferred forkserver mode
    is enabled. */

void __afl_manual_init(void) {

  static u8 init_done;
  //如果还没有被初始化，就初始化共享内存，然后开始执行forkserver，然后设置init_done为1
  if (!init_done) {

    __afl_map_shm();            
    __afl_start_forkserver();   
    init_done = 1;

  }

}

//__attribute__ constructor，代表被此修饰的函数将在main执行之前自动运行
/* Proper initialization routine. */

__attribute__((constructor(CONST_PRIO))) void __afl_auto_init(void) {
  //读取环境变量PERSIST_ENV_VAR的值，设置给is_persistent
  is_persistent = !!getenv(PERSIST_ENV_VAR);
  //读取环境变量DEFER_ENV_VAR的值，如果为1，就直接返回，这代表__afl_auto_init和deferred instrumentation不通用，这其实道理也很简单，因为deferred instrumentation会自己选择合适的时机，手动init，不需要用这个函数来init，所以这个函数只在没有手动init的时候会自动init
  if (getenv(DEFER_ENV_VAR)) return;

  __afl_manual_init();

}


/* The following stuff deals with supporting -fsanitize-coverage=trace-pc-guard.
   It remains non-operational in the traditional, plugin-backed LLVM mode.
   For more info about 'trace-pc-guard', see README.llvm.

   The first function (__sanitizer_cov_trace_pc_guard) is called back on every
   edge (as opposed to every basic block). */
//在每个edge插入桩代码，函数 __sanitizer_cov_trace_pc_guard 会在每个edge进行调用，该函数利用函数参数 guard 指针所指向的 uint32 值来确定共享内存上所对应的地址
void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
  __afl_area_ptr[*guard]++;
}


/* Init callback. Populates instrumentation IDs. Note that we're using
   ID of 0 as a special value to indicate non-instrumented bits. That may
   still touch the bitmap, but in a fairly harmless way. */
//guard 的初始化
void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop) {

  u32 inst_ratio = 100;
  u8* x;

  if (start == stop || *start) return;

  x = getenv("AFL_INST_RATIO");
  if (x) inst_ratio = atoi(x);

  if (!inst_ratio || inst_ratio > 100) {
    fprintf(stderr, "[-] ERROR: Invalid AFL_INST_RATIO (must be 1-100).\n");
    abort();
  }

  /* Make sure that the first element in the range is always set - we use that
     to avoid duplicate calls (which can happen as an artifact of the underlying
     implementation in LLVM). */
  //它会从第一个guard开始向后遍历，设置guard指向的值，这个值是通过R(MAP_SIZE)设置的，定义如下，所以如果我们的edge足够多，而MAP_SIZE不够大，就有可能重复，而这个加一是因为我们会把0当成一个特殊的值，其代表对这个edge不进行插桩。
  //这个init其实很有趣，我们可以打印输出一下stop-start的值，就代表了llvm发现的程序里总计的edge数。
  *(start++) = R(MAP_SIZE - 1) + 1;

  while (start < stop) {      //这里如果计算stop-start，就是程序里总计的edge数

    if (R(100) < inst_ratio) *start = R(MAP_SIZE - 1) + 1;
    else *start = 0;

    start++;

  }

}
