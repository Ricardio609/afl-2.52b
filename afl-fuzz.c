/*
   american fuzzy lop - fuzzer code
   --------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Copyright 2013, 2014, 2015, 2016, 2017 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

/*
  该文件的主要作用是通过不断变异测试用例来影响程序的执行路径。

  在功能上，可以总体上分为3部分：
    1. 初始配置：进行fuzz环境配置相关工作
    2. fuzz执行：fuzz的主循环过程
    3. 变异策略：测试用例的变异过程和方式
*/

#define AFL_MAIN
#define MESSAGES_TO_STDOUT

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

//下面五个头文件是自定义头文件
//配置文件，包含各种宏定义，属于通用配置。比如bitflip变异时收集的token的长度和数量会在此文件中进行定义。
#include "config.h"
//类型重定义，一些在 afl-fuzz.c 中看不太懂的类型，可以在这里看看是不是有相关定义，比如 u8 在源码中经常出现，
//实际上在这个头文件可以看出 typedef uint8_t u8，所以其对应的类型应该是 uint8_t ，对应的是 C99 标准里的无符号字符型。
#include "types.h"
//调试，宏定义各种参数及函数，比如显示的颜色，还有各种自定义的函数，如果改AFL，这些东西相当于没有编译器情况下的 "高端
// printf(滑稽脸)"，比如最常见的 OKF("We're done here. Have a nice day!\n"); 其中的 OKF 就是一个输出代表成功信息的函数
#include "debug.h"
//内存相关，提供错误检查、内存清零、内存分配等常规操作，“内存器的设计初衷不是为了抵抗恶意攻击，但是它确实提供了便携健壮的
//内存处理方式，可以检查 use-after-free 等”
#include "alloc-inl.h"
//哈希函数，文件中实现一个参数为 const void* key, u32 len, u32 seed 返回为 u32 的静态内联函数
#include "hash.h"

//标准库头文件，基本和widonws下c编程一样，仅个别是linux c才会用到
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h> //文件操作相关，此处可以参考afl-tmin.c文件中的修改，查看其具体用途
#include <ctype.h>
#include <fcntl.h>
#include <termios.h>
#include <dlfcn.h>
#include <sched.h> //任务调度相关

// Linux C编程特有的头文件
//这一部分，引用了一些Linux环境下的特殊头文件，跟上一部分会有一些重叠，但是各司其职，实际编程
//两边的函数都可以，但是偏向于用这部分。
//对应Linux环境的头文件位置 /usr/include/sys/
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/file.h>

//环境判断预处理
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <sys/sysctl.h>
#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

/* For systems that have sched_setaffinity; right now just Linux, but one
   can hope... */

// Linux环境下独有的宏定义
#ifdef __linux__
#define HAVE_AFFINITY 1 // affinity 亲和性，跟cpu的亲和性，与与运行性能有关。定义之后共出现了五次。
#endif                  /* __linux__ */

/* A toggle to export some variables when building as a library. Not very
   useful for the general public. */
//不常用，当afl被编译成库的时候，用来保证变量的输出。
#ifdef AFL_LIB
#define EXP_ST
#else
#define EXP_ST static
#endif /* ^AFL_LIB */

/* Lots of globals, but mostly for the status UI and other things where it
   really makes no sense to haul them around as function parameters. */

EXP_ST u8 *in_dir, /* Input directory with test cases  */
    *out_file,     /* File to fuzz, if any             */
    *out_dir,      /* Working & output directory       */
    *sync_dir,     /* Synchronization directory        */
    *sync_id,      /* Fuzzer ID                        */
    *use_banner,   /* Display banner(横幅)                   */
    *in_bitmap,    /* Input bitmap                     */
    *doc_path,     /* Path to documentation dir        */
    *target_path,  /* Path to target binary            */
    *orig_cmdline, /* Original command line            */
    *old_out_dir;  /* 新添加的字段，用于保存fuzz停止时out文件夹利里有价值的种子, 当出现 out 文件夹比较有用时旧的文件保存  */

EXP_ST u32 exec_tmout = EXEC_TIMEOUT; /* Configurable exec timeout (ms)   */
static u32 hang_tmout = EXEC_TIMEOUT; /* Timeout used for hang det (ms)   */

EXP_ST u64 mem_limit = MEM_LIMIT; /* Memory cap for child (MB)        */

static u32 stats_update_freq = 1; /* Stats update frequency (execs)   */

EXP_ST u8 skip_deterministic, /* Skip deterministic stages?       */
    force_deterministic,      /* Force deterministic stages?      */
    use_splicing,             /* Recombine input files?           */
    dumb_mode,                /* Run in non-instrumented mode?    dumb mode:盲目变异，不插桩。非dumb mode（-d）*/
    score_changed,            /* Scoring for favorites changed?   */
    kill_signal,              /* Signal that killed the child     */
    resuming_fuzz,            /* Resuming an older fuzzing job?   */
    timeout_given,            /* Specific timeout given?          */
    not_on_tty,               /* stdout is not a tty              */
    term_too_small,           /* terminal dimensions too small    */
    uses_asan,                /* Target uses ASAN?                */
    no_forkserver,            /* Disable forkserver?              */
    crash_mode,               /* Crash mode! Yeah!                */
    in_place_resume,          /* Attempt in-place resume?         */
    auto_changed,             /* Auto-generated tokens changed?   */
    no_cpu_meter_red,         /* Feng shui on the status screen   */
    no_arith,                 /* Skip most arithmetic ops         */
    shuffle_queue,            /* Shuffle input queue?             */
    bitmap_changed = 1,       /* Time to update bitmap?           */
    qemu_mode,                /* Running in QEMU mode?            */
    skip_requested,           /* Skip request, via SIGUSR1        */
    run_over10m,              /* Run time over 10 minutes?        */
    persistent_mode,          /* Running in persistent mode?      */
    deferred_mode,            /* Deferred forkserver mode?        */
    fast_cal;                 /* Try to calibrate faster?         */

static s32 out_fd,       /* Persistent fd for out_file       */
    dev_urandom_fd = -1, /* Persistent fd for /dev/urandom   */
    dev_null_fd = -1,    /* Persistent fd for /dev/null      */
    fsrv_ctl_fd,         /* Fork server control pipe (write) */
    fsrv_st_fd;          /* Fork server status pipe (read)   */

static s32 forksrv_pid, /* PID of the fork server           */
    child_pid = -1,     /* PID of the fuzzed program        */
    out_dir_fd = -1;    /* FD of the lock file              */
// AFL是根据二元tuple(跳转的源地址和目标地址)来记录分支信息，从而获取target的执行流程和代码覆盖情况.tuple信息：目标程序执行路径
EXP_ST u8 *trace_bits; /* SHM with instrumentation bitmap  记录当前的tuple信息*/

EXP_ST u8 virgin_bits[MAP_SIZE], /* Regions yet untouched by fuzzing 记录总的tuple信息*/
    virgin_tmout[MAP_SIZE],      /* Bits we haven't seen in tmouts   记录fuzz过程中出现的所有目标程序的timeout时的tuple信息*/
    virgin_crash[MAP_SIZE];      /* Bits we haven't seen in crashes  记录fuzz过程中出现的crash时的tuple信息*/

static u8 var_bytes[MAP_SIZE]; /* Bytes that appear to be variable */

static s32 shm_id; /* ID of the SHM region             */

static volatile u8 stop_soon, /* Ctrl-C pressed?                  */
    clear_screen = 1,         /* Window resized?                  */
    child_timed_out;          /* Traced process timed out?        */

EXP_ST u32 queued_paths, /* Total number of queued testcases */
    queued_variable,     /* Testcases with variable behavior */
    queued_at_start,     /* Total number of initial inputs   */
    queued_discovered,   /* Items discovered during this run */
    queued_imported,     /* Items imported via -S            */
    queued_favored,      /* Paths deemed favorable           */
    queued_with_cov,     /* Paths with new coverage bytes    */
    pending_not_fuzzed,  /* Queued but not done yet          */
    pending_favored,     /* Pending favored paths            */
    cur_skipped_paths,   /* Abandoned inputs in cur cycle    */
    cur_depth,           /* Current path depth               */
    max_depth,           /* Max path depth                   */
    useless_at_start,    /* Number of useless starting paths */
    var_byte_count,      /* Bitmap bytes with var behavior   */
    current_entry,       /* Current queue entry ID           */
    havoc_div = 1;       /* Cycle count divisor for havoc    */

EXP_ST u64 total_crashes, /* Total number of crashes          */
    unique_crashes,       /* Crashes with unique signatures   */
    total_tmouts,         /* Total number of timeouts         */
    unique_tmouts,        /* Timeouts with unique signatures  */
    unique_hangs,         /* Hangs with unique signatures     */
    total_execs,          /* Total execve() calls             */
    start_time,           /* Unix start time (ms)             */
    last_path_time,       /* Time for most recent path (ms)   */
    last_crash_time,      /* Time for most recent crash (ms)  */
    last_hang_time,       /* Time for most recent hang (ms)   */
    last_crash_execs,     /* Exec counter at last crash       */
    queue_cycle,          /* Queue round counter              */
    cycles_wo_finds,      /* Cycles without any new paths     */
    trim_execs,           /* Execs done to trim input files   */
    bytes_trim_in,        /* Bytes coming into the trimmer    */
    bytes_trim_out,       /* Bytes coming outa the trimmer    */
    blocks_eff_total,     /* Blocks subject to effector maps  */
    blocks_eff_select;    /* Blocks selected as fuzzable      */

static u32 subseq_tmouts; /* Number of timeouts in a row      */

static u8 *stage_name = "init", /* Name of the current fuzz stage   */
    *stage_short,               /* Short stage name                 */
    *syncing_party;             /* Currently syncing with...        */

static s32 stage_cur, stage_max; /* Stage progression                */
static s32 splicing_with = -1;   /* Splicing with which test case?   */

static u32 master_id, master_max; /* Master instance job splitting    */

static u32 syncing_case; /* Syncing with case #...           */

static s32 stage_cur_byte, /* Byte offset of current stage op  */
    stage_cur_val;         /* Value used for stage op          */

static u8 stage_val_type; /* Value type (STAGE_VAL_*)         */

static u64 stage_finds[32], /* Patterns found per fuzz stage    */
    stage_cycles[32];       /* Execs per fuzz stage             */

static u32 rand_cnt; /* Random number counter            */

static u64 total_cal_us, /* Total calibration time (us)      */
    total_cal_cycles;    /* Total calibration cycles         */

static u64 total_bitmap_size, /* Total bit count for all bitmaps  */
    total_bitmap_entries;     /* Number of bitmaps counted        */

static s32 cpu_core_count; /* CPU core count                   */

#ifdef HAVE_AFFINITY
//因为是特定条件下的宏定义，所以也可以当是跟cpu操作相关的bool用，都是成对出现。
static s32 cpu_aff = -1; /* Selected CPU core                */
//只有在启用这种亲和性的情况下，才会定义 cpu_aff 用来标记选择的cpu核。
#endif /* HAVE_AFFINITY */

static FILE *plot_file; /* Gnuplot output file              */

struct queue_entry
{

    u8 *fname; /* File name for the test case    测试用例的文件名  */
    u32 len;   /* Input length   testcase大小                  */

    u8 cal_failed,    /* Calibration failed?    标准失败          */
        trim_done,    /* Trimmed?   该testcase是否被修建                      */
        was_fuzzed,   /* Had any fuzzing done yet?        是否已经经过fuzzing  */
        passed_det,   /* Deterministic stages passed?     */
        has_new_cov,  /* Triggers new coverage?           */
        var_behavior, /* Variable behavior?               */
        favored,      /* Currently favored?     当前是否被标记为favored（更多的fuzz机会）   */
        fs_redundant; /* Marked as redundant in the fs?   */

    u32 bitmap_size, /* Number of bits set in bitmap    bitmap中bit的数量 */
        exec_cksum;  /* Checksum of the execution trace  */

    u64 exec_us,  /* Execution time (us)              */
        handicap, /* Number of queue cycles behind    */
        depth;    /* Path depth          路径深度             */

    u8 *trace_mini; /* Trace bytes, if kept       1个bit存一个byte的trace_mini      */
    u32 tc_ref;     /* Trace bytes ref count      top_rate[]中该testcase入选的次数      */

    struct queue_entry *next, /* Next element, if any      队列下一结点       */
        *next_100;            /* 100 elements ahead               */
};

static struct queue_entry *queue, /* Fuzzing queue (linked list)      */
    *queue_cur,                   /* Current offset within the queue  */
    *queue_top,                   /* Top of the list                  */
    *q_prev100;                   /* Previous 100 marker              */

static struct queue_entry *
    top_rated[MAP_SIZE]; /* Top entries for bitmap bytes     */

struct extra_data
{
    u8 *data;    /* Dictionary token data            */
    u32 len;     /* Dictionary token length          */
    u32 hit_cnt; /* Use count in the corpus          */
};

static struct extra_data *extras; /* Extra tokens to fuzz with        */
static u32 extras_cnt;            /* Total number of tokens read      */

static struct extra_data *a_extras; /* Automatically selected extras    */
static u32 a_extras_cnt;            /* Total number of tokens available */

static u8 *(*post_handler)(u8 *buf, u32 *len);

/* Interesting values, as per config.h */

static s8 interesting_8[] = {INTERESTING_8};
static s16 interesting_16[] = {INTERESTING_8, INTERESTING_16};
static s32 interesting_32[] = {INTERESTING_8, INTERESTING_16, INTERESTING_32};

/* Fuzzing stages */
// fuzzing状态，这里包含了很多不同fuzz种子的变异策略。使用枚举可以避免使用数组时还需要解释数组下标的含义。

enum
{
    /* 00 */ STAGE_FLIP1,
    /* 01 */ STAGE_FLIP2,
    /* 02 */ STAGE_FLIP4,
    /* 03 */ STAGE_FLIP8,
    /* 04 */ STAGE_FLIP16,
    /* 05 */ STAGE_FLIP32,
    /* 06 */ STAGE_ARITH8,
    /* 07 */ STAGE_ARITH16,
    /* 08 */ STAGE_ARITH32,
    /* 09 */ STAGE_INTEREST8,
    /* 10 */ STAGE_INTEREST16,
    /* 11 */ STAGE_INTEREST32,
    /* 12 */ STAGE_EXTRAS_UO,
    /* 13 */ STAGE_EXTRAS_UI,
    /* 14 */ STAGE_EXTRAS_AO,
    /* 15 */ STAGE_HAVOC,
    /* 16 */ STAGE_SPLICE
};

/* Stage value types */
//状态值的类型，用来辅助、修饰上一个枚举fuzzing状态，用来识别当前的状态枚举对应的变异方式的类型。
enum
{
    /* 00 */ STAGE_VAL_NONE,
    /* 01 */ STAGE_VAL_LE,
    /* 02 */ STAGE_VAL_BE
};

/* Execution status fault codes */
//

enum
{
    /* 00 */ FAULT_NONE,
    /* 01 */ FAULT_TMOUT,
    /* 02 */ FAULT_CRASH,
    /* 03 */ FAULT_ERROR,
    /* 04 */ FAULT_NOINST,
    /* 05 */ FAULT_NOBITS
};

/* Get unix time in milliseconds */

static u64 get_cur_time(void)
{

    struct timeval tv;
    struct timezone tz;

    gettimeofday(&tv, &tz);

    return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);
}

/* Get unix time in microseconds */

static u64 get_cur_time_us(void)
{

    struct timeval tv;
    struct timezone tz;

    gettimeofday(&tv, &tz);

    return (tv.tv_sec * 1000000ULL) + tv.tv_usec;
}

/* Generate a random number (from 0 to limit - 1). This may
   have slight bias. */

static inline u32 UR(u32 limit)
{

    if (unlikely(!rand_cnt--))
    {

        u32 seed[2];

        ck_read(dev_urandom_fd, &seed, sizeof(seed), "/dev/urandom");

        srandom(seed[0]);
        rand_cnt = (RESEED_RNG / 2) + (seed[1] % RESEED_RNG);
    }

    return random() % limit;
}

/* Shuffle an array of pointers. Might be slightly biased. */

static void shuffle_ptrs(void **ptrs, u32 cnt)
{

    u32 i;

    for (i = 0; i < cnt - 2; i++)
    {

        u32 j = i + UR(cnt - i);
        void *s = ptrs[i];
        ptrs[i] = ptrs[j];
        ptrs[j] = s;
    }
}

#ifdef HAVE_AFFINITY

/* Build a list of processes bound to specific cores. Returns -1 if nothing
   can be found. Assumes an upper bound of 4k CPUs. */
//尝试绑定空闲的cpu

static void bind_to_free_cpu(void)
{

    DIR *d;
    struct dirent *de;
    cpu_set_t c;

    u8 cpu_used[4096] = {0};
    u32 i;

    if (cpu_core_count < 2)
        return;

    if (getenv("AFL_NO_AFFINITY"))
    {

        WARNF("Not binding to a CPU core (AFL_NO_AFFINITY set).");
        return;
    }

    d = opendir("/proc");

    if (!d)
    {

        WARNF("Unable to access /proc - can't scan for free CPU cores.");
        return;
    }

    ACTF("Checking CPU core loadout...");

    /* Introduce some jitter, in case multiple AFL tasks are doing the same
       thing at the same time... */

    usleep(R(1000) * 250);

    /* Scan all /proc/<pid>/status entries, checking for Cpus_allowed_list.
       Flag all processes bound to a specific CPU using cpu_used[]. This will
       fail for some exotic binding setups, but is likely good enough in almost
       all real-world use cases. */

    while ((de = readdir(d)))
    {

        u8 *fn;
        FILE *f;
        u8 tmp[MAX_LINE];
        u8 has_vmsize = 0;

        if (!isdigit(de->d_name[0]))
            continue;

        fn = alloc_printf("/proc/%s/status", de->d_name);

        if (!(f = fopen(fn, "r")))
        {
            ck_free(fn);
            continue;
        }

        while (fgets(tmp, MAX_LINE, f))
        {

            u32 hval;

            /* Processes without VmSize are probably kernel tasks. */

            if (!strncmp(tmp, "VmSize:\t", 8))
                has_vmsize = 1;

            if (!strncmp(tmp, "Cpus_allowed_list:\t", 19) &&
                !strchr(tmp, '-') && !strchr(tmp, ',') &&
                sscanf(tmp + 19, "%u", &hval) == 1 && hval < sizeof(cpu_used) &&
                has_vmsize)
            {

                cpu_used[hval] = 1;
                break;
            }
        }

        ck_free(fn);
        fclose(f);
    }

    closedir(d);

    for (i = 0; i < cpu_core_count; i++)
        if (!cpu_used[i])
            break;

    if (i == cpu_core_count)
    {

        SAYF("\n" cLRD "[-] " cRST
             "Uh-oh, looks like all %u CPU cores on your system are allocated to\n"
             "    other instances of afl-fuzz (or similar CPU-locked tasks). Starting\n"
             "    another fuzzer on this machine is probably a bad plan, but if you are\n"
             "    absolutely sure, you can set AFL_NO_AFFINITY and try again.\n",
             cpu_core_count);

        FATAL("No more free CPU cores");
    }
    //获取空闲的cpu，尝试绑定
    OKF("Found a free CPU core, binding to #%u.", i);

    cpu_aff = i;

    CPU_ZERO(&c);
    CPU_SET(i, &c);

    if (sched_setaffinity(0, sizeof(c), &c))
        PFATAL("sched_setaffinity failed");
}

#endif /* HAVE_AFFINITY */

#ifndef IGNORE_FINDS2

/* Helper function to compare buffers; returns first and last differing offset. We
   use this to find reasonable locations for splicing two files. */

static void locate_diffs(u8 *ptr1, u8 *ptr2, u32 len, s32 *first, s32 *last)
{

    s32 f_loc = -1;
    s32 l_loc = -1;
    u32 pos;

    for (pos = 0; pos < len; pos++)
    {

        if (*(ptr1++) != *(ptr2++))
        {

            if (f_loc == -1)
                f_loc = pos;
            l_loc = pos;
        }
    }

    *first = f_loc;
    *last = l_loc;

    return;
}

#endif /* !IGNORE_FINDS */

/* Describe integer. Uses 12 cyclic static buffers for return values. The value
   returned should be five characters or less for all the integers we reasonably
   expect to see. */

static u8 *DI(u64 val)
{

    static u8 tmp[12][16];
    static u8 cur;

    cur = (cur + 1) % 12;

#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast)          \
    do                                                          \
    {                                                           \
        if (val < (_divisor) * (_limit_mult))                   \
        {                                                       \
            sprintf(tmp[cur], _fmt, ((_cast)val) / (_divisor)); \
            return tmp[cur];                                    \
        }                                                       \
    } while (0)

    /* 0-9999 */
    CHK_FORMAT(1, 10000, "%llu", u64);

    /* 10.0k - 99.9k */
    CHK_FORMAT(1000, 99.95, "%0.01fk", double);

    /* 100k - 999k */
    CHK_FORMAT(1000, 1000, "%lluk", u64);

    /* 1.00M - 9.99M */
    CHK_FORMAT(1000 * 1000, 9.995, "%0.02fM", double);

    /* 10.0M - 99.9M */
    CHK_FORMAT(1000 * 1000, 99.95, "%0.01fM", double);

    /* 100M - 999M */
    CHK_FORMAT(1000 * 1000, 1000, "%lluM", u64);

    /* 1.00G - 9.99G */
    CHK_FORMAT(1000LL * 1000 * 1000, 9.995, "%0.02fG", double);

    /* 10.0G - 99.9G */
    CHK_FORMAT(1000LL * 1000 * 1000, 99.95, "%0.01fG", double);

    /* 100G - 999G */
    CHK_FORMAT(1000LL * 1000 * 1000, 1000, "%lluG", u64);

    /* 1.00T - 9.99G */
    CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 9.995, "%0.02fT", double);

    /* 10.0T - 99.9T */
    CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 99.95, "%0.01fT", double);

    /* 100T+ */
    strcpy(tmp[cur], "infty");
    return tmp[cur];
}

/* Describe float. Similar to the above, except with a single
   static buffer. */

static u8 *DF(double val)
{

    static u8 tmp[16];

    if (val < 99.995)
    {
        sprintf(tmp, "%0.02f", val);
        return tmp;
    }

    if (val < 999.95)
    {
        sprintf(tmp, "%0.01f", val);
        return tmp;
    }

    return DI((u64)val);
}

/* Describe integer as memory size. */

static u8 *DMS(u64 val)
{

    static u8 tmp[12][16];
    static u8 cur;

    cur = (cur + 1) % 12;

    /* 0-9999 */
    CHK_FORMAT(1, 10000, "%llu B", u64);

    /* 10.0k - 99.9k */
    CHK_FORMAT(1024, 99.95, "%0.01f kB", double);

    /* 100k - 999k */
    CHK_FORMAT(1024, 1000, "%llu kB", u64);

    /* 1.00M - 9.99M */
    CHK_FORMAT(1024 * 1024, 9.995, "%0.02f MB", double);

    /* 10.0M - 99.9M */
    CHK_FORMAT(1024 * 1024, 99.95, "%0.01f MB", double);

    /* 100M - 999M */
    CHK_FORMAT(1024 * 1024, 1000, "%llu MB", u64);

    /* 1.00G - 9.99G */
    CHK_FORMAT(1024LL * 1024 * 1024, 9.995, "%0.02f GB", double);

    /* 10.0G - 99.9G */
    CHK_FORMAT(1024LL * 1024 * 1024, 99.95, "%0.01f GB", double);

    /* 100G - 999G */
    CHK_FORMAT(1024LL * 1024 * 1024, 1000, "%llu GB", u64);

    /* 1.00T - 9.99G */
    CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 9.995, "%0.02f TB", double);

    /* 10.0T - 99.9T */
    CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 99.95, "%0.01f TB", double);

#undef CHK_FORMAT

    /* 100T+ */
    strcpy(tmp[cur], "infty");
    return tmp[cur];
}

/* Describe time delta. Returns one static buffer, 34 chars of less. */

static u8 *DTD(u64 cur_ms, u64 event_ms)
{

    static u8 tmp[64];
    u64 delta;
    s32 t_d, t_h, t_m, t_s;

    if (!event_ms)
        return "none seen yet";

    delta = cur_ms - event_ms;

    t_d = delta / 1000 / 60 / 60 / 24;
    t_h = (delta / 1000 / 60 / 60) % 24;
    t_m = (delta / 1000 / 60) % 60;
    t_s = (delta / 1000) % 60;

    sprintf(tmp, "%s days, %u hrs, %u min, %u sec", DI(t_d), t_h, t_m, t_s);
    return tmp;
}

/* Mark deterministic checks as done for a particular queue entry. We use the
   .state file to avoid repeating deterministic fuzzing when resuming aborted
   scans. */

static void mark_as_det_done(struct queue_entry *q)
{

    u8 *fn = strrchr(q->fname, '/');
    s32 fd;

    fn = alloc_printf("%s/queue/.state/deterministic_done/%s", out_dir, fn + 1);

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        PFATAL("Unable to create '%s'", fn);
    close(fd);

    ck_free(fn);

    q->passed_det = 1;
}

/* Mark as variable. Create symlinks if possible to make it easier to examine
   the files. */

static void mark_as_variable(struct queue_entry *q)
{

    u8 *fn = strrchr(q->fname, '/') + 1, *ldest;
    //创建符号链接out_dir/queue/.state/variable_behavior/fname
    ldest = alloc_printf("../../%s", fn);
    fn = alloc_printf("%s/queue/.state/variable_behavior/%s", out_dir, fn);

    if (symlink(ldest, fn))
    {

        s32 fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0)
            PFATAL("Unable to create '%s'", fn);
        close(fd);
    }

    ck_free(ldest);
    ck_free(fn);
    //设置queue的var_behavior为1
    q->var_behavior = 1;
}

/* Mark / unmark as redundant (edge-only). This is not used for restoring state,
   but may be useful for post-processing datasets. */

static void mark_as_redundant(struct queue_entry *q, u8 state)
{

    u8 *fn;
    s32 fd;

    if (state == q->fs_redundant)
        return;

    q->fs_redundant = state;

    fn = strrchr(q->fname, '/');
    fn = alloc_printf("%s/queue/.state/redundant_edges/%s", out_dir, fn + 1);
    //如果state为1
    if (state)
    {
        //尝试创建out_dir/queue/.state/redundant_edges/fname
        fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0)
            PFATAL("Unable to create '%s'", fn);
        close(fd);
    }
    else
    {
        //尝试删除out_dir/queue/.state/redundant_edges/fname
        if (unlink(fn))
            PFATAL("Unable to remove '%s'", fn);
    }

    ck_free(fn);
}

/* Append new test case to the queue. */
//将新的测试用例插入队列，并初始化fname文件名称，增加cur_depth深度++
// queued_paths测试用例数量++，pending_not_fuzzed没被fuzzed测试用例数量++，更新last_path_time = get_cur_time()
static void add_to_queue(u8 *fname, u32 len, u8 passed_det)
{
    //通过ck_alloc分配一个 queue_entry 结构体，并进行初始化
    struct queue_entry *q = ck_alloc(sizeof(struct queue_entry));

    q->fname = fname;
    q->len = len;
    q->depth = cur_depth + 1;
    q->passed_det = passed_det;

    if (q->depth > max_depth)
        max_depth = q->depth;

    if (queue_top)
    {

        queue_top->next = q;
        queue_top = q;
    }
    else
        q_prev100 = queue = queue_top = q;

    queued_paths++;       // queue计数器加1
    pending_not_fuzzed++; // 待fuzz的样例计数器加1

    cycles_wo_finds = 0;

    if (!(queued_paths % 100))
    {

        q_prev100->next_100 = q;
        q_prev100 = q;
    }

    last_path_time = get_cur_time();
}

/* Destroy the entire queue. */

EXP_ST void destroy_queue(void)
{

    struct queue_entry *q = queue, *n;

    while (q)
    {

        n = q->next;
        ck_free(q->fname);
        ck_free(q->trace_mini);
        ck_free(q);
        q = n;
    }
}

/* Write bitmap to file. The bitmap is useful mostly for the secret
   -B option, to focus a separate fuzzing session on a particular
   interesting input without rediscovering all the others. */

EXP_ST void write_bitmap(void)
{

    u8 *fname;
    s32 fd;

    if (!bitmap_changed)
        return;
    bitmap_changed = 0;

    fname = alloc_printf("%s/fuzz_bitmap", out_dir);
    fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd < 0)
        PFATAL("Unable to open '%s'", fname);

    ck_write(fd, virgin_bits, MAP_SIZE, fname);

    close(fd);
    ck_free(fname);
}

/* Read bitmap from file. This is for the -B option again. */

EXP_ST void read_bitmap(u8 *fname)
{

    s32 fd = open(fname, O_RDONLY);

    if (fd < 0)
        PFATAL("Unable to open '%s'", fname);

    ck_read(fd, virgin_bits, MAP_SIZE, fname);

    close(fd);
}

/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen.
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */
//判断测试用例是否产生新状态,检查有没有新路径或者某个路径的执行次数有所不同
static inline u8 has_new_bits(u8 *virgin_map)
{
//初始化current和virgin为trace_bits和virgin_map的u64首元素地址
#ifdef __x86_64__

    u64 *current = (u64 *)trace_bits;
    u64 *virgin = (u64 *)virgin_map;

    u32 i = (MAP_SIZE >> 3);

#else

    u32 *current = (u32 *)trace_bits;
    u32 *virgin = (u32 *)virgin_map;

    u32 i = (MAP_SIZE >> 2);

#endif /* ^__x86_64__ */
       //设置ret的值为0
    u8 ret = 0;
    // 8个字节一组，每次从trace_bits(也就是共享内存)里取出8个字节
    while (i--)
    {

        /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
           that have not been already cleared from the virgin map - since this will
           almost always be the case. */
        //如果current不为0，且current & virgin不为0，即代表current发现了新路径或者某条路径的执行次数和之前有所不同
        if (unlikely(*current) && unlikely(*current & *virgin))
        {
            //如果ret当前小于2
            if (likely(ret < 2))
            {
                //取current的首字节地址为cur，virgin的首字节地址为vir
                u8 *cur = (u8 *)current;
                u8 *vir = (u8 *)virgin;

                /* Looks like we have not found any new bytes yet; see if any non-zero
                   bytes in current[] are pristine in virgin[]. */
                // i的范围是0-7，比较cur[i] && vir[i] == 0xff，如果有一个为真，则设置ret为2
#ifdef __x86_64__
                //注意==的优先级比&&要高，所以先判断vir[i]是否是0xff，即之前从未被覆盖到，然后再和cur[i]进行逻辑与
                if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
                    (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
                    (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
                    (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff))
                    ret = 2; //这代表发现了之前没有出现过的tuple
                else
                    ret = 1; //这代表仅仅只是改变了某个tuple的hit-count

#else

                if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
                    (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff))
                    ret = 2;
                else
                    ret = 1;

#endif /* ^__x86_64__ */
            }

            *virgin &= ~*current;
        }
        // current和virgin移动到下一组8个字节，直到MAPSIZE全被遍历完
        current++;
        virgin++;
    }
    //如果传入给has_new_bits的参数virgin_map是virgin_bits,且ret不为0，就设置bitmap_changed为1
    if (ret && virgin_map == virgin_bits)
        bitmap_changed = 1;

    return ret;
}

/* Count the number of bits set in the provided bitmap. Used for the status
   screen several times every second, does not have to be fast. */

static u32 count_bits(u8 *mem)
{

    u32 *ptr = (u32 *)mem;
    u32 i = (MAP_SIZE >> 2);
    u32 ret = 0;

    while (i--)
    {

        u32 v = *(ptr++);

        /* This gets called on the inverse, virgin bitmap; optimize for sparse
           data. */

        if (v == 0xffffffff)
        {
            ret += 32;
            continue;
        }

        v -= ((v >> 1) & 0x55555555);
        v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
        ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;
    }

    return ret;
}

//(_b)<<3等于_b*8;(0xff << ((_b<<3)))等于将0x000000ff左移(_b*8)位
//最终结果可以是0x000000ff,0x0000ff00,0x00ff0000,0xff000000其中之一（通过下面函数中FF()中参数值推理得到）
#define FF(_b) (0xff << ((_b) << 3))

/* Count the number of bytes set in the bitmap. Called fairly sporadically,
   mostly to update the status screen or calibrate and examine confirmed
   new paths. */

static u32 count_bytes(u8 *mem)
{

    u32 *ptr = (u32 *)mem;
    u32 i = (MAP_SIZE >> 2);
    u32 ret = 0;
    //初始化计数器ret的值为0，循环读取mem里的值，每次读取4个字节到u32变量v中
    while (i--)
    {

        u32 v = *(ptr++);

        if (!v)
            continue; //如果v为0，则代表这四个字节都是0，直接跳过，进入下一次循环
        if (v & FF(0))
            ret++;
        if (v & FF(1))
            ret++;
        if (v & FF(2))
            ret++;
        if (v & FF(3))
            ret++;
    }

    return ret;
}

/* Count the number of non-255 bytes set in the bitmap. Used strictly for the
   status screen, several calls per second or so. */

static u32 count_non_255_bytes(u8 *mem)
{

    u32 *ptr = (u32 *)mem;
    u32 i = (MAP_SIZE >> 2);
    u32 ret = 0;

    while (i--)
    {

        u32 v = *(ptr++);

        /* This is called on the virgin bitmap, so optimize for the most likely
           case. */

        if (v == 0xffffffff)
            continue;
        if ((v & FF(0)) != FF(0))
            ret++;
        if ((v & FF(1)) != FF(1))
            ret++;
        if ((v & FF(2)) != FF(2))
            ret++;
        if ((v & FF(3)) != FF(3))
            ret++;
    }

    return ret;
}

/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or timeout, should be
   reasonably fast. */

static const u8 simplify_lookup[256] = {

    [0] = 1,
    [1 ... 255] = 128 // 128,二进制1000 0000

};

#ifdef __x86_64__

static void simplify_trace(u64 *mem)
{

    u32 i = MAP_SIZE >> 3;

    while (i--)
    {

        /* Optimize for sparse bitmaps. */

        if (unlikely(*mem))
        {
            // i从0-7，mem8[i] = simplify_lookup[mem8[i]]，代表规整该路径的命中次数到指令值，这个路径如果没有命中，就设置为1，如果命中了，就设置为128，即二进制的1000 0000
            u8 *mem8 = (u8 *)mem;

            mem8[0] = simplify_lookup[mem8[0]];
            mem8[1] = simplify_lookup[mem8[1]];
            mem8[2] = simplify_lookup[mem8[2]];
            mem8[3] = simplify_lookup[mem8[3]];
            mem8[4] = simplify_lookup[mem8[4]];
            mem8[5] = simplify_lookup[mem8[5]];
            mem8[6] = simplify_lookup[mem8[6]];
            mem8[7] = simplify_lookup[mem8[7]];
        }
        else
            *mem = 0x0101010101010101ULL;

        mem++;
    }
}

#else

static void simplify_trace(u32 *mem)
{

    u32 i = MAP_SIZE >> 2;
    //按8个字节为一组循环读入，直到完全读取完mem
    while (i--)
    {

        /* Optimize for sparse bitmaps. */

        if (unlikely(*mem))
        {

            u8 *mem8 = (u8 *)mem;

            mem8[0] = simplify_lookup[mem8[0]];
            mem8[1] = simplify_lookup[mem8[1]];
            mem8[2] = simplify_lookup[mem8[2]];
            mem8[3] = simplify_lookup[mem8[3]];
        }
        else
            *mem = 0x01010101; //否则设置mem为0x0101010101010101ULL，即代表这8个字节代表的path都没有命中，每个字节的值被置为1

        mem++;
    }
}

#endif /* ^__x86_64__ */

/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */
// count_class_lookup8中对于执行次数进行了规整，比如执行了4-7次的其计数为8，比如32次到127次都会认为是64次
static const u8 count_class_lookup8[256] = {

    [0] = 0,
    [1] = 1,
    [2] = 2,
    [3] = 4,
    [4 ... 7] = 8,
    [8 ... 15] = 16,
    [16 ... 31] = 32,
    [32 ... 127] = 64,
    [128 ... 255] = 128

};

static u16 count_class_lookup16[65536];

//该函数用来初始化 u16 count_class_lookup16[65536]这个数组。
//将整个 count_class_lookup16 分成256段，每一段256份儿。初始化的时候利用了 count_class_lookup8。
/*
  变量 trace_bits来记录分支执行次数，而count_class_lookup8实际就是对于trace_bits的规整。
  而初始化 count_class_lookup16 实际是因为 AFL 中对于一条分支径的表示是由一个二元组来表示的。
  例如：A->B->C->D->A-B， 可以用[A,B] [B,C] [C,D] [D,A]四个二元组表示，只需要记录跳转的源地址和目标地址。并且[A,B]执行了两次，其余执行了一次，这里用hash映射在一张map中。
  而基于这种二元组的表示的效率考虑，又使用了u16 count_class_lookup16[65536] 这个数组，并在此初始化。
*/
//对应每一条边的执行次数
EXP_ST void init_count_class16(void)
{

    u32 b1, b2;

    for (b1 = 0; b1 < 256; b1++)
        for (b2 = 0; b2 < 256; b2++)
            count_class_lookup16[(b1 << 8) + b2] =
                (count_class_lookup8[b1] << 8) |
                count_class_lookup8[b2]; // count_class_lookup8中对于执行次数进行了规整，比如执行了4-7次的其计数为8，比如32次到127次都会认为是64次
}

#ifdef __x86_64__

static inline void classify_counts(u64 *mem)
{
    // target是将每个分支的执行次数用1个byte来储存，而fuzzer则进一步把这个执行次数归入到buckets中，
    //举个例子，如果某分支执行了1次，那么落入第2个bucket，其计数byte仍为1；如果某分支执行了4次，那么落入第5个bucket，其计数byte将变为8，等等

    //这样处理之后，对分支执行次数就会有一个简单的归类。例如，如果对某个测试用例处理时，分支A执行了32次；对另外一个测试用例，分支A执行了33次，那么AFL就会认为这两次的代码覆盖是相同的。当然，这样的简单分类肯定不能区分所有的情况，不过在某种程度上，处理了一些因为循环次数的微小区别，而误判为不同执行结果的情况
    u32 i = MAP_SIZE >> 3;
    // 8个字节一组去循环读入，直到遍历完整个mem
    while (i--)
    {

        /* Optimize for sparse bitmaps. */

        if (unlikely(*mem))
        {
            //每次取两个字节u16 *mem16 = (u16 *) mem
            u16 *mem16 = (u16 *)mem;
            // i从0到3，计算mem16[i]的值，在count_class_lookup16[mem16[i]]里找到对应的取值，并赋值给mem16[i]
            mem16[0] = count_class_lookup16[mem16[0]];
            mem16[1] = count_class_lookup16[mem16[1]];
            mem16[2] = count_class_lookup16[mem16[2]];
            mem16[3] = count_class_lookup16[mem16[3]];
        }

        mem++;
    }
}

#else

static inline void classify_counts(u32 *mem)
{

    u32 i = MAP_SIZE >> 2;

    while (i--)
    {

        /* Optimize for sparse bitmaps. */

        if (unlikely(*mem))
        {

            u16 *mem16 = (u16 *)mem;

            mem16[0] = count_class_lookup16[mem16[0]];
            mem16[1] = count_class_lookup16[mem16[1]];
        }

        mem++;
    }
}

#endif /* ^__x86_64__ */

/* Get rid of shared memory (atexit handler). */

static void remove_shm(void)
{
    /*
      参数1：shm_id是shmget()函数返回的共享内存标识符。
      参数2：command是要采取的操作，IPC_RMID是删除共享内存段
      参数3：buf是一个结构指针
    */
    shmctl(shm_id, IPC_RMID, NULL);
}

/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. */
//将trace_bits压缩为较小的位图;简单的理解就是把原本是包括了是否覆盖到和覆盖了多少次的byte，压缩成是否覆盖到的bit
static void minimize_bits(u8 *dst, u8 *src)
{

    u32 i = 0;
    //虽然dst是一个bitmap，但是实际上在这里我们还是用一个byte数组来操作它，所以就首先得做byte->bit的映射，比如说将src的前0-7个字节映射到dst的第一个字节(0-7位)
    while (i < MAP_SIZE)
    {
        //然后如果src里该字节的值不为0，i此时就代表这个字节的index索引，其与0000 0111相与，最终的结果都只在0-7之间，这样我们就可以知道这个index在0-7之间对应的具体的bit是哪一个，最后通过或运算将该位置位
        if (*(src++))
            dst[i >> 3] |= 1 << (i & 7);
        i++;
    }
}

/* When we bump into a new path, we call this to see if the path appears
   more "favorable" than any of the existing ones. The purpose of the
   "favorables" is to have a minimal set of paths that trigger all the bits
   seen in the bitmap so far, and focus on fuzzing them at the expense of
   the rest.

   The first step of the process is to maintain a list of top_rated[] entries
   for every byte in the bitmap. We win that slot if there is no previous
   contender, or if the contender has a more favorable speed x size factor. */
//每当我们发现一个新的路径，都会调用这个函数来判断其是不是更加地favorable，这个favorable的意思是说是否包含最小的路径集合来遍历到所有bitmap中的位，我们专注于这些集合而忽略其他的。
//以上过程的第一步是为bitmap中的每个字节维护一个 top_rated[] 的列表，这里会计算究竟哪些位置是更“合适”的，该函数主要实现该过程
static void update_bitmap_score(struct queue_entry *q)
{
    //首先计算出这个case的fav_factor，计算方法是q->exec_us * q->len即执行时间和样例大小的乘积，以这两个指标来衡量权重,越小越优
    u32 i;
    u64 fav_factor = q->exec_us * q->len;

    /* For every byte set in trace_bits[], see if there is a previous winner,
       and how it compares to us. */

    for (i = 0; i < MAP_SIZE; i++)
        //遍历trace_bits数组，如果该字节的值不为0，则代表这是已经被覆盖到的path(tuple?)
        if (trace_bits[i])
        {
            //然后检查对应于这个path的top_rated是否存在
            if (top_rated[i]) // top_rated[]保存各tuple相应的最优测试用例
            {

                /* Faster-executing or smaller test cases are favored. */
                //比较执行时间和样例大小的乘积，哪个更小
                if (fav_factor > top_rated[i]->exec_us * top_rated[i]->len)
                    continue;
                // 如果top_rated[i]的更小，则代表它的更优，不做处理，继续遍历下一个路径；

                /* Looks like we're going to win. Decrease ref count for the
                   previous winner, discard its trace_bits[] if necessary. */
                //如果q更小，就将top_rated[i]原先对应的queue entry的tc_ref字段减一，并将其trace_mini字段置为空
                if (!--top_rated[i]->tc_ref)
                {
                    ck_free(top_rated[i]->trace_mini);
                    top_rated[i]->trace_mini = 0;
                }
            }

            /* Insert ourselves as the new winner. */
            //设置top_rated[i]为q，即当前case，然后将其tc_ref的值加一
            top_rated[i] = q;
            q->tc_ref++;
            //如果q->trace_mini为空，则将trace_bits经过minimize_bits压缩，然后存到trace_mini字段里
            if (!q->trace_mini)
            {
                q->trace_mini = ck_alloc(MAP_SIZE >> 3);
                minimize_bits(q->trace_mini, trace_bits); //将trace_bits经过minimize_bits压缩，存放在trace_mini中
            }

            score_changed = 1;
        }
}

/* The second part of the mechanism discussed above is a routine that
   goes over top_rated[] entries, and then sequentially grabs winners for
   previously-unseen bytes (temp_v) and marks them as favored, at least
   until the next run. The favored entries are given more air time during
   all fuzzing steps. */
//精简队列
//在前面讨论的关于case的 top_rated 的计算中，还有一个机制是检查所有的 top_rated[] 条目，然后
//顺序获取之前没有遇到过的byte的对比分数低的“获胜者”进行标记，标记至少会维持到下一次运行之前。在所有的fuzz步骤中，“favorable”的条目会获得更多的执行时间
/* 例子
  tuple t0,t1,t2,t3,t4；seed s0,s1,s2 初始化temp_v=[1,1,1,1,1]
  s1可覆盖t2,t3 | s2覆盖t0,t1,t4，并且top_rated[0]=s2，top_rated[2]=s1
  开始后判断temp_v[0]=1，说明t0没有被访问
  top_rated[0]存在(s2) -> 判断s2可以覆盖的范围 -> trace_mini=[1,1,0,0,1]
  更新temp_v=[0,0,1,1,0]
  标记s2为favored
  继续判断temp_v[1]=0，说明t1此时已经被访问过了，跳过
  继续判断temp_v[2]=1，说明t2没有被访问
  top_rated[2]存在(s1) -> 判断s1可以覆盖的范围 -> trace_mini=[0,0,1,1,0]
  更新temp_v=[0,0,0,0,0]
  标记s1为favored
  此时所有tuple都被覆盖，favored为s1,s2
*/

static void cull_queue(void)
{

    struct queue_entry *q;
    static u8 temp_v[MAP_SIZE >> 3];
    u32 i;
    //如果score_changed为0，即top_rated没有变化，或者dumb_mode,就直接返回
    if (dumb_mode || !score_changed)
        return;

    score_changed = 0;
    //创建u8 temp_v数组，大小为MAP_SIZE除8，并将其初始值设置为0xff，其每位如果为1就代表还没有被覆盖到，如果为0就代表以及被覆盖到了
    memset(temp_v, 255, MAP_SIZE >> 3);

    queued_favored = 0;
    pending_favored = 0;

    q = queue;
    //开始遍历queue队列，设置所有的favored的值都为0
    while (q)
    {
        q->favored = 0;
        q = q->next;
    }

    /* Let's see if anything in the bitmap isn't captured in temp_v.
       If yes, and if it has a top_rated[] contender, let's use it. */
    //将i从0到MAP_SIZE迭代，这个迭代其实就是筛选出一组queue entry，它们就能够覆盖到所有现在已经覆盖到的路径（猜测这里是覆盖当前所有的tuple状态），而且这个case集合里的case要更小更快，这并不是最优算法，只能算是贪婪算法
    //依次遍历bitmap中的每个byte
    for (i = 0; i < MAP_SIZE; i++)
        //判断每个byte的top_rated是否存在,该byte对应的temp_v是否被置为1
        // temp_v[i >> 3] & (1 << (i & 7))与minimize_bits()的差不多，中间的或运算改成了与，是为了检查该位是不是0，即判断该path对应的bit有没有被置位
        //如果top_rated[i]有值，且该path在temp_v里被置位
        if (top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7))))
        {

            u32 j = MAP_SIZE >> 3;

            /* Remove all bits belonging to the current entry from temp_v. */
            //从temp_v中，移除所有属于当前current-entry的byte，也就是这个testcase触发了多少path就给tempv标记上
            //就从temp_v中清除掉所有top_rated[i]覆盖到的path，将对应的bit置为0
            while (j--)
                if (top_rated[i]->trace_mini[j])               // trace_mini：only record path coverage, ignoring counts.
                    temp_v[j] &= ~top_rated[i]->trace_mini[j]; //从temp_v中清除掉所有top_rated[i]覆盖到的path，将对应的bit设置为0

            top_rated[i]->favored = 1;
            queued_favored++;
            //如果top_rated[i]的was_fuzzed字段是0，代表其还没有fuzz过，则将pending_favored计数器加一
            if (!top_rated[i]->was_fuzzed)
                pending_favored++;
        }

    q = queue;
    //遍历queue队列
    while (q)
    {
        //将queue中冗余的testcase进行标记;如果不是favored的case，就被标记成redundant_edges
        mark_as_redundant(q, !q->favored); // 位置在/queue/.state/redundent_edges中
        q = q->next;
    }
}

/* Configure shared memory and virgin_bits. This is called at startup. */
//该函数用于设置共享内存和 virgin_bits，属于比较重要的函数
//通过 trace_bits 和 virgin_bits 两个 bitmap 来分别记录当前的 tuple 信息及整体 tuple 信息，其中 trace_bits 位于共享内存上，便于进行进程间通信。
//通过 virgin_tmout 和 virgin_crash 两个 bitmap 来记录 fuzz 过程中出现的所有目标程序超时以及崩溃的 tuple 信息
EXP_ST void setup_shm(void)
{

    u8 *shm_str;
    //如果 in_bitmap 为空，调用 memset将virgin_bits[MAP_SIZE]数组的每个元素置为255（0xff）
    if (!in_bitmap)
        memset(virgin_bits, 255, MAP_SIZE); //所有的覆盖状态

    memset(virgin_tmout, 255, MAP_SIZE); //调用 memset 初始化数组 virgin_tmout[MAP_SIZE] 的每个元素的值为 ‘255’ time out的覆盖状态
    memset(virgin_crash, 255, MAP_SIZE); // 调用 memset 初始化数组 virgin_crash[MAP_SIZE] 的每个元素的值为 ‘255’ crash的覆盖状态
    //调用shmget函数分配一块共享内存，将返回的共享内存标识符存到shm_id
    shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);
    /*
      shmget参数
      参数1：程序需要提供一个参数key（非0整数），它有效地为共享内存段命名，shmget()函数
            成功时返回一个与key相关的共享内存标识符（非负整数），用于后续的共享内存函数。调用失败返回-1

      参数2：size以字节为单位指定需要共享的内存容量
      参数3：权限标志。IPC_CREAT 如果共享内存不存在，则创建一个共享内存，否则打开操作。
            IPC_EXCL 只有在共享内存不存在的时候，新的共享内存才建立，否则就产生错误。
            421分别表示，读写执行3种权限。 比如，上面的6＝4＋2，表示读＋写。
            0600 每一位表示一种类型的权限，比如，第一位是表示八进制,第二位表示拥有者的权限
            为读写，第三位表示同组无权限，第四位表示他人无权限。
    */
    if (shm_id < 0)
        PFATAL("shmget() failed");
    /*注册atexit handler为remove_shm。在程序终止时调用remove_shm */
    atexit(remove_shm);
    //创建一个字符串shm_str
    shm_str = alloc_printf("%d", shm_id);

    /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
       we don't want them to detect instrumentation, since we won't be sending
       fork server commands. This should be replaced with better auto-detection
       later on, perhaps? */

    if (!dumb_mode)
        setenv(SHM_ENV_VAR, shm_str, 1); // 如果不是dumb_mode，设置环境变量 SHM_ENV_VAR 的值为 shm_str

    ck_free(shm_str);
    /*
      trac_bits是用做SHM with instrumentation bitmap
      第一次创建完共享内存时，它还不能被任何进程访问，所以通过shmat来启动对该共享内存的访问，并把共享内存连接到当前进程的地址空间。
    */
    trace_bits = shmat(shm_id, NULL, 0);
    /*
      void *shmat(int shm_id, const void *shm_addr, int shm_flg)
      参数1：shm_id是由shmget()函数返回的共享内存标识
      参数2：shm_addr指定共享内存连接到当前进程中的位置，通常为空，表示让系统来选择共享内存的地址
      参数3：shm_flg是一组标志位，通常为0
      函数调用成功返回一个指向共享内存第一个字节的指针，如果调用失败返回 -1
    */

    if (!trace_bits)
        PFATAL("shmat() failed");
}

/* Load postprocessor, if available. */

static void setup_post(void)
{

    void *dh;
    u8 *fn = getenv("AFL_POST_LIBRARY");
    u32 tlen = 6;

    if (!fn)
        return;

    ACTF("Loading postprocessor from '%s'...", fn);

    dh = dlopen(fn, RTLD_NOW);
    if (!dh)
        FATAL("%s", dlerror());

    post_handler = dlsym(dh, "afl_postprocess");
    if (!post_handler)
        FATAL("Symbol 'afl_postprocess' not found.");

    /* Do a quick test. It's better to segfault now than later =) */
    //测试
    post_handler("hello", &tlen);

    OKF("Postprocessor installed successfully.");
}

/* Read all testcases from the input directory, then queue them for testing.
   Called at startup. */
//该函数会将 in_dir 目录下的测试用例扫描到 queue 中，并且区分该文件是否为经过确定性变异的input，如果是的话跳过，以节省时间
static void read_testcases(void)
{

    struct dirent **nl;
    s32 nl_cnt;
    u32 i;
    u8 *fn;

    /* Auto-detect non-in-place resumption attempts. */

    fn = alloc_printf("%s/queue", in_dir);
    if (!access(fn, F_OK))
        in_dir = fn;
    else
        ck_free(fn);

    ACTF("Scanning '%s'...", in_dir);

    /* We use scandir() + alphasort() rather than readdir() because otherwise,
       the ordering  of test cases would vary somewhat randomly and would be
       difficult to control. */

    nl_cnt = scandir(in_dir, &nl, NULL, alphasort);

    if (nl_cnt < 0)
    {

        if (errno == ENOENT || errno == ENOTDIR)

            SAYF("\n" cLRD "[-] " cRST
                 "The input directory does not seem to be valid - try again. The fuzzer needs\n"
                 "    one or more test case to start with - ideally, a small file under 1 kB\n"
                 "    or so. The cases must be stored as regular files directly in the input\n"
                 "    directory.\n");

        PFATAL("Unable to open '%s'", in_dir);
    }

    if (shuffle_queue && nl_cnt > 1)
    {

        ACTF("Shuffling queue...");
        shuffle_ptrs((void **)nl, nl_cnt);
    }

    for (i = 0; i < nl_cnt; i++)
    {

        struct stat st;

        u8 *fn = alloc_printf("%s/%s", in_dir, nl[i]->d_name);
        u8 *dfn = alloc_printf("%s/.state/deterministic_done/%s", in_dir, nl[i]->d_name);

        u8 passed_det = 0;

        free(nl[i]); /* not tracked */

        if (lstat(fn, &st) || access(fn, R_OK))
            PFATAL("Unable to access '%s'", fn);

        /* This also takes care of . and .. */

        if (!S_ISREG(st.st_mode) || !st.st_size || strstr(fn, "/README.txt"))
        {

            ck_free(fn);
            ck_free(dfn);
            continue;
        }
        //种子不要大于 1M
        if (st.st_size > MAX_FILE)
            FATAL("Test case '%s' is too big (%s, limit is %s)", fn,
                  DMS(st.st_size), DMS(MAX_FILE));

        /* Check for metadata that indicates that deterministic fuzzing
           is complete for this entry. We don't want to repeat deterministic
           fuzzing when resuming aborted scans, because it would be pointless
           and probably very time-consuming. */

        if (!access(dfn, F_OK))
            passed_det = 1;
        ck_free(dfn);
        //调用函数 add_to_queue() 将测试用例排成queue队列。该函数会在启动时进行调用     对种子信息初始化，加入队列
        add_to_queue(fn, st.st_size, passed_det); //在read_testcases的时候会调用add_to_queue，此时所有的input case的queue depth都会被设置为1。
    }

    free(nl); /* not tracked */

    if (!queued_paths)
    {

        SAYF("\n" cLRD "[-] " cRST
             "Looks like there are no valid test cases in the input directory! The fuzzer\n"
             "    needs one or more test case to start with - ideally, a small file under\n"
             "    1 kB or so. The cases must be stored as regular files directly in the\n"
             "    input directory.\n");

        FATAL("No usable test cases in '%s'", in_dir);
    }

    last_path_time = 0;
    queued_at_start = queued_paths;
}

/* Helper function for load_extras. */

static int compare_extras_len(const void *p1, const void *p2)
{
    struct extra_data *e1 = (struct extra_data *)p1,
                      *e2 = (struct extra_data *)p2;

    return e1->len - e2->len;
}

static int compare_extras_use_d(const void *p1, const void *p2)
{
    struct extra_data *e1 = (struct extra_data *)p1,
                      *e2 = (struct extra_data *)p2;

    return e2->hit_cnt - e1->hit_cnt;
}

/* Read extras from a file, sort by size. */

static void load_extras_file(u8 *fname, u32 *min_len, u32 *max_len,
                             u32 dict_level)
{

    FILE *f;
    u8 buf[MAX_LINE];
    u8 *lptr;
    u32 cur_line = 0;

    f = fopen(fname, "r");

    if (!f)
        PFATAL("Unable to open '%s'", fname);

    while ((lptr = fgets(buf, MAX_LINE, f)))
    {

        u8 *rptr, *wptr;
        u32 klen = 0;

        cur_line++;

        /* Trim on left and right. */

        while (isspace(*lptr))
            lptr++;

        rptr = lptr + strlen(lptr) - 1;
        while (rptr >= lptr && isspace(*rptr))
            rptr--;
        rptr++;
        *rptr = 0;

        /* Skip empty lines and comments. */

        if (!*lptr || *lptr == '#')
            continue;

        /* All other lines must end with '"', which we can consume. */

        rptr--;

        if (rptr < lptr || *rptr != '"')
            FATAL("Malformed name=\"value\" pair in line %u.", cur_line);

        *rptr = 0;

        /* Skip alphanumerics and dashes (label). */

        while (isalnum(*lptr) || *lptr == '_')
            lptr++;

        /* If @number follows, parse that. */

        if (*lptr == '@')
        {

            lptr++;
            if (atoi(lptr) > dict_level)
                continue;
            while (isdigit(*lptr))
                lptr++;
        }

        /* Skip whitespace and = signs. */

        while (isspace(*lptr) || *lptr == '=')
            lptr++;

        /* Consume opening '"'. */

        if (*lptr != '"')
            FATAL("Malformed name=\"keyword\" pair in line %u.", cur_line);

        lptr++;

        if (!*lptr)
            FATAL("Empty keyword in line %u.", cur_line);

        /* Okay, let's allocate memory and copy data between "...", handling
           \xNN escaping, \\, and \". */

        extras = ck_realloc_block(extras, (extras_cnt + 1) *
                                              sizeof(struct extra_data));

        wptr = extras[extras_cnt].data = ck_alloc(rptr - lptr);

        while (*lptr)
        {

            char *hexdigits = "0123456789abcdef";

            switch (*lptr)
            {

            case 1 ... 31:
            case 128 ... 255:
                FATAL("Non-printable characters in line %u.", cur_line);

            case '\\':

                lptr++;

                if (*lptr == '\\' || *lptr == '"')
                {
                    *(wptr++) = *(lptr++);
                    klen++;
                    break;
                }

                if (*lptr != 'x' || !isxdigit(lptr[1]) || !isxdigit(lptr[2]))
                    FATAL("Invalid escaping (not \\xNN) in line %u.", cur_line);

                *(wptr++) =
                    ((strchr(hexdigits, tolower(lptr[1])) - hexdigits) << 4) |
                    (strchr(hexdigits, tolower(lptr[2])) - hexdigits);

                lptr += 3;
                klen++;

                break;

            default:

                *(wptr++) = *(lptr++);
                klen++;
            }
        }

        extras[extras_cnt].len = klen;

        if (extras[extras_cnt].len > MAX_DICT_FILE)
            FATAL("Keyword too big in line %u (%s, limit is %s)", cur_line,
                  DMS(klen), DMS(MAX_DICT_FILE));

        if (*min_len > klen)
            *min_len = klen;
        if (*max_len < klen)
            *max_len = klen;

        extras_cnt++;
    }

    fclose(f);
}

/* Read extras from the extras directory and sort them by size. */
//如果有token的目录，则将目录下的token加载到extra队列中。
//其中函数load_extras_file从文件中加载extra_file并且排序，将token添加到extra数组中影响参数和load_auto差不多。
static void load_extras(u8 *dir)
{

    DIR *d;
    struct dirent *de;
    u32 min_len = MAX_DICT_FILE, max_len = 0, dict_level = 0;
    u8 *x;

    /* If the name ends with @, extract level and continue. */

    if ((x = strchr(dir, '@')))
    {

        *x = 0;
        dict_level = atoi(x + 1);
    }

    ACTF("Loading extra dictionary from '%s' (level %u)...", dir, dict_level);

    d = opendir(dir);

    if (!d)
    {

        if (errno == ENOTDIR)
        {
            load_extras_file(dir, &min_len, &max_len, dict_level);
            goto check_and_sort;
        }

        PFATAL("Unable to open '%s'", dir);
    }

    if (x)
        FATAL("Dictionary levels not supported for directories.");

    while ((de = readdir(d)))
    {

        struct stat st;
        u8 *fn = alloc_printf("%s/%s", dir, de->d_name);
        s32 fd;

        if (lstat(fn, &st) || access(fn, R_OK))
            PFATAL("Unable to access '%s'", fn);

        /* This also takes care of . and .. */
        if (!S_ISREG(st.st_mode) || !st.st_size)
        {

            ck_free(fn);
            continue;
        }

        if (st.st_size > MAX_DICT_FILE)
            FATAL("Extra '%s' is too big (%s, limit is %s)", fn,
                  DMS(st.st_size), DMS(MAX_DICT_FILE));

        if (min_len > st.st_size)
            min_len = st.st_size;
        if (max_len < st.st_size)
            max_len = st.st_size;

        extras = ck_realloc_block(extras, (extras_cnt + 1) *
                                              sizeof(struct extra_data));

        extras[extras_cnt].data = ck_alloc(st.st_size);
        extras[extras_cnt].len = st.st_size;

        fd = open(fn, O_RDONLY);

        if (fd < 0)
            PFATAL("Unable to open '%s'", fn);

        ck_read(fd, extras[extras_cnt].data, st.st_size, fn);

        close(fd);
        ck_free(fn);

        extras_cnt++;
    }

    closedir(d);

check_and_sort:

    if (!extras_cnt)
        FATAL("No usable files in '%s'", dir);

    qsort(extras, extras_cnt, sizeof(struct extra_data), compare_extras_len);

    OKF("Loaded %u extra tokens, size range %s to %s.", extras_cnt,
        DMS(min_len), DMS(max_len));

    if (max_len > 32)
        WARNF("Some tokens are relatively large (%s) - consider trimming.",
              DMS(max_len));

    if (extras_cnt > MAX_DET_EXTRAS)
        WARNF("More than %u tokens - will use them probabilistically.",
              MAX_DET_EXTRAS);
}

/* Helper function for maybe_add_auto() */

static inline u8 memcmp_nocase(u8 *m1, u8 *m2, u32 len)
{

    while (len--)
        if (tolower(*(m1++)) ^ tolower(*(m2++)))
            return 1;
    return 0;
}

/* Maybe add automatic extra. */
//添加Token
static void maybe_add_auto(u8 *mem, u32 len)
{

    u32 i;

    /* Allow users to specify that they don't want auto dictionaries. */
    //如果用户设置了MAX_AUTO_EXTRAS或者USE_AUTO_EXTRAS为0，则直接返回
    if (!MAX_AUTO_EXTRAS || !USE_AUTO_EXTRAS)
        return;

    /* Skip runs of identical bytes. */

    for (i = 1; i < len; i++)
        if (mem[0] ^ mem[i])
            break;

    if (i == len)
        return;

    /* Reject builtin interesting values. */

    if (len == 2)
    {

        i = sizeof(interesting_16) >> 1;

        while (i--)
            if (*((u16 *)mem) == interesting_16[i] ||
                *((u16 *)mem) == SWAP16(interesting_16[i]))
                return;
    }

    if (len == 4)
    {

        i = sizeof(interesting_32) >> 2;

        while (i--)
            if (*((u32 *)mem) == interesting_32[i] ||
                *((u32 *)mem) == SWAP32(interesting_32[i]))
                return;
    }

    /* Reject anything that matches existing extras. Do a case-insensitive
       match. We optimize by exploiting the fact that extras[] are sorted
       by size. */

    for (i = 0; i < extras_cnt; i++)
        if (extras[i].len >= len)
            break;

    for (; i < extras_cnt && extras[i].len == len; i++)
        if (!memcmp_nocase(extras[i].data, mem, len))
            return;

    /* Last but not least, check a_extras[] for matches. There are no
       guarantees of a particular sort order. */

    auto_changed = 1;

    for (i = 0; i < a_extras_cnt; i++)
    {
        // memcmp_nocase：比较a_extras[i].data与mem的内容是否相同
        if (a_extras[i].len == len && !memcmp_nocase(a_extras[i].data, mem, len))
        {

            a_extras[i].hit_cnt++; // hit_cnt表示该token被use的次数
            goto sort_a_extras;
        }
    }

    /* At this point, looks like we're dealing with a new entry. So, let's
       append it if we have room. Otherwise, let's randomly evict some other
       entry from the bottom half of the list. */

    if (a_extras_cnt < MAX_AUTO_EXTRAS)
    { //如果小于，则表明a_extras数组未填满，可以直接拷贝mem和len

        a_extras = ck_realloc_block(a_extras, (a_extras_cnt + 1) *
                                                  sizeof(struct extra_data));

        a_extras[a_extras_cnt].data = ck_memdup(mem, len);
        a_extras[a_extras_cnt].len = len;
        a_extras_cnt++;
    }
    else
    {
        //若a_extras已满，从a_extras数组的后半部分里，随机替换掉一个元素的a_extras[i].data为ck_memdup(mem, len)，并将len设置为len，hit_cnt设置为0
        i = MAX_AUTO_EXTRAS / 2 +
            UR((MAX_AUTO_EXTRAS + 1) / 2);

        ck_free(a_extras[i].data);

        a_extras[i].data = ck_memdup(mem, len);
        a_extras[i].len = len;
        a_extras[i].hit_cnt = 0;
    }

sort_a_extras:

    /* First, sort all auto extras by use count, descending order. */

    qsort(a_extras, a_extras_cnt, sizeof(struct extra_data),
          compare_extras_use_d);

    /* Then, sort the top USE_AUTO_EXTRAS entries by size. */

    qsort(a_extras, MIN(USE_AUTO_EXTRAS, a_extras_cnt),
          sizeof(struct extra_data), compare_extras_len);
}

/* Save automatically generated extras. */
//保存自动生成的extras
static void save_auto(void)
{

    u32 i;

    if (!auto_changed)
        return;
    auto_changed = 0;

    for (i = 0; i < MIN(USE_AUTO_EXTRAS, a_extras_cnt); i++)
    {
        //创建名为alloc_printf("%s/queue/.state/auto_extras/auto_%06u", out_dir, i);的文件
        u8 *fn = alloc_printf("%s/queue/.state/auto_extras/auto_%06u", out_dir, i);
        s32 fd;

        fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);

        if (fd < 0)
            PFATAL("Unable to create '%s'", fn);
        //写入a_extras的内容
        ck_write(fd, a_extras[i].data, a_extras[i].len, fn);

        close(fd);
        ck_free(fn);
    }
}

/* Load automatically generated extras. */
// load自动生成的提取出来的词典token         加载自动生成的字典，token使用次数越多，排名越前
static void load_auto(void)
{

    u32 i;

    for (i = 0; i < USE_AUTO_EXTRAS; i++)
    {

        u8 tmp[MAX_AUTO_EXTRA + 1];
        u8 *fn = alloc_printf("%s/.state/auto_extras/auto_%06u", in_dir, i);
        s32 fd, len;
        //以只读模式尝试打开文件名为alloc_printf("%s/.state/auto_extras/auto_%06u", in_dir, i)的文件
        fd = open(fn, O_RDONLY, 0600);

        if (fd < 0)
        {

            if (errno != ENOENT)
                PFATAL("Unable to open '%s'", fn);
            ck_free(fn);
            break;
        }

        /* We read one byte more to cheaply detect tokens that are too
           long (and skip them). */

        len = read(fd, tmp, MAX_AUTO_EXTRA + 1);

        if (len < 0)
            PFATAL("Unable to read from '%s'", fn);
        // token越短，排名越前
        if (len >= MIN_AUTO_EXTRA && len <= MAX_AUTO_EXTRA)
            maybe_add_auto(tmp, len);

        close(fd);
        ck_free(fn);
    }

    if (i)
        OKF("Loaded %u auto-discovered dictionary tokens.", i);
    else
        OKF("No auto-generated dictionary tokens to reuse.");
}

/* Destroy extras. */

static void destroy_extras(void)
{

    u32 i;

    for (i = 0; i < extras_cnt; i++)
        ck_free(extras[i].data);

    ck_free(extras);

    for (i = 0; i < a_extras_cnt; i++)
        ck_free(a_extras[i].data);

    ck_free(a_extras);
}

/* Spin up fork server (instrumented mode only). The idea is explained here:

   http://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html

   In essence, the instrumentation allows us to skip execve(), and just keep
   cloning a stopped child. So, we just execute once, and then send commands
   through a pipe. The other part of this logic is in afl-as.h. */
//该函数主要用于启动APP和它的forkserver
// AFL的fork server机制避免了多次执行 execve() 函数的多次调用，只需要调用一次然后通过管道发送命令即可
EXP_ST void init_forkserver(char **argv)
{

    static struct itimerval it;
    int st_pipe[2], ctl_pipe[2];
    int status;
    s32 rlen;

    ACTF("Spinning up the fork server...");
    //检查输入输出管道是否存在。检查 st_pipe 和ctl_pipe，在父子进程间进行管道通信，一个用于传递状态，一个用于传递命令
    if (pipe(st_pipe) || pipe(ctl_pipe))
        PFATAL("pipe() failed");

    forksrv_pid = fork();
    // fork进程出一个子进程
    // 如果fork成功，则现在有父子两个进程。pid=0的话就是fork出来的子进程；！=0的话就是父进程 ,＜0就是fork失败
    // 此时的父进程为fuzzer，子进程则为目标程序进程，也是将来的fork server

    // fork失败就打印关键词弹出失败并退出（这里起什么作用？）
    if (forksrv_pid < 0)
        PFATAL("fork() failed");

    //如果是子进程的话，就执行下面
    if (!forksrv_pid)
    { //子进程返回0

        struct rlimit r;

        /* Umpf. On OpenBSD, the default fd limit for root users is set to
           soft 128. Let's try to fix that... */

        if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2)
        {

            r.rlim_cur = FORKSRV_FD + 2;
            setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */
        }

        if (mem_limit)
        {

            r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

            setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

            /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
               according to reliable sources, RLIMIT_DATA covers anonymous
               maps - so we should be getting good protection against OOM bugs. */

            setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */
        }

        /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
           before the dump is complete. */

        r.rlim_max = r.rlim_cur = 0;

        setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

        /* Isolate the process and configure standard descriptors. If out_file is
           specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */
        //该函数用于创建一个守护进程。在这个程序里面意思就是让该进程成为这个进程组的组长
        setsid();
        // dup2函数：复制一个文件的描述符。它们经常用来重定向进程的stdin、stdout和stderr;
        //重定向文件描述符1和2到dev_null_fd
        dup2(dev_null_fd, 1);
        dup2(dev_null_fd, 2);
        //如果指定了out_file，则文件描述符0重定向到dev_null_fd，否则重定向到out_fd
        if (out_file)
        {

            dup2(dev_null_fd, 0);
        }
        else
        {

            dup2(out_fd, 0);
            close(out_fd);
        }

        /* Set up control and status pipes, close the unneeded original fds. */
        //// 设置控制和状态管道，关闭不需要的一些文件描述符
        //重定向FORKSRV_FD到ctl_pipe[0],重定向FORKSRV_FD + 1到st_pipe[1]
        //子进程只能读取命令;子进程只能发送(“写出”)状态
        if (dup2(ctl_pipe[0], FORKSRV_FD) < 0)
            PFATAL("dup2() failed");
        if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0)
            PFATAL("dup2() failed");
        //关闭子进程里的一些文件描述符
        close(ctl_pipe[0]);
        close(ctl_pipe[1]);
        close(st_pipe[0]);
        close(st_pipe[1]);

        close(out_dir_fd);
        close(dev_null_fd);
        close(dev_urandom_fd);
        close(fileno(plot_file));

        /* This should improve performance a bit, since it stops the linker from
           doing extra work post-fork(). */
        // 如果没有设置延迟绑定，则进行设置，不使用缺省模式
        //读取环境变量LD_BIND_LAZY，如果没有设置，则设置环境变量LD_BIND_NOW为1
        if (!getenv("LD_BIND_LAZY"))
            setenv("LD_BIND_NOW", "1", 0);

        /* Set sane defaults for ASAN if nothing else specified. */
        // 设置环境变量ASAN_OPTIONS，配置ASAN相关
        setenv("ASAN_OPTIONS", "abort_on_error=1:"
                               "detect_leaks=0:"
                               "symbolize=0:"
                               "allocator_may_return_null=1",
               0);

        /* MSAN is tricky, because it doesn't support abort_on_error=1 at this
           point. So, we do this in a very hacky way. */
        // MSAN相关
        setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                                                                  "symbolize=0:"
                                                                  "abort_on_error=1:"
                                                                  "allocator_may_return_null=1:"
                                                                  "msan_track_origins=0",
               0);
        //如果成功，执行execv用以开始执行程序，这个函数除非出错,不然不会返回
        // execv会替换掉原有的进程空间为target_path代表的程序，所以相当于后续就是去执行target_path，这个程序结束的话，子进程就结束
        //在这里非常特殊，第一个target会进入__afl_maybe_log里的__afl_fork_wait_loop，并充当fork server，在整个Fuzz的过
        //程中，它都不会结束，每次要Fuzz一次target，都会从这个fork server fork出来一个子进程去fuzz
        //可以看作：fuzzer -> fork server -> target子进程
        execv(target_path, argv);

        /* Use a distinctive bitmap signature to tell the parent about execv()
           falling through. */
        //此处使用一个EXEC_FAIL_SIG 来告诉父进程执行失败
        //使用一个独特的bitmaps EXEC_FAIL_SIG(0xfee1dead)写入trace_bits，来告诉父进程执行失败，并结束子进程
        *(u32 *)trace_bits = EXEC_FAIL_SIG;
        exit(0);
    }

    /* Close the unneeded endpoints. */
    // 关闭不需要的endpoints
    close(ctl_pipe[0]);
    close(st_pipe[1]);

    fsrv_ctl_fd = ctl_pipe[1]; //父进程只能发送("写出")命令
    fsrv_st_fd = st_pipe[0];   //父进程只能读取状态

    /* Wait for the fork server to come up, but don't wait too long. */
    //在一定时间内等待fork server启动，但是不能等太久。（所以在调试时要注意这个）
    it.it_value.tv_sec = ((exec_tmout * FORK_WAIT_MULT) / 1000);
    it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

    setitimer(ITIMER_REAL, &it, NULL);

    rlen = read(fsrv_st_fd, &status, 4);

    it.it_value.tv_sec = 0;
    it.it_value.tv_usec = 0;

    setitimer(ITIMER_REAL, &it, NULL);

    /* If we have a four-byte "hello" message from the server, we're all set.
       Otherwise, try to figure out what went wrong. */
    // fuzzer从server中读取了四个字节的hello ，那么forkserver程序就设置成功了，就结束这个函数并返回。如果没有，接下来的代码就是检查错误
    if (rlen == 4)
    { // 以读取的结果判断fork server是否成功启动
        OKF("All right - fork server is up.");
        return;
    }

    // 子进程启动失败的异常处理相关
    if (child_timed_out)
        FATAL("Timeout while initializing fork server (adjusting -t may help)");

    if (waitpid(forksrv_pid, &status, 0) <= 0)
        PFATAL("waitpid() failed");

    if (WIFSIGNALED(status))
    {

        if (mem_limit && mem_limit < 500 && uses_asan)
        {

            SAYF("\n" cLRD "[-] " cRST
                 "Whoops, the target binary crashed suddenly, before receiving any input\n"
                 "    from the fuzzer! Since it seems to be built with ASAN and you have a\n"
                 "    restrictive memory limit configured, this is expected; please read\n"
                 "    %s/notes_for_asan.txt for help.\n",
                 doc_path);
        }
        else if (!mem_limit)
        {

            SAYF("\n" cLRD "[-] " cRST
                 "Whoops, the target binary crashed suddenly, before receiving any input\n"
                 "    from the fuzzer! There are several probable explanations:\n\n"

                 "    - The binary is just buggy and explodes entirely on its own. If so, you\n"
                 "      need to fix the underlying problem or find a better replacement.\n\n"

#ifdef __APPLE__

                 "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
                 "      break afl-fuzz performance optimizations when running platform-specific\n"
                 "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

                 "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
                 "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");
        }
        else
        {

            SAYF("\n" cLRD "[-] " cRST
                 "Whoops, the target binary crashed suddenly, before receiving any input\n"
                 "    from the fuzzer! There are several probable explanations:\n\n"

                 "    - The current memory limit (%s) is too restrictive, causing the\n"
                 "      target to hit an OOM condition in the dynamic linker. Try bumping up\n"
                 "      the limit with the -m setting in the command line. A simple way confirm\n"
                 "      this diagnosis would be:\n\n"

#ifdef RLIMIT_AS
                 "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
                 "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

                 "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
                 "      estimate the required amount of virtual memory for the binary.\n\n"

                 "    - The binary is just buggy and explodes entirely on its own. If so, you\n"
                 "      need to fix the underlying problem or find a better replacement.\n\n"

#ifdef __APPLE__

                 "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
                 "      break afl-fuzz performance optimizations when running platform-specific\n"
                 "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

                 "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
                 "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
                 DMS(mem_limit << 20), mem_limit - 1);
        }

        FATAL("Fork server crashed with signal %d", WTERMSIG(status));
    }

    if (*(u32 *)trace_bits == EXEC_FAIL_SIG)
        FATAL("Unable to execute target application ('%s')", argv[0]);

    if (mem_limit && mem_limit < 500 && uses_asan)
    {

        SAYF("\n" cLRD "[-] " cRST
             "Hmm, looks like the target binary terminated before we could complete a\n"
             "    handshake with the injected code. Since it seems to be built with ASAN and\n"
             "    you have a restrictive memory limit configured, this is expected; please\n"
             "    read %s/notes_for_asan.txt for help.\n",
             doc_path);
    }
    else if (!mem_limit)
    {

        SAYF("\n" cLRD "[-] " cRST
             "Hmm, looks like the target binary terminated before we could complete a\n"
             "    handshake with the injected code. Perhaps there is a horrible bug in the\n"
             "    fuzzer. Poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");
    }
    else
    {

        SAYF("\n" cLRD "[-] " cRST
             "Hmm, looks like the target binary terminated before we could complete a\n"
             "    handshake with the injected code. There are %s probable explanations:\n\n"

             "%s"
             "    - The current memory limit (%s) is too restrictive, causing an OOM\n"
             "      fault in the dynamic linker. This can be fixed with the -m option. A\n"
             "      simple way to confirm the diagnosis may be:\n\n"

#ifdef RLIMIT_AS
             "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
             "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

             "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
             "      estimate the required amount of virtual memory for the binary.\n\n"

             "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
             "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
             getenv(DEFER_ENV_VAR) ? "three" : "two",
             getenv(DEFER_ENV_VAR) ? "    - You are using deferred forkserver, but __AFL_INIT() is never\n"
                                     "      reached before the program terminates.\n\n"
                                   : "",
             DMS(mem_limit << 20), mem_limit - 1);
    }

    FATAL("Fork server handshake failed");
}

/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */
//执行目标应用程序，监控超时。返回状态信息。被调用的程序将更新trace_bits[]。
//该函数将在每次运行targetBinary的时候调用，次数非常多
static u8 run_target(char **argv, u32 timeout)
{

    static struct itimerval it;
    static u32 prev_timed_out = 0;

    int status = 0;
    u32 tb4;

    child_timed_out = 0;

    /* After this memset, trace_bits[] are effectively volatile, so we
       must prevent any earlier operations from venturing into that
       territory. */
    //在每次target执行之前，fuzzer首先将该共享内容清零;先清空trace_bits[MAP_SIZE]，将其全置为0，也就是清空共享内存
    memset(trace_bits, 0, MAP_SIZE);
    MEM_BARRIER();

    /* If we're running in "dumb" mode, we can't rely on the fork server
       logic compiled into the target program, so we will just keep calling
       execve(). There is a bit of code duplication between here and
       init_forkserver(), but c'est la vie. */

    if (dumb_mode == 1 || no_forkserver)
    {

        child_pid = fork();

        if (child_pid < 0)
            PFATAL("fork() failed");

        if (!child_pid)
        {

            struct rlimit r;

            if (mem_limit)
            {

                r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

                setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

                setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */
            }

            r.rlim_max = r.rlim_cur = 0;

            setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

            /* Isolate the process and configure standard descriptors. If out_file is
               specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */
            //该函数用于创建一个守护进程。在这个程序里面意思就是让该进程成为这个进程组的组长
            setsid();

            dup2(dev_null_fd, 1);
            dup2(dev_null_fd, 2);

            if (out_file)
            {

                dup2(dev_null_fd, 0);
            }
            else
            {

                dup2(out_fd, 0);
                close(out_fd);
            }

            /* On Linux, would be faster to use O_CLOEXEC. Maybe TODO. */

            close(dev_null_fd);
            close(out_dir_fd);
            close(dev_urandom_fd);
            close(fileno(plot_file));

            /* Set sane defaults for ASAN if nothing else specified. */

            setenv("ASAN_OPTIONS", "abort_on_error=1:"
                                   "detect_leaks=0:"
                                   "symbolize=0:"
                                   "allocator_may_return_null=1",
                   0);

            setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                                                                      "symbolize=0:"
                                                                      "msan_track_origins=0",
                   0);

            execv(target_path, argv);

            /* Use a distinctive bitmap value to tell the parent about execv()
               falling through. */

            *(u32 *)trace_bits = EXEC_FAIL_SIG;
            exit(0);
        }
    }
    else
    {
        //否则，就向控制管道写入prev_timed_out的值，命令Fork server开始fork出一个子进程进行fuzz，然后从状态管道读取fork server返
        //回的fork出的子进程的ID到child_pid
        s32 res;

        /* In non-dumb mode, we have the fork server up and running, so simply
           tell it to have at it, and then read back PID. */
        // fsrv_ctl_fd 管道用于写
        if ((res = write(fsrv_ctl_fd, &prev_timed_out, 4)) != 4)
        {

            if (stop_soon)
                return 0;
            RPFATAL(res, "Unable to request new process from fork server (OOM?)");
        }
        // fsrv_st_fd 管道用来读
        if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4)
        {

            if (stop_soon)
                return 0;
            RPFATAL(res, "Unable to request new process from fork server (OOM?)");
        }

        if (child_pid <= 0)
            FATAL("Fork server is misbehaving (OOM?)");
    }

    /* Configure timeout, as requested by user, then wait for child to terminate. */
    //无论实际执行的是上面两种的哪一种，在执行target期间，都设置计数器为timeout，如果超时，就杀死正在执行的子进程，并设置child_timed_out为1
    it.it_value.tv_sec = (timeout / 1000);
    it.it_value.tv_usec = (timeout % 1000) * 1000;

    setitimer(ITIMER_REAL, &it, NULL);

    /* The SIGALRM handler simply kills the child_pid and sets child_timed_out. */
    //等待target执行结束，如果是dumb_mode，target执行结束的状态码将直接保存到status中，如果不是dumb_mode，则从状态管道中读取target执行结束的状态码
    if (dumb_mode == 1 || no_forkserver)
    {

        if (waitpid(child_pid, &status, 0) <= 0)
            PFATAL("waitpid() failed");
    }
    else
    {

        s32 res;

        if ((res = read(fsrv_st_fd, &status, 4)) != 4)
        {

            if (stop_soon)
                return 0;
            RPFATAL(res, "Unable to communicate with fork server (OOM?)");
        }
    }

    if (!WIFSTOPPED(status))
        child_pid = 0;

    it.it_value.tv_sec = 0;
    it.it_value.tv_usec = 0;
    //计算target执行时间exec_ms，并将total_execs这个执行次数计数器加一
    setitimer(ITIMER_REAL, &it, NULL);

    total_execs++;

    /* Any subsequent operations on trace_bits must not be moved by the
       compiler below this point. Past this location, trace_bits[] behave
       very normally and do not have to be treated as volatile. */

    MEM_BARRIER();

    tb4 = *(u32 *)trace_bits;
//分别执行32和64位下面的函数classify_counts()设置tracebit所在的mem
#ifdef __x86_64__
    classify_counts((u64 *)trace_bits);
#else
    classify_counts((u32 *)trace_bits);
#endif /* ^__x86_64__ */

    prev_timed_out = child_timed_out;

    /* Report outcome to caller. */
    // WIFSIGNALED(status)若为异常结束子进程返回的状态，则为真
    if (WIFSIGNALED(status) && !stop_soon)
    {
        // WTERMSIG(status)取得子进程因信号而中止的信号代码
        kill_signal = WTERMSIG(status);
        //如果child_timed_out为1，且状态码为SIGKILL，则返回FAULT_TMOUT
        if (child_timed_out && kill_signal == SIGKILL)
            return FAULT_TMOUT;

        return FAULT_CRASH;
    }

    /* A somewhat nasty hack for MSAN, which doesn't support abort_on_error and
       must use a special exit code. */

    if (uses_asan && WEXITSTATUS(status) == MSAN_ERROR)
    {
        kill_signal = 0;
        return FAULT_CRASH;
    }
    //如果是dumb_mode，且trace_bits为EXEC_FAIL_SIG，就返回FAULT_ERROR
    if ((dumb_mode == 1 || no_forkserver) && tb4 == EXEC_FAIL_SIG)
        return FAULT_ERROR;
    //
    return FAULT_NONE;
    // runtarget最后会返回fault参数
}

/* Write modified data to file for testing. If out_file is set, the old file
   is unlinked and a new one is created. Otherwise, out_fd is rewound and
   truncated. */
//变异后的内容写入测试文件;将从mem中读取len个字节，写入到.cur_input中
static void write_to_testcase(void *mem, u32 len)
{

    s32 fd = out_fd;

    if (out_file)
    {

        unlink(out_file); /* Ignore errors. */

        fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

        if (fd < 0)
            PFATAL("Unable to create '%s'", out_file);
    }
    else
        lseek(fd, 0, SEEK_SET);

    ck_write(fd, mem, len, out_file);

    if (!out_file)
    {

        if (ftruncate(fd, len))
            PFATAL("ftruncate() failed");
        lseek(fd, 0, SEEK_SET);
    }
    else
        close(fd);
}

/* The same, but with an adjustable gap. Used for trimming. */

static void write_with_gap(void *mem, u32 len, u32 skip_at, u32 skip_len)
{

    s32 fd = out_fd;
    u32 tail_len = len - skip_at - skip_len;

    if (out_file)
    {

        unlink(out_file); /* Ignore errors. */

        fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

        if (fd < 0)
            PFATAL("Unable to create '%s'", out_file);
    }
    else
        lseek(fd, 0, SEEK_SET);

    if (skip_at)
        ck_write(fd, mem, skip_at, out_file);

    if (tail_len)
        ck_write(fd, mem + skip_at + skip_len, tail_len, out_file);

    if (!out_file)
    {

        if (ftruncate(fd, len - skip_len))
            PFATAL("ftruncate() failed");
        lseek(fd, 0, SEEK_SET);
    }
    else
        close(fd);
}

static void show_stats(void);

/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on. */
// afl关键函数
//在perform_dry_run，save_if_interesting，fuzz_one，pilot_fuzzing,core_fuzzing函数中均有调用
//该函数主要用途是init_forkserver；将testcase运行多次；用update_bitmap_score进行初始的byte排序
//校准一个新的测试用例。这是在处理输入目录时完成的，以便在早期就警告有问题的测试用例;当发现新的路径来检测变量行为等等

//这个函数评估input文件夹下的case，来发现这些testcase的行为是否异常；以及在发现新的路径时，用以评估这个新发现的testcase的
//行为是否是可变（这里的可变是指多次执行这个case，发现的路径不同）等等
static u8 calibrate_case(char **argv, struct queue_entry *q, u8 *use_mem,
                         u32 handicap, u8 from_queue)
{
    //函数最后一个参数from_queue,判断是否是为队列中的||刚恢复fuzz 以此设置较长的时间延迟
    static u8 first_trace[MAP_SIZE];

    u8 fault = 0, new_bits = 0, var_detected = 0,
       first_run = (q->exec_cksum == 0); //如果q->exec_cksum为0，代表这是这个case第一次运行，即来自input文件夹下，所以将first_run置为1

    u64 start_us, stop_us;

    s32 old_sc = stage_cur, old_sm = stage_max;
    u32 use_tmout = exec_tmout;
    u8 *old_sn = stage_name;

    /* Be a bit more generous about timeouts when resuming sessions, or when
       trying to calibrate already-added finds. This helps avoid trouble due
       to intermittent latency. */

    if (!from_queue || resuming_fuzz)
        //如果from_queue是0或者resuming_fuzz被置为1，即代表不来自于queue中或者在resuming sessions的时候，则use_tmout的值被设置的更大
        use_tmout = MAX(exec_tmout + CAL_TMOUT_ADD,
                        exec_tmout * CAL_TMOUT_PERC / 100); // 提升 use_tmout 的值

    q->cal_failed++; // testcase参数q->cal_failed++ 是否校准失败参数++

    stage_name = "calibration"; //阶段名称
    //根据是否fast_cal为1，来设置stage_max的值为3还是CAL_CYCLES(默认为8)，含义是每个新测试用例（以及显示出可变行为的测试用例）的校准
    //设置校验次数；默认是8，可以设置成3   周期数，也就是说这个stage要执行几次的意思
    stage_max = fast_cal ? 3 : CAL_CYCLES; // 设置 stage_max，新测试用例的校准周期数

    /* Make sure the forkserver is up before we do anything, and let's not
       count its spin-up time toward binary calibration. */
    //判断是否已经启动forkserver ,调用函数init_forkserver()启动fork服务
    if (dumb_mode != 1 && !no_forkserver && !forksrv_pid)
        init_forkserver(argv); // 没有运行在dumb_mode，没有禁用fork server，切forksrv_pid为0时，启动fork server

    //如果这个queue不是来自input文件夹，而是评估新case，则此时q->exec_cksum不为空，拷贝trace_bits到first_trace里，然后
    //计算has_new_bits的值，赋值给new_bits

    //拷贝trace_bits到first_trace
    if (q->exec_cksum)
        memcpy(first_trace, trace_bits, MAP_SIZE);
    //获取开始时间start_us
    start_us = get_cur_time_us();

    /* 开始执行calibration stage，共执行sstage_max轮 */
    //循环多次执行这个testcase，循环的次数 8次或者3次，取决于是否快速校准
    //猜测：对同一个初始testcase多次运行的意义可能是，觉得有些targetApp执行同一个testcase可能也会出现不同的路径
    for (stage_cur = 0; stage_cur < stage_max; stage_cur++)
    {

        u32 cksum;
        //如果这个queue不是来自input文件夹，而是评估新case，且第一轮calibration stage执行结束
        //时，刷新一次展示界面show_stats，用来展示这次执行的结果，此后不再展示
        if (!first_run && !(stage_cur % stats_update_freq))
            show_stats();
        //将修改后的数据写入文件进行测试，即将从q->fname中读取的内容写入到.cur_input中
        write_to_testcase(use_mem, q->len);
        //通知forkserver可以开始fork并fuzz
        fault = run_target(argv, use_tmout);

        /* stop_soon is set by the handler for Ctrl+C. When it's pressed,
           we want to bail out quickly. */
        //如果执行失败，种子校准置空
        if (stop_soon || fault != crash_mode)
            goto abort_calibration;
        //如果这是calibration stage第一次运行，且不在dumb_mode，且共享内存里没有
        //任何路径（即没有任何byte被置位），设置fault为FAULT_NOINST,然后goto abort_calibration
        if (!dumb_mode && !stage_cur && !count_bytes(trace_bits))
        {
            fault = FAULT_NOINST;
            goto abort_calibration;
        }

        cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST); //校验此次运行的trace_bits，检查是否出现新的情况
        //先用cksum也就是本次运行的出现trace_bits哈希和本次testcase q->exec_cksum对比
        //如果发现不同，则调用has_new_bits函数和我们的总表virgin_bits对比
        if (q->exec_cksum != cksum)
        { //检查是否有新的覆盖状态
            //如果q->exec_cksum不等于cksum，即代表这是第一次运行，或者在相同的参数下，每次执行，cksum却不同，是一个路径可变的queue
            u8 hnb = has_new_bits(virgin_bits);
            if (hnb > new_bits)
                new_bits = hnb;
            //判断判断q->exec_cksum 是否为0，不为0那说明不是第一次执行
            //后面运行的时候如果，和前面第一次trace_bits结果不同，则需要多运行几次
            if (q->exec_cksum)
            { //如果q->exec_cksum不等于0，即代表这是判断是否是可变queue

                u32 i;

                for (i = 0; i < MAP_SIZE; i++)
                {
                    // 从0到MAP_SIZE进行遍历， first_trace[i] != trace_bits[i]，表示发现了可变queue

                    //如果first_trace[i]不等于trace_bits[i]，代表发现了可变queue，且var_bytes
                    //为空，则将该字节设置为1，并将stage_max设置为CAL_CYCLES_LONG，即需要执行40次
                    if (!var_bytes[i] && first_trace[i] != trace_bits[i])
                    {

                        var_bytes[i] = 1;
                        stage_max = CAL_CYCLES_LONG; //这里把校准次数设为40
                    }
                }

                var_detected = 1;
            }
            else
            { //即q->exec_cksum等于0，即代表这是第一次执行这个queue

                q->exec_cksum = cksum;                     //设置q->exec_cksum的值为之前计算出来的本次执行的cksum
                memcpy(first_trace, trace_bits, MAP_SIZE); //拷贝trace_bits到first_trace中
            }
        }
    }
    //检查是否有新的覆盖状态
    stop_us = get_cur_time_us();

    total_cal_us += stop_us - start_us; //保存所有轮次总的执行时间，加到total_cal_us里，总的执行轮次，加到total_cal_cycles里
    total_cal_cycles += stage_max;      // 保存总轮次

    /* OK, let's collect some stats about the performance of this test case.
       This is used for fuzzing air time calculations in calculate_score(). */

    q->exec_us = (stop_us - start_us) / stage_max; //执行时间延迟，计算出单次执行时间的平均值保存到q->exec_us里
    q->bitmap_size = count_bytes(trace_bits);      // bitmap大小，将最后一次执行所覆盖到的路径数保存到q->bitmap_size里    命中的边的次数
    q->handicap = handicap;                        //种子执行了几轮
    q->cal_failed = 0;                             //校准错误,总校验数

    total_bitmap_size += q->bitmap_size; // total_bitmap_size里加上这个queue所覆盖到的路径数
    total_bitmap_entries++;
    // 对这个测试用例的每一个byte进行排序，用一个top_rate[]来维护它的最佳入口
    // 更新q的分数（更新优先选择队列）
    update_bitmap_score(q);

    /* If this case didn't result in new output from the instrumentation, tell
       parent. This is a non-critical problem, but something to warn the user
       about. */
    //如果这种情况没有从检测中得到new_bit，则告诉父程序。这是一个无关紧要的问题，但是需要提醒用户注意
    //如果fault为FAULT_NONE，且该queue是第一次执行，且不属于dumb_mode，而且new_bits为0，代表在这个样例
    //所有轮次的执行里，都没有发现任何新路径和出现异常，设置fault为FAULT_NOBITS
    if (!dumb_mode && first_run && !fault && !new_bits)
        fault = FAULT_NOBITS;
//中断校准
abort_calibration:
    //是否产生新的路径
    if (new_bits == 2 && !q->has_new_cov)
    {
        q->has_new_cov = 1;
        queued_with_cov++; //代表有一个queue发现了新路径
    }

    /* Mark variable paths. */
    //如果这个queue是可变路径，即var_detected为1，则计算var_bytes里被置位的tuple个数，保存到var_byte_count里，代表这些tuple具有可变的行为
    if (var_detected)
    {
        //通过count_bytes函数，计算共享内存里有多少字节被置位了
        var_byte_count = count_bytes(var_bytes);

        if (!q->var_behavior)
        {
            mark_as_variable(q); //将这个queue标记为一个variable
            queued_variable++;
        }
    }
    //恢复之前的stage值
    stage_name = old_sn;
    stage_cur = old_sc;
    stage_max = old_sm;
    //如果不是第一次运行这个queue，展示show_stats
    if (!first_run)
        show_stats();

    return fault;
}

/* Examine map coverage. Called once, for first test case. */

static void check_map_coverage(void)
{

    u32 i;
    //计数trace_bits发现的路径数，如果小于100，就直接返回
    if (count_bytes(trace_bits) < 100)
        return;

    for (i = (1 << (MAP_SIZE_POW2 - 1)); i < MAP_SIZE; i++)
        //在trace_bits的数组后半段，如果有值就直接返回
        if (trace_bits[i])
            return;

    WARNF("Recompile binary with newer version of afl to improve coverage!");
}

/* Perform dry run of all test cases to confirm that the app is working as
   expected. This is done only for the initial inputs, and only once. */
//执行input文件夹下的预先准备的所有testcase（perform_dry_run），生成初始化的queue和bitmap。这只对初始输入执行一次，所以叫：dry run
static void perform_dry_run(char **argv)
{

    struct queue_entry *q = queue; // 创建queue_entry结构体
    u32 cal_failures = 0;
    u8 *skip_crashes = getenv("AFL_SKIP_CRASHES"); //读取环境变量AFL_SKIP_CRASHES到skip_crashes,设置cal_failures为0

    while (q)
    { // 遍历队列

        u8 *use_mem;
        u8 res;
        s32 fd;

        u8 *fn = strrchr(q->fname, '/') + 1;

        ACTF("Attempting dry run with '%s'...", fn);

        fd = open(q->fname, O_RDONLY);
        if (fd < 0)
            PFATAL("Unable to open '%s'", q->fname);

        use_mem = ck_alloc_nozero(q->len);
        //读取文件内容到分配的内存中，然后关闭文件
        if (read(fd, use_mem, q->len) != q->len)
            FATAL("Short read from '%s'", q->fname); // 打开q->fname，读取到分配的内存中

        close(fd);

        res = calibrate_case(argv, q, use_mem, 0, 1); //校准testcase
        ck_free(use_mem);

        if (stop_soon)
            return;

        if (res == crash_mode || res == FAULT_NOBITS)
            SAYF(cGRA "    len = %u, map size = %u, exec speed = %llu us\n" cRST,
                 q->len, q->bitmap_size, q->exec_us); //打印
        //根据返回值res，查看哪种错误并进行判断。错误类型在本文件开头定义
        switch (res)
        {
        //什么都没有的情况
        case FAULT_NONE:
            //如果q是头结点，即第一个测试用例，则check_map_coverage，用以评估map coverage
            if (q == queue)
                check_map_coverage(); // 如果为头结点，调用check_map_coverage评估覆盖率

            if (crash_mode)
                FATAL("Test case '%s' does *NOT* crash", fn); // 抛出异常

            break;
        //超时的情况
        case FAULT_TMOUT:

            if (timeout_given)
            {
                //如果指定了-t参数，则timeout_given值为2
                /* The -t nn+ syntax in the command line sets timeout_given to '2' and
                   instructs afl-fuzz to tolerate but skip queue entries that time
                   out. */

                if (timeout_given > 1)
                {
                    WARNF("Test case results in a timeout (skipping)");
                    q->cal_failed = CAL_CHANCES;
                    cal_failures++;
                    break;
                }

                SAYF("\n" cLRD "[-] " cRST
                     "The program took more than %u ms to process one of the initial test cases.\n"
                     "    Usually, the right thing to do is to relax the -t option - or to delete it\n"
                     "    altogether and allow the fuzzer to auto-calibrate. That said, if you know\n"
                     "    what you are doing and want to simply skip the unruly test cases, append\n"
                     "    '+' at the end of the value passed to -t ('-t %u+').\n",
                     exec_tmout,
                     exec_tmout);

                FATAL("Test case '%s' results in a timeout", fn);
            }
            else
            {

                SAYF("\n" cLRD "[-] " cRST
                     "The program took more than %u ms to process one of the initial test cases.\n"
                     "    This is bad news; raising the limit with the -t option is possible, but\n"
                     "    will probably make the fuzzing process extremely slow.\n\n"

                     "    If this test case is just a fluke, the other option is to just avoid it\n"
                     "    altogether, and find one that is less of a CPU hog.\n",
                     exec_tmout);

                FATAL("Test case '%s' results in a timeout", fn);
            }
        //产生crash
        case FAULT_CRASH:

            if (crash_mode)
                break;

            if (skip_crashes)
            {
                WARNF("Test case results in a crash (skipping)");
                q->cal_failed = CAL_CHANCES;
                cal_failures++;
                break;
            }
            //如果没有指定mem_limit，则可能抛出建议增加内存的建议
            if (mem_limit)
            {

                SAYF("\n" cLRD "[-] " cRST
                     "Oops, the program crashed with one of the test cases provided. There are\n"
                     "    several possible explanations:\n\n"

                     "    - The test case causes known crashes under normal working conditions. If\n"
                     "      so, please remove it. The fuzzer should be seeded with interesting\n"
                     "      inputs - but not ones that cause an outright crash.\n\n"

                     "    - The current memory limit (%s) is too low for this program, causing\n"
                     "      it to die due to OOM when parsing valid files. To fix this, try\n"
                     "      bumping it up with the -m setting in the command line. If in doubt,\n"
                     "      try something along the lines of:\n\n"

#ifdef RLIMIT_AS
                     "      ( ulimit -Sv $[%llu << 10]; /path/to/binary [...] <testcase )\n\n"
#else
                     "      ( ulimit -Sd $[%llu << 10]; /path/to/binary [...] <testcase )\n\n"
#endif /* ^RLIMIT_AS */

                     "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
                     "      estimate the required amount of virtual memory for the binary. Also,\n"
                     "      if you are using ASAN, see %s/notes_for_asan.txt.\n\n"

#ifdef __APPLE__

                     "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
                     "      break afl-fuzz performance optimizations when running platform-specific\n"
                     "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

                     "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
                     "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
                     DMS(mem_limit << 20), mem_limit - 1, doc_path);
            }
            else
            {

                SAYF("\n" cLRD "[-] " cRST
                     "Oops, the program crashed with one of the test cases provided. There are\n"
                     "    several possible explanations:\n\n"

                     "    - The test case causes known crashes under normal working conditions. If\n"
                     "      so, please remove it. The fuzzer should be seeded with interesting\n"
                     "      inputs - but not ones that cause an outright crash.\n\n"

#ifdef __APPLE__

                     "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
                     "      break afl-fuzz performance optimizations when running platform-specific\n"
                     "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

                     "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
                     "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");
            }

            FATAL("Test case '%s' results in a crash", fn);

        case FAULT_ERROR:
            //抛出异常
            FATAL("Unable to execute target application ('%s')", argv[0]);

        case FAULT_NOINST:
            //这个样例运行没有出现任何路径信息，抛出异常
            FATAL("No instrumentation detected");

        case FAULT_NOBITS:
            //如果这个样例有出现路径信息，但是没有任何新路径，抛出警告，并认为这是无用路径
            useless_at_start++;

            if (!in_bitmap && !shuffle_queue)
                WARNF("No new instrumentation output, test case may be useless.");

            break;
        }
        //如果这个样例q的var_behavior为真，则代表它多次运行，同样的输入条件下，却出现不同的覆盖信息
        if (q->var_behavior)
            WARNF("Instrumentation output varies across runs."); //代表这个样例的路径输出可变

        q = q->next; // 读取下一个queue
    }

    if (cal_failures)
    {

        if (cal_failures == queued_paths)
            FATAL("All test cases time out%s, giving up!",
                  skip_crashes ? " or crash" : "");

        WARNF("Skipped %u test cases (%0.02f%%) due to timeouts%s.", cal_failures,
              ((double)cal_failures) * 100 / queued_paths,
              skip_crashes ? " or crashes" : "");

        if (cal_failures * 5 > queued_paths)
            WARNF(cLRD "High percentage of rejected test cases, check settings!");
    }

    OKF("All test cases processed.");
}

/* Helper function: link() if possible, copy otherwise. */

static void link_or_copy(u8 *old_path, u8 *new_path)
{

    s32 i = link(old_path, new_path);
    s32 sfd, dfd;
    u8 *tmp;

    if (!i)
        return;

    sfd = open(old_path, O_RDONLY);
    if (sfd < 0)
        PFATAL("Unable to open '%s'", old_path);

    dfd = open(new_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (dfd < 0)
        PFATAL("Unable to create '%s'", new_path);

    tmp = ck_alloc(64 * 1024);

    while ((i = read(sfd, tmp, 64 * 1024)) > 0)
        ck_write(dfd, tmp, i, new_path);

    if (i < 0)
        PFATAL("read() failed");

    ck_free(tmp);
    close(sfd);
    close(dfd);
}

static void nuke_resume_dir(void);

/* Create hard links for input test cases in the output directory, choosing
   good names and pivoting accordingly. */
//在输出目录中为输入测试用例创建硬链接，选择好名称并相应地旋转。
//使用函数link_or_copy重新命名并且拷贝；使用函数mark_as_det_done为已经经过确定性变异（deterministic）阶段
//的testcase文件放入deterministic_done文件夹。这样经过deterministic的testcase就不用浪费时间进行重复
static void pivot_inputs(void)
{

    struct queue_entry *q = queue;
    u32 id = 0;

    ACTF("Creating hard links for all input files...");
    //依次遍历queue里的queue_entry
    while (q)
    {
        //在q->fname里找到最后一个’/‘所在的位置，如果找不到，则rsl = q->fname,否则rsl指向’/‘后的第一个字符,其实也就是最后一个/后面的字符串
        u8 *nfn, *rsl = strrchr(q->fname, '/');
        u32 orig_id;

        if (!rsl)
            rsl = q->fname;
        else
            rsl++;

            /* If the original file name conforms to the syntax and the recorded
               ID matches the one we'd assign, just use the original file name.
               This is valuable for resuming fuzzing runs. */

#ifndef SIMPLE_FILES
#define CASE_PREFIX "id:"
#else
#define CASE_PREFIX "id_"
#endif /* ^!SIMPLE_FILES */
        //将rsl的前三个字节和id进行比较
        if (!strncmp(rsl, CASE_PREFIX, 3) &&
            sscanf(rsl + 3, "%06u", &orig_id) == 1 && orig_id == id)
        {

            u8 *src_str;
            u32 src_id;

            resuming_fuzz = 1;
            nfn = alloc_printf("%s/queue/%s", out_dir, rsl);

            /* Since we're at it, let's also try to find parent and figure out the
               appropriate depth for this entry. */

            src_str = strchr(rsl + 3, ':');

            if (src_str && sscanf(src_str + 1, "%06u", &src_id) == 1)
            {

                struct queue_entry *s = queue;
                while (src_id-- && s)
                    s = s->next;
                if (s)
                    q->depth = s->depth + 1;

                if (max_depth < q->depth)
                    max_depth = q->depth;
            }
        }
        else
        {

            /* No dice - invent a new name, capturing the original one as a
               substring. */

#ifndef SIMPLE_FILES
            //在rsl里寻找,orig:子串，如果找到了，将use_name指向该子串的冒号后的名字；如果没找到，就另use_name = rsl
            u8 *use_name = strstr(rsl, ",orig:");

            if (use_name)
                use_name += 6;
            else
                use_name = rsl;
            nfn = alloc_printf("%s/queue/id:%06u,orig:%s", out_dir, id, use_name);

#else

            nfn = alloc_printf("%s/queue/id_%06u", out_dir, id);

#endif /* ^!SIMPLE_FILES */
        }

        /* Pivot to the new queue entry. */
        //修改q的fname指向这个硬连接
        link_or_copy(q->fname, nfn);
        ck_free(q->fname);
        q->fname = nfn;

        /* Make sure that the passed_det value carries over, too. */
        // mark_as_det_done：简单的说就是打开out_dir/queue/.state/deterministic_done/use_name这个文件，如果不存在就创建这个文件，然后设置q的passed_det为1
        if (q->passed_det)
            mark_as_det_done(q);

        q = q->next;
        id++;
    }

    if (in_place_resume)
        nuke_resume_dir();
}

#ifndef SIMPLE_FILES

/* Construct a file name for a new test case, capturing the operation
   that led to its discovery. Uses a static buffer. */

static u8 *describe_op(u8 hnb)
{

    static u8 ret[256];

    if (syncing_party)
    {

        sprintf(ret, "sync:%s,src:%06u", syncing_party, syncing_case);
    }
    else
    {

        sprintf(ret, "src:%06u", current_entry);

        if (splicing_with >= 0)
            sprintf(ret + strlen(ret), "+%06u", splicing_with);

        sprintf(ret + strlen(ret), ",op:%s", stage_short);

        if (stage_cur_byte >= 0)
        {

            sprintf(ret + strlen(ret), ",pos:%u", stage_cur_byte);

            if (stage_val_type != STAGE_VAL_NONE)
                sprintf(ret + strlen(ret), ",val:%s%+d",
                        (stage_val_type == STAGE_VAL_BE) ? "be:" : "",
                        stage_cur_val);
        }
        else
            sprintf(ret + strlen(ret), ",rep:%u", stage_cur_val);
    }

    if (hnb == 2)
        strcat(ret, ",+cov");

    return ret;
}

#endif /* !SIMPLE_FILES */

/* Write a message accompanying the crash directory :-) */

static void write_crash_readme(void)
{

    u8 *fn = alloc_printf("%s/crashes/README.txt", out_dir);
    s32 fd;
    FILE *f;

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    ck_free(fn);

    /* Do not die on errors here - that would be impolite. */

    if (fd < 0)
        return;

    f = fdopen(fd, "w");

    if (!f)
    {
        close(fd);
        return;
    }

    fprintf(f, "Command line used to find this crash:\n\n"

               "%s\n\n"

               "If you can't reproduce a bug outside of afl-fuzz, be sure to set the same\n"
               "memory limit. The limit used for this fuzzing session was %s.\n\n"

               "Need a tool to minimize test cases before investigating the crashes or sending\n"
               "them to a vendor? Check out the afl-tmin that comes with the fuzzer!\n\n"

               "Found any cool bugs in open-source tools using afl-fuzz? If yes, please drop\n"
               "me a mail at <lcamtuf@coredump.cx> once the issues are fixed - I'd love to\n"
               "add your finds to the gallery at:\n\n"

               "  http://lcamtuf.coredump.cx/afl/\n\n"

               "Thanks :-)\n",

            orig_cmdline, DMS(mem_limit << 20)); /* ignore errors */

    fclose(f);
}

/* Check if the result of an execve() during routine fuzzing is interesting,
   save or queue the input test case for further analysis if so. Returns 1 if
   entry is saved, 0 otherwise. */
//判断是否保存这个测试用例;检查这个case的执行结果是否是interesting的，决定是否保存或跳过。如果保存了这个case，则返回1，否则返回0
//是否新路径 && 是否新类型（之前的分类）
//评分：更快的时间、更小的存储大小
static u8 save_if_interesting(char **argv, void *mem, u32 len, u8 fault)
{

    u8 *fn = "";
    u8 hnb;
    s32 fd;
    u8 keeping = 0, res;

    if (fault == crash_mode)
    {

        /* Keep only if there are new bits in the map, add to queue for
           future fuzzing, etc. */
        //校验哈希
        if (!(hnb = has_new_bits(virgin_bits)))
        { // has_new_bits,如果没有新的path发现或者path命中次数相同，就直接返回0
            if (crash_mode)
                total_crashes++;
            return 0;
        }

#ifndef SIMPLE_FILES
        //否则，将case保存到fn = alloc_printf("%s/queue/id:%06u,%s", out_dir, queued_paths, describe_op(hnb))文件里
        fn = alloc_printf("%s/queue/id:%06u,%s", out_dir, queued_paths,
                          describe_op(hnb));

#else

        fn = alloc_printf("%s/queue/id_%06u", out_dir, queued_paths);

#endif /* ^!SIMPLE_FILES */
        //添加到队列
        add_to_queue(fn, len, 0);
        //如果hnb的值是2，代表发现了新path，设置刚刚加入到队列里的queue的has_new_cov字段为1，即queue_top->has_new_cov = 1，然后queued_with_cov计数器加一
        if (hnb == 2)
        {
            queue_top->has_new_cov = 1;
            queued_with_cov++;
        }
        //保存hash到其exec_cksum
        queue_top->exec_cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

        /* Try to calibrate inline; this also calls update_bitmap_score() when
           successful. */
        //校准种子，同时calibrate_case函数里的update_bitmap_score()重新排列toprate[]种子;评估这个queue
        res = calibrate_case(argv, queue_top, mem, queue_cycle - 1, 0);

        if (res == FAULT_ERROR)
            FATAL("Unable to execute target application");

        fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0)
            PFATAL("Unable to create '%s'", fn);
        ck_write(fd, mem, len, fn);
        close(fd);

        keeping = 1;
    }
    //根据fault结果进入不同的分支
    switch (fault)
    {

    case FAULT_TMOUT:

        /* Timeouts are not very interesting, but we're still obliged to keep
           a handful of samples. We use the presence of new bits in the
           hang-specific bitmap as a signal of uniqueness. In "dumb" mode, we
           just keep everything. */

        total_tmouts++;
        //如果unique_hangs的个数超过能保存的最大数量KEEP_UNIQUE_HANG，就直接返回keeping的值
        if (unique_hangs >= KEEP_UNIQUE_HANG)
            return keeping;
        //如果不是dumb mode，就simplify_trace((u64 *) trace_bits)进行规整
        if (!dumb_mode)
        {

#ifdef __x86_64__
            simplify_trace((u64 *)trace_bits);
#else
            simplify_trace((u32 *)trace_bits);
#endif /* ^__x86_64__ */
            //如果没有发现新的超时路径，就直接返回keeping
            if (!has_new_bits(virgin_tmout))
                return keeping;
        }
        //否则，代表发现了新的超时路径，unique_tmouts计数器加一
        unique_tmouts++;

        /* Before saving, we make sure that it's a genuine hang by re-running
           the target with a more generous timeout (unless the default timeout
           is already generous). */
        //如果hang_tmout大于exec_tmout，则以hang_tmout为timeout，重新执行一次runt_target
        if (exec_tmout < hang_tmout)
        {

            u8 new_fault;
            write_to_testcase(mem, len);
            new_fault = run_target(argv, hang_tmout);

            /* A corner case that one user reported bumping into: increasing the
               timeout actually uncovers a crash. Make sure we don't discard it if
               so. */
            //如果结果为FAULT_CRASH，就跳转到keep_as_crash
            if (!stop_soon && new_fault == FAULT_CRASH)
                goto keep_as_crash;
            //如果结果不是FAULT_TMOUT，就返回keeping，否则就使unique_hangs计数器加一，然后更新last_hang_time的值，并保存到alloc_printf("%s/hangs/id:%06llu,%s", out_dir, unique_hangs, describe_op(0))文件
            if (stop_soon || new_fault != FAULT_TMOUT)
                return keeping;
        }

#ifndef SIMPLE_FILES

        fn = alloc_printf("%s/hangs/id:%06llu,%s", out_dir,
                          unique_hangs, describe_op(0));

#else

        fn = alloc_printf("%s/hangs/id_%06llu", out_dir,
                          unique_hangs);

#endif /* ^!SIMPLE_FILES */

        unique_hangs++;

        last_hang_time = get_cur_time();

        break;

    case FAULT_CRASH:

    keep_as_crash:

        /* This is handled in a manner roughly similar to timeouts,
           except for slightly different limits and no need to re-run test
           cases. */

        total_crashes++;
        //如果unique_crashes大于能保存的最大数量KEEP_UNIQUE_CRASH即5000，就直接返回keeping的值
        if (unique_crashes >= KEEP_UNIQUE_CRASH)
            return keeping;
        //如果不是dumb mode，就simplify_trace((u64 *) trace_bits)进行规整
        if (!dumb_mode)
        {

#ifdef __x86_64__
            simplify_trace((u64 *)trace_bits);
#else
            simplify_trace((u32 *)trace_bits);
#endif /* ^__x86_64__ */
            //如果没有发现新的crash路径，就直接返回keeping
            if (!has_new_bits(virgin_crash))
                return keeping;
        }
        //否则，代表发现了新的crash路径，unique_crashes计数器加一，并将结果保存到alloc_printf("%s/crashes/id:%06llu,sig:%02u,%s", out_dir,unique_crashes, kill_signal, describe_op(0))文件
        if (!unique_crashes)
            write_crash_readme();

#ifndef SIMPLE_FILES

        fn = alloc_printf("%s/crashes/id:%06llu,sig:%02u,%s", out_dir,
                          unique_crashes, kill_signal, describe_op(0));

#else

        fn = alloc_printf("%s/crashes/id_%06llu_%02u", out_dir, unique_crashes,
                          kill_signal);

#endif /* ^!SIMPLE_FILES */

        unique_crashes++;

        last_crash_time = get_cur_time();
        last_crash_execs = total_execs;

        break;

    case FAULT_ERROR:
        FATAL("Unable to execute target application");

    default:
        return keeping;
    }

    /* If we're here, we apparently want to save the crash or hang
       test case, too. */

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        PFATAL("Unable to create '%s'", fn);
    ck_write(fd, mem, len, fn);
    close(fd);

    ck_free(fn);

    return keeping;
}

/* When resuming, try to find the queue position to start from. This makes sense
   only when resuming, and when we can find the original fuzzer_stats. */
// resume时,请尝试查找要从其开始的队列位置,这仅在resume时以及当我们可以找到原始的fuzzer_stats时才有意义
static u32 find_start_position(void)
{

    static u8 tmp[4096]; /* Ought to be enough for anybody. */

    u8 *fn, *off;
    s32 fd, i;
    u32 ret;
    //如果不是resuming_fuzz，就直接返回
    if (!resuming_fuzz)
        return 0;
    //如果是in_place_resume,就打开out_dir/fuzzer_stats文件，否则打开in_dir/../fuzzer_stats文件
    if (in_place_resume)
        fn = alloc_printf("%s/fuzzer_stats", out_dir);
    else
        fn = alloc_printf("%s/../fuzzer_stats", in_dir);

    fd = open(fn, O_RDONLY);
    ck_free(fn);

    if (fd < 0)
        return 0;
    //读这个文件的内容到tmp[4096]中，找到cur_path，并设置为ret的值，如果大于queued_paths就设置ret为0，返回ret
    i = read(fd, tmp, sizeof(tmp) - 1);
    (void)i; /* Ignore errors */
    close(fd);

    off = strstr(tmp, "cur_path          : ");
    if (!off)
        return 0;

    ret = atoi(off + 20);
    if (ret >= queued_paths)
        ret = 0;
    return ret;
}

/* The same, but for timeouts. The idea is that when resuming sessions without
   -t given, we don't want to keep auto-scaling the timeout over and over
   again to prevent it from growing due to random flukes. */
//如果有-t的设置了自己的超时，那么会触发这个函数
//变量 timeout_given 没有被设置时，会调用到该函数。该函数主要是在没有指定 -t 选项进行 resuming session 时，避免一次次地自动调整超时时间
static void find_timeout(void)
{

    static u8 tmp[4096]; /* Ought to be enough for anybody. */

    u8 *fn, *off;
    s32 fd, i;
    u32 ret;

    if (!resuming_fuzz)
        return;

    if (in_place_resume)
        fn = alloc_printf("%s/fuzzer_stats", out_dir);
    else
        fn = alloc_printf("%s/../fuzzer_stats", in_dir);

    fd = open(fn, O_RDONLY);
    ck_free(fn);

    if (fd < 0)
        return;

    i = read(fd, tmp, sizeof(tmp) - 1);
    (void)i; /* Ignore errors */
    close(fd);

    off = strstr(tmp, "exec_timeout   : ");
    if (!off)
        return;

    ret = atoi(off + 17);
    if (ret <= 4)
        return;

    exec_tmout = ret;
    timeout_given = 3;
}

/* Update stats file for unattended monitoring. */
//更新统计信息文件以进行无人值守的监视
static void write_stats_file(double bitmap_cvg, double stability, double eps)
{

    static double last_bcvg, last_stab, last_eps;
    //创建文件out_dir/fuzzer_stats
    u8 *fn = alloc_printf("%s/fuzzer_stats", out_dir);
    s32 fd;
    FILE *f;

    fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd < 0)
        PFATAL("Unable to create '%s'", fn);

    ck_free(fn);
    //写入统计信息
    f = fdopen(fd, "w");

    if (!f)
        PFATAL("fdopen() failed");

    /* Keep last values in case we're called from another context
       where exec/sec stats and such are not readily available. */

    if (!bitmap_cvg && !stability && !eps)
    {
        bitmap_cvg = last_bcvg;
        stability = last_stab;
        eps = last_eps;
    }
    else
    {
        last_bcvg = bitmap_cvg;
        last_stab = stability;
        last_eps = eps;
    }

    fprintf(f, "start_time        : %llu\n"                                      // fuzz运行的开始时间，start_time / 1000
               "last_update       : %llu\n"                                      //当前时间
               "fuzzer_pid        : %u\n"                                        //获取当前pid
               "cycles_done       : %llu\n"                                      // queue_cycle在queue_cur为空，即执行到当前队列尾的时候才增加1，所以这代表queue队列被完全变异一次的次数
               "execs_done        : %llu\n"                                      // total_execs，target的总的执行次数，每次run_target的时候会增加1
               "execs_per_sec     : %0.02f\n"                                    //每秒执行的次数
               "paths_total       : %u\n"                                        // queued_paths在每次add_to_queue的时候会增加1，代表queue里的样例总数
               "paths_favored     : %u\n"                                        // queued_favored，有价值的路径总数
               "paths_found       : %u\n"                                        // queued_discovered在每次common_fuzz_stuff去执行一次fuzz时，发现新的interesting case的时候会增加1，代表在fuzz运行期间发现的新queue entry
               "paths_imported    : %u\n"                                        // queued_imported是master-slave模式下，如果sync过来的case是interesting的，就增加1
               "max_depth         : %u\n"                                        //最大路径深度
               "cur_path          : %u\n" /* Must match find_start_position() */ // current_entry一般情况下代表的是正在执行的queue entry的整数ID,queue首节点的ID是0
               "pending_favs      : %u\n"                                        // pending_favored 等待fuzz的favored paths数
               "pending_total     : %u\n"                                        // pending_not_fuzzed 在queue中等待fuzz的case数
               "variable_paths    : %u\n"                                        // queued_variable在calibrate_case去评估一个新的test case的时候，如果发现这个case的路径是可变的，则将这个计数器加一，代表发现了一个可变case
               "stability         : %0.02f%%\n"
               "bitmap_cvg        : %0.02f%%\n"
               "unique_crashes    : %llu\n" // unique_crashes这是在save_if_interesting时，如果fault是FAULT_CRASH，就将unique_crashes计数器加一
               "unique_hangs      : %llu\n" // unique_hangs这是在save_if_interesting时，如果fault是FAULT_TMOUT，且exec_tmout小于hang_tmout，就以hang_tmout为超时时间再执行一次，如果还超时，就让hang计数器加一
               "last_path         : %llu\n" //在add_to_queue里将一个新case加入queue时，就设置一次last_path_time为当前时间，last_path_time / 1000
               "last_crash        : %llu\n" //同上，在unique_crashes加一的时候，last_crash也更新时间，last_crash_time / 1000
               "last_hang         : %llu\n" //同上，在unique_hangs加一的时候，last_hang也更新时间，last_hang_time / 1000
               "execs_since_crash : %llu\n" // total_execs - last_crash_execs,这里last_crash_execs是在上一次crash的时候的总计执行了多少次
               "exec_timeout      : %u\n"   //配置好的超时时间，有三种可能的配置方式，见show_init_stats()
               "afl_banner        : %s\n"
               "afl_version       : " VERSION "\n"
               "target_mode       : %s%s%s%s%s%s%s\n"
               "command_line      : %s\n",
            start_time / 1000, get_cur_time() / 1000, getpid(),
            queue_cycle ? (queue_cycle - 1) : 0, total_execs, eps,
            queued_paths, queued_favored, queued_discovered, queued_imported,
            max_depth, current_entry, pending_favored, pending_not_fuzzed,
            queued_variable, stability, bitmap_cvg, unique_crashes,
            unique_hangs, last_path_time / 1000, last_crash_time / 1000,
            last_hang_time / 1000, total_execs - last_crash_execs,
            exec_tmout, use_banner,
            qemu_mode ? "qemu " : "", dumb_mode ? " dumb " : "",
            no_forkserver ? "no_forksrv " : "", crash_mode ? "crash " : "",
            persistent_mode ? "persistent " : "", deferred_mode ? "deferred " : "",
            (qemu_mode || dumb_mode || no_forkserver || crash_mode ||
             persistent_mode || deferred_mode)
                ? ""
                : "default",
            orig_cmdline);
    /* ignore errors */

    fclose(f);
}

/* Update the plot file if there is a reason to. */

static void maybe_update_plot_file(double bitmap_cvg, double eps)
{

    static u32 prev_qp, prev_pf, prev_pnf, prev_ce, prev_md;
    static u64 prev_qc, prev_uc, prev_uh;

    if (prev_qp == queued_paths && prev_pf == pending_favored &&
        prev_pnf == pending_not_fuzzed && prev_ce == current_entry &&
        prev_qc == queue_cycle && prev_uc == unique_crashes &&
        prev_uh == unique_hangs && prev_md == max_depth)
        return;

    prev_qp = queued_paths;
    prev_pf = pending_favored;
    prev_pnf = pending_not_fuzzed;
    prev_ce = current_entry;
    prev_qc = queue_cycle;
    prev_uc = unique_crashes;
    prev_uh = unique_hangs;
    prev_md = max_depth;

    /* Fields in the file:

       unix_time, cycles_done, cur_path, paths_total, paths_not_fuzzed,
       favored_not_fuzzed, unique_crashes, unique_hangs, max_depth,
       execs_per_sec */

    fprintf(plot_file,
            "%llu, %llu, %u, %u, %u, %u, %0.02f%%, %llu, %llu, %u, %0.02f\n",
            get_cur_time() / 1000, queue_cycle - 1, current_entry, queued_paths,
            pending_not_fuzzed, pending_favored, bitmap_cvg, unique_crashes,
            unique_hangs, max_depth, eps); /* ignore errors */

    fflush(plot_file);
}

/* A helper function for maybe_delete_out_dir(), deleting all prefixed
   files in a directory. */

static u8 delete_files(u8 *path, u8 *prefix)
{

    DIR *d;
    struct dirent *d_ent;

    d = opendir(path);

    if (!d)
        return 0;

    while ((d_ent = readdir(d)))
    {

        if (d_ent->d_name[0] != '.' && (!prefix ||
                                        !strncmp(d_ent->d_name, prefix, strlen(prefix))))
        {

            u8 *fname = alloc_printf("%s/%s", path, d_ent->d_name);
            if (unlink(fname))
                PFATAL("Unable to delete '%s'", fname);
            ck_free(fname);
        }
    }

    closedir(d);

    return !!rmdir(path);
}

/* Get the number of runnable processes, with some simple smoothing. */

static double get_runnable_processes(void)
{

    static double res;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)

    /* I don't see any portable sysctl or so that would quickly give us the
       number of runnable processes; the 1-minute load average can be a
       semi-decent approximation, though. */

    if (getloadavg(&res, 1) != 1)
        return 0;

#else

    /* On Linux, /proc/stat is probably the best way; load averages are
       computed in funny ways and sometimes don't reflect extremely short-lived
       processes well. */

    FILE *f = fopen("/proc/stat", "r");
    u8 tmp[1024];
    u32 val = 0;

    if (!f)
        return 0;

    while (fgets(tmp, sizeof(tmp), f))
    {

        if (!strncmp(tmp, "procs_running ", 14) ||
            !strncmp(tmp, "procs_blocked ", 14))
            val += atoi(tmp + 14);
    }

    fclose(f);

    if (!res)
    {

        res = val;
    }
    else
    {

        res = res * (1.0 - 1.0 / AVG_SMOOTHING) +
              ((double)val) * (1.0 / AVG_SMOOTHING);
    }

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

    return res;
}

/* Delete the temporary directory used for in-place session resume. */

static void nuke_resume_dir(void)
{

    u8 *fn;
    //删除out_dir/_resume/.state/deterministic_done文件夹下所有id:前缀的文件
    fn = alloc_printf("%s/_resume/.state/deterministic_done", out_dir);
    if (delete_files(fn, CASE_PREFIX))
        goto dir_cleanup_failed;
    ck_free(fn);
    //删除out_dir/_resume/.state/auto_extras文件夹下所有auto_前缀的文件
    fn = alloc_printf("%s/_resume/.state/auto_extras", out_dir);
    if (delete_files(fn, "auto_"))
        goto dir_cleanup_failed;
    ck_free(fn);
    //删除out_dir/_resume/.state/redundant_edges文件夹下所有id:前缀的文件
    fn = alloc_printf("%s/_resume/.state/redundant_edges", out_dir);
    if (delete_files(fn, CASE_PREFIX))
        goto dir_cleanup_failed;
    ck_free(fn);
    //删除out_dir/_resume/.state/variable_behavior文件夹下所有id:前缀的文件
    fn = alloc_printf("%s/_resume/.state/variable_behavior", out_dir);
    if (delete_files(fn, CASE_PREFIX))
        goto dir_cleanup_failed;
    ck_free(fn);
    //删除文件夹out_dir/_resume/.state
    fn = alloc_printf("%s/_resume/.state", out_dir);
    if (rmdir(fn) && errno != ENOENT)
        goto dir_cleanup_failed;
    ck_free(fn);
    //删除out_dir/_resume文件夹下所有id:前缀的文件
    fn = alloc_printf("%s/_resume", out_dir);
    if (delete_files(fn, CASE_PREFIX))
        goto dir_cleanup_failed;
    ck_free(fn);

    return;

dir_cleanup_failed:

    FATAL("_resume directory cleanup failed");
}

/* Delete fuzzer output directory if we recognize it as ours, if the fuzzer
   is not currently running, and if the last run time isn't too great. */

static void maybe_delete_out_dir(void)
{

    FILE *f;
    u8 *fn = alloc_printf("%s/fuzzer_stats", out_dir);

    /* See if the output directory is locked. If yes, bail out. If not,
       create a lock that will persist for the lifetime of the process
       (this requires leaving the descriptor open).*/

    out_dir_fd = open(out_dir, O_RDONLY);
    if (out_dir_fd < 0)
        PFATAL("Unable to open '%s'", out_dir);

#ifndef __sun

    if (flock(out_dir_fd, LOCK_EX | LOCK_NB) && errno == EWOULDBLOCK)
    {

        SAYF("\n" cLRD "[-] " cRST
             "Looks like the job output directory is being actively used by another\n"
             "    instance of afl-fuzz. You will need to choose a different %s\n"
             "    or stop the other process first.\n",
             sync_id ? "fuzzer ID" : "output location");

        FATAL("Directory '%s' is in use", out_dir);
    }

#endif /* !__sun */

    f = fopen(fn, "r");

    if (f)
    {

        u64 start_time, last_update;

        if (fscanf(f, "start_time     : %llu\n"
                      "last_update    : %llu\n",
                   &start_time, &last_update) != 2)
            FATAL("Malformed data in '%s'", fn);

        fclose(f);

        /* Let's see how much work is at stake. */

        if (!in_place_resume && last_update - start_time > OUTPUT_GRACE * 60)
        {

            SAYF("\n" cLRD "[-] " cRST
                 "The job output directory already exists and contains the results of more\n"
                 "    than %u minutes worth of fuzzing. To avoid data loss, afl-fuzz will *NOT*\n"
                 "    automatically delete this data for you.\n\n"

                 "    If you wish to start a new session, remove or rename the directory manually,\n"
                 "    or specify a different output location for this job. To resume the old\n"
                 "    session, put '-' as the input directory in the command line ('-i -') and\n"
                 "    try again.\n",
                 OUTPUT_GRACE);

            /*  当发现 valuable out info 的时候，对文件夹进行暂存操作，让程序继续进行  (发现文件夹有价值，又不舍得删，就备份一下，跟cmin思路相同)*/
            if ((old_out_dir = alloc_printf("%s_old", out_dir)))
            {                                 //如果输入路径合适，新的备份路径合适，重命名，并新建空文件夹
                rename(out_dir, old_out_dir); // rename操作，重命名文件夹
                mkdir(out_dir, 0700);         // mkdir新建文件夹，用的是旧的名字
                OKF("Success to create old_file_dir and move valuable files in it.");
            }
            else
            { //如果不合适，继续之前的FATAL操作，停止程序   (如果最开始的拼接失败，可能是out_dir本身就有问题，停止程序)
                OKF("Fail to move file!!!");
                FATAL("At-risk data found in '%s'", out_dir);
            }
        }
        // FATAL("At-risk data found in '%s'", out_dir);
    }

    ck_free(fn);

    /* The idea for in-place resume is pretty simple: we temporarily move the old
       queue/ to a new location that gets deleted once import to the new queue/
       is finished. If _resume/ already exists, the current queue/ may be
       incomplete due to an earlier abort, so we want to use the old _resume/
       dir instead, and we let rename() fail silently. */

    if (in_place_resume)
    {

        u8 *orig_q = alloc_printf("%s/queue", out_dir);

        in_dir = alloc_printf("%s/_resume", out_dir);

        rename(orig_q, in_dir); /* Ignore errors */

        OKF("Output directory exists, will attempt session resume.");

        ck_free(orig_q);
    }
    else
    {

        OKF("Output directory exists but deemed OK to reuse.");
    }

    ACTF("Deleting old session data...");

    /* Okay, let's get the ball rolling! First, we need to get rid of the entries
       in <out_dir>/.synced/.../id:*, if any are present. */

    if (!in_place_resume)
    {

        fn = alloc_printf("%s/.synced", out_dir);
        if (delete_files(fn, NULL))
            goto dir_cleanup_failed;
        ck_free(fn);
    }

    /* Next, we need to clean up <out_dir>/queue/.state/ subdirectories: */

    fn = alloc_printf("%s/queue/.state/deterministic_done", out_dir);
    if (delete_files(fn, CASE_PREFIX))
        goto dir_cleanup_failed;
    ck_free(fn);

    fn = alloc_printf("%s/queue/.state/auto_extras", out_dir);
    if (delete_files(fn, "auto_"))
        goto dir_cleanup_failed;
    ck_free(fn);

    fn = alloc_printf("%s/queue/.state/redundant_edges", out_dir);
    if (delete_files(fn, CASE_PREFIX))
        goto dir_cleanup_failed;
    ck_free(fn);

    fn = alloc_printf("%s/queue/.state/variable_behavior", out_dir);
    if (delete_files(fn, CASE_PREFIX))
        goto dir_cleanup_failed;
    ck_free(fn);

    /* Then, get rid of the .state subdirectory itself (should be empty by now)
       and everything matching <out_dir>/queue/id:*. */

    fn = alloc_printf("%s/queue/.state", out_dir);
    if (rmdir(fn) && errno != ENOENT)
        goto dir_cleanup_failed;
    ck_free(fn);

    fn = alloc_printf("%s/queue", out_dir);
    if (delete_files(fn, CASE_PREFIX))
        goto dir_cleanup_failed;
    ck_free(fn);

    /* All right, let's do <out_dir>/crashes/id:* and <out_dir>/hangs/id:*. */

    if (!in_place_resume)
    {

        fn = alloc_printf("%s/crashes/README.txt", out_dir);
        unlink(fn); /* Ignore errors */
        ck_free(fn);
    }

    fn = alloc_printf("%s/crashes", out_dir);

    /* Make backup of the crashes directory if it's not empty and if we're
       doing in-place resume. */

    if (in_place_resume && rmdir(fn))
    {

        time_t cur_t = time(0);
        struct tm *t = localtime(&cur_t);

#ifndef SIMPLE_FILES

        u8 *nfn = alloc_printf("%s.%04u-%02u-%02u-%02u:%02u:%02u", fn,
                               t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                               t->tm_hour, t->tm_min, t->tm_sec);

#else

        u8 *nfn = alloc_printf("%s_%04u%02u%02u%02u%02u%02u", fn,
                               t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                               t->tm_hour, t->tm_min, t->tm_sec);

#endif /* ^!SIMPLE_FILES */

        rename(fn, nfn); /* Ignore errors. */
        ck_free(nfn);
    }

    if (delete_files(fn, CASE_PREFIX))
        goto dir_cleanup_failed;
    ck_free(fn);

    fn = alloc_printf("%s/hangs", out_dir);

    /* Backup hangs, too. */

    if (in_place_resume && rmdir(fn))
    {

        time_t cur_t = time(0);
        struct tm *t = localtime(&cur_t);

#ifndef SIMPLE_FILES

        u8 *nfn = alloc_printf("%s.%04u-%02u-%02u-%02u:%02u:%02u", fn,
                               t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                               t->tm_hour, t->tm_min, t->tm_sec);

#else

        u8 *nfn = alloc_printf("%s_%04u%02u%02u%02u%02u%02u", fn,
                               t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                               t->tm_hour, t->tm_min, t->tm_sec);

#endif /* ^!SIMPLE_FILES */

        rename(fn, nfn); /* Ignore errors. */
        ck_free(nfn);
    }

    if (delete_files(fn, CASE_PREFIX))
        goto dir_cleanup_failed;
    ck_free(fn);

    /* And now, for some finishing touches. */

    fn = alloc_printf("%s/.cur_input", out_dir);
    if (unlink(fn) && errno != ENOENT)
        goto dir_cleanup_failed;
    ck_free(fn);

    fn = alloc_printf("%s/fuzz_bitmap", out_dir);
    if (unlink(fn) && errno != ENOENT)
        goto dir_cleanup_failed;
    ck_free(fn);

    if (!in_place_resume)
    {
        fn = alloc_printf("%s/fuzzer_stats", out_dir);
        if (unlink(fn) && errno != ENOENT)
            goto dir_cleanup_failed;
        ck_free(fn);
    }

    fn = alloc_printf("%s/plot_data", out_dir);
    if (unlink(fn) && errno != ENOENT)
        goto dir_cleanup_failed;
    ck_free(fn);

    OKF("Output dir cleanup successful.");

    /* Wow... is that all? If yes, celebrate! */

    return;

dir_cleanup_failed:

    SAYF("\n" cLRD "[-] " cRST
         "Whoops, the fuzzer tried to reuse your output directory, but bumped into\n"
         "    some files that shouldn't be there or that couldn't be removed - so it\n"
         "    decided to abort! This happened while processing this path:\n\n"

         "    %s\n\n"
         "    Please examine and manually delete the files, or specify a different\n"
         "    output location for the tool.\n",
         fn);

    FATAL("Output directory cleanup failed");
}

static void check_term_size(void);

/* A spiffy retro stats screen! This is called every stats_update_freq
   execve() calls, plus in several other circumstances. */

static void show_stats(void)
{

    static u64 last_stats_ms, last_plot_ms, last_ms, last_execs;
    static double avg_exec;
    double t_byte_ratio, stab_ratio;

    u64 cur_ms;
    u32 t_bytes, t_bits;

    u32 banner_len, banner_pad;
    u8 tmp[256];

    cur_ms = get_cur_time();

    /* If not enough time has passed since last UI update, bail out. */

    if (cur_ms - last_ms < 1000 / UI_TARGET_HZ)
        return;

    /* Check if we're past the 10 minute mark. */

    if (cur_ms - start_time > 10 * 60 * 1000)
        run_over10m = 1;

    /* Calculate smoothed exec speed stats. */

    if (!last_execs)
    {

        avg_exec = ((double)total_execs) * 1000 / (cur_ms - start_time);
    }
    else
    {

        double cur_avg = ((double)(total_execs - last_execs)) * 1000 /
                         (cur_ms - last_ms);

        /* If there is a dramatic (5x+) jump in speed, reset the indicator
           more quickly. */

        if (cur_avg * 5 < avg_exec || cur_avg / 5 > avg_exec)
            avg_exec = cur_avg;

        avg_exec = avg_exec * (1.0 - 1.0 / AVG_SMOOTHING) +
                   cur_avg * (1.0 / AVG_SMOOTHING);
    }

    last_ms = cur_ms;
    last_execs = total_execs;

    /* Tell the callers when to contact us (as measured in execs). */

    stats_update_freq = avg_exec / (UI_TARGET_HZ * 10);
    if (!stats_update_freq)
        stats_update_freq = 1;

    /* Do some bitmap stats. */

    t_bytes = count_non_255_bytes(virgin_bits);
    t_byte_ratio = ((double)t_bytes * 100) / MAP_SIZE;

    if (t_bytes)
        stab_ratio = 100 - ((double)var_byte_count) * 100 / t_bytes;
    else
        stab_ratio = 100;

    /* Roughly every minute, update fuzzer stats and save auto tokens. */

    if (cur_ms - last_stats_ms > STATS_UPDATE_SEC * 1000)
    {

        last_stats_ms = cur_ms;
        write_stats_file(t_byte_ratio, stab_ratio, avg_exec);
        save_auto();
        write_bitmap();
    }

    /* Every now and then, write plot data. */

    if (cur_ms - last_plot_ms > PLOT_UPDATE_SEC * 1000)
    {

        last_plot_ms = cur_ms;
        maybe_update_plot_file(t_byte_ratio, avg_exec);
    }

    /* Honor AFL_EXIT_WHEN_DONE and AFL_BENCH_UNTIL_CRASH. */

    if (!dumb_mode && cycles_wo_finds > 100 && !pending_not_fuzzed &&
        getenv("AFL_EXIT_WHEN_DONE"))
        stop_soon = 2;

    if (total_crashes && getenv("AFL_BENCH_UNTIL_CRASH"))
        stop_soon = 2;

    /* If we're not on TTY, bail out. */

    if (not_on_tty)
        return;

    /* Compute some mildly useful bitmap stats. */

    t_bits = (MAP_SIZE << 3) - count_bits(virgin_bits);

    /* Now, for the visuals... */

    if (clear_screen)
    {

        SAYF(TERM_CLEAR CURSOR_HIDE);
        clear_screen = 0;

        check_term_size();
    }

    SAYF(TERM_HOME);

    if (term_too_small)
    {

        SAYF(cBRI "Your terminal is too small to display the UI.\n"
                  "Please resize terminal window to at least 80x25.\n" cRST);

        return;
    }

    /* Let's start by drawing a centered banner. */

    banner_len = (crash_mode ? 24 : 22) + strlen(VERSION) + strlen(use_banner);
    banner_pad = (80 - banner_len) / 2;
    memset(tmp, ' ', banner_pad);

    sprintf(tmp + banner_pad, "%s " cLCY VERSION cLGN " (%s)", crash_mode ? cPIN "peruvian were-rabbit" : cYEL "american fuzzy lop", use_banner);

    SAYF("\n%s\n\n", tmp);

    /* "Handy" shortcuts for drawing boxes... */

#define bSTG bSTART cGRA
#define bH2 bH bH
#define bH5 bH2 bH2 bH
#define bH10 bH5 bH5
#define bH20 bH10 bH10
#define bH30 bH20 bH10
#define SP5 "     "
#define SP10 SP5 SP5
#define SP20 SP10 SP10

    /* Lord, forgive me this. */

    SAYF(SET_G1 bSTG bLT bH bSTOP cCYA " process timing " bSTG bH30 bH5 bH2 bHB
             bH bSTOP cCYA " overall results " bSTG bH5 bRT "\n");

    if (dumb_mode)
    {

        strcpy(tmp, cRST);
    }
    else
    {

        u64 min_wo_finds = (cur_ms - last_path_time) / 1000 / 60;

        /* First queue cycle: don't stop now! */
        if (queue_cycle == 1 || min_wo_finds < 15)
            strcpy(tmp, cMGN);
        else

            /* Subsequent cycles, but we're still making finds. */
            if (cycles_wo_finds < 25 || min_wo_finds < 30)
                strcpy(tmp, cYEL);
            else

                /* No finds for a long time and no test cases to try. */
                if (cycles_wo_finds > 100 && !pending_not_fuzzed && min_wo_finds > 120)
                    strcpy(tmp, cLGN);

                /* Default: cautiously OK to stop? */
                else
                    strcpy(tmp, cLBL);
    }

    SAYF(bV bSTOP "        run time : " cRST "%-34s " bSTG bV bSTOP
                  "  cycles done : %s%-5s  " bSTG bV "\n",
         DTD(cur_ms, start_time), tmp, DI(queue_cycle - 1));

    /* We want to warn people about not seeing new paths after a full cycle,
       except when resuming fuzzing or running in non-instrumented mode. */

    if (!dumb_mode && (last_path_time || resuming_fuzz || queue_cycle == 1 ||
                       in_bitmap || crash_mode))
    {

        SAYF(bV bSTOP "   last new path : " cRST "%-34s ",
             DTD(cur_ms, last_path_time));
    }
    else
    {

        if (dumb_mode)

            SAYF(bV bSTOP "   last new path : " cPIN "n/a" cRST
                          " (non-instrumented mode)        ");

        else

            SAYF(bV bSTOP "   last new path : " cRST "none yet " cLRD
                          "(odd, check syntax!)      ");
    }

    SAYF(bSTG bV bSTOP "  total paths : " cRST "%-5s  " bSTG bV "\n",
         DI(queued_paths));

    /* Highlight crashes in red if found, denote going over the KEEP_UNIQUE_CRASH
       limit with a '+' appended to the count. */

    sprintf(tmp, "%s%s", DI(unique_crashes),
            (unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

    SAYF(bV bSTOP " last uniq crash : " cRST "%-34s " bSTG bV bSTOP
                  " uniq crashes : %s%-6s " bSTG bV "\n",
         DTD(cur_ms, last_crash_time), unique_crashes ? cLRD : cRST,
         tmp);

    sprintf(tmp, "%s%s", DI(unique_hangs),
            (unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

    SAYF(bV bSTOP "  last uniq hang : " cRST "%-34s " bSTG bV bSTOP
                  "   uniq hangs : " cRST "%-6s " bSTG bV "\n",
         DTD(cur_ms, last_hang_time), tmp);

    SAYF(bVR bH bSTOP cCYA " cycle progress " bSTG bH20 bHB bH bSTOP cCYA
                           " map coverage " bSTG bH bHT bH20 bH2 bH bVL "\n");

    /* This gets funny because we want to print several variable-length variables
       together, but then cram them into a fixed-width field - so we need to
       put them in a temporary buffer first. */

    sprintf(tmp, "%s%s (%0.02f%%)", DI(current_entry),
            queue_cur->favored ? "" : "*",
            ((double)current_entry * 100) / queued_paths);

    SAYF(bV bSTOP "  now processing : " cRST "%-17s " bSTG bV bSTOP, tmp);

    sprintf(tmp, "%0.02f%% / %0.02f%%", ((double)queue_cur->bitmap_size) * 100 / MAP_SIZE, t_byte_ratio);

    SAYF("    map density : %s%-21s " bSTG bV "\n", t_byte_ratio > 70 ? cLRD : ((t_bytes < 200 && !dumb_mode) ? cPIN : cRST), tmp);

    sprintf(tmp, "%s (%0.02f%%)", DI(cur_skipped_paths),
            ((double)cur_skipped_paths * 100) / queued_paths);

    SAYF(bV bSTOP " paths timed out : " cRST "%-17s " bSTG bV, tmp);

    sprintf(tmp, "%0.02f bits/tuple",
            t_bytes ? (((double)t_bits) / t_bytes) : 0);

    SAYF(bSTOP " count coverage : " cRST "%-21s " bSTG bV "\n", tmp);

    SAYF(bVR bH bSTOP cCYA " stage progress " bSTG bH20 bX bH bSTOP cCYA
                           " findings in depth " bSTG bH20 bVL "\n");

    sprintf(tmp, "%s (%0.02f%%)", DI(queued_favored),
            ((double)queued_favored) * 100 / queued_paths);

    /* Yeah... it's still going on... halp? */

    SAYF(bV bSTOP "  now trying : " cRST "%-21s " bSTG bV bSTOP
                  " favored paths : " cRST "%-22s " bSTG bV "\n",
         stage_name, tmp);

    if (!stage_max)
    {

        sprintf(tmp, "%s/-", DI(stage_cur));
    }
    else
    {

        sprintf(tmp, "%s/%s (%0.02f%%)", DI(stage_cur), DI(stage_max),
                ((double)stage_cur) * 100 / stage_max);
    }

    SAYF(bV bSTOP " stage execs : " cRST "%-21s " bSTG bV bSTOP, tmp);

    sprintf(tmp, "%s (%0.02f%%)", DI(queued_with_cov),
            ((double)queued_with_cov) * 100 / queued_paths);

    SAYF("  new edges on : " cRST "%-22s " bSTG bV "\n", tmp);

    sprintf(tmp, "%s (%s%s unique)", DI(total_crashes), DI(unique_crashes),
            (unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

    if (crash_mode)
    {

        SAYF(bV bSTOP " total execs : " cRST "%-21s " bSTG bV bSTOP
                      "   new crashes : %s%-22s " bSTG bV "\n",
             DI(total_execs),
             unique_crashes ? cLRD : cRST, tmp);
    }
    else
    {

        SAYF(bV bSTOP " total execs : " cRST "%-21s " bSTG bV bSTOP
                      " total crashes : %s%-22s " bSTG bV "\n",
             DI(total_execs),
             unique_crashes ? cLRD : cRST, tmp);
    }

    /* Show a warning about slow execution. */

    if (avg_exec < 100)
    {

        sprintf(tmp, "%s/sec (%s)", DF(avg_exec), avg_exec < 20 ? "zzzz..." : "slow!");

        SAYF(bV bSTOP "  exec speed : " cLRD "%-21s ", tmp);
    }
    else
    {

        sprintf(tmp, "%s/sec", DF(avg_exec));
        SAYF(bV bSTOP "  exec speed : " cRST "%-21s ", tmp);
    }

    sprintf(tmp, "%s (%s%s unique)", DI(total_tmouts), DI(unique_tmouts),
            (unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

    SAYF(bSTG bV bSTOP "  total tmouts : " cRST "%-22s " bSTG bV "\n", tmp);

    /* Aaaalmost there... hold on! */

    SAYF(bVR bH cCYA bSTOP " fuzzing strategy yields " bSTG bH10 bH bHT bH10
             bH5 bHB bH bSTOP cCYA " path geometry " bSTG bH5 bH2 bH bVL "\n");

    if (skip_deterministic)
    {

        strcpy(tmp, "n/a, n/a, n/a");
    }
    else
    {

        sprintf(tmp, "%s/%s, %s/%s, %s/%s",
                DI(stage_finds[STAGE_FLIP1]), DI(stage_cycles[STAGE_FLIP1]),
                DI(stage_finds[STAGE_FLIP2]), DI(stage_cycles[STAGE_FLIP2]),
                DI(stage_finds[STAGE_FLIP4]), DI(stage_cycles[STAGE_FLIP4]));
    }

    SAYF(bV bSTOP "   bit flips : " cRST "%-37s " bSTG bV bSTOP "    levels : " cRST "%-10s " bSTG bV "\n", tmp, DI(max_depth));

    if (!skip_deterministic)
        sprintf(tmp, "%s/%s, %s/%s, %s/%s",
                DI(stage_finds[STAGE_FLIP8]), DI(stage_cycles[STAGE_FLIP8]),
                DI(stage_finds[STAGE_FLIP16]), DI(stage_cycles[STAGE_FLIP16]),
                DI(stage_finds[STAGE_FLIP32]), DI(stage_cycles[STAGE_FLIP32]));

    SAYF(bV bSTOP "  byte flips : " cRST "%-37s " bSTG bV bSTOP "   pending : " cRST "%-10s " bSTG bV "\n", tmp, DI(pending_not_fuzzed));

    if (!skip_deterministic)
        sprintf(tmp, "%s/%s, %s/%s, %s/%s",
                DI(stage_finds[STAGE_ARITH8]), DI(stage_cycles[STAGE_ARITH8]),
                DI(stage_finds[STAGE_ARITH16]), DI(stage_cycles[STAGE_ARITH16]),
                DI(stage_finds[STAGE_ARITH32]), DI(stage_cycles[STAGE_ARITH32]));

    SAYF(bV bSTOP " arithmetics : " cRST "%-37s " bSTG bV bSTOP "  pend fav : " cRST "%-10s " bSTG bV "\n", tmp, DI(pending_favored));

    if (!skip_deterministic)
        sprintf(tmp, "%s/%s, %s/%s, %s/%s",
                DI(stage_finds[STAGE_INTEREST8]), DI(stage_cycles[STAGE_INTEREST8]),
                DI(stage_finds[STAGE_INTEREST16]), DI(stage_cycles[STAGE_INTEREST16]),
                DI(stage_finds[STAGE_INTEREST32]), DI(stage_cycles[STAGE_INTEREST32]));

    SAYF(bV bSTOP "  known ints : " cRST "%-37s " bSTG bV bSTOP " own finds : " cRST "%-10s " bSTG bV "\n", tmp, DI(queued_discovered));

    if (!skip_deterministic)
        sprintf(tmp, "%s/%s, %s/%s, %s/%s",
                DI(stage_finds[STAGE_EXTRAS_UO]), DI(stage_cycles[STAGE_EXTRAS_UO]),
                DI(stage_finds[STAGE_EXTRAS_UI]), DI(stage_cycles[STAGE_EXTRAS_UI]),
                DI(stage_finds[STAGE_EXTRAS_AO]), DI(stage_cycles[STAGE_EXTRAS_AO]));

    SAYF(bV bSTOP "  dictionary : " cRST "%-37s " bSTG bV bSTOP
                  "  imported : " cRST "%-10s " bSTG bV "\n",
         tmp,
         sync_id ? DI(queued_imported) : (u8 *)"n/a");

    sprintf(tmp, "%s/%s, %s/%s",
            DI(stage_finds[STAGE_HAVOC]), DI(stage_cycles[STAGE_HAVOC]),
            DI(stage_finds[STAGE_SPLICE]), DI(stage_cycles[STAGE_SPLICE]));

    SAYF(bV bSTOP "       havoc : " cRST "%-37s " bSTG bV bSTOP, tmp);

    if (t_bytes)
        sprintf(tmp, "%0.02f%%", stab_ratio);
    else
        strcpy(tmp, "n/a");

    SAYF(" stability : %s%-10s " bSTG bV "\n", (stab_ratio < 85 && var_byte_count > 40) ? cLRD : ((queued_variable && (!persistent_mode || var_byte_count > 20)) ? cMGN : cRST), tmp);

    if (!bytes_trim_out)
    {

        sprintf(tmp, "n/a, ");
    }
    else
    {

        sprintf(tmp, "%0.02f%%/%s, ",
                ((double)(bytes_trim_in - bytes_trim_out)) * 100 / bytes_trim_in,
                DI(trim_execs));
    }

    if (!blocks_eff_total)
    {

        u8 tmp2[128];

        sprintf(tmp2, "n/a");
        strcat(tmp, tmp2);
    }
    else
    {

        u8 tmp2[128];

        sprintf(tmp2, "%0.02f%%",
                ((double)(blocks_eff_total - blocks_eff_select)) * 100 /
                    blocks_eff_total);

        strcat(tmp, tmp2);
    }

    SAYF(bV bSTOP "        trim : " cRST "%-37s " bSTG bVR bH20 bH2 bH2 bRB "\n" bLB bH30 bH20 bH2 bH bRB bSTOP cRST RESET_G1, tmp);

    /* Provide some CPU utilization stats. */

    if (cpu_core_count)
    {

        double cur_runnable = get_runnable_processes();
        u32 cur_utilization = cur_runnable * 100 / cpu_core_count;

        u8 *cpu_color = cCYA;

        /* If we could still run one or more processes, use green. */

        if (cpu_core_count > 1 && cur_runnable + 1 <= cpu_core_count)
            cpu_color = cLGN;

        /* If we're clearly oversubscribed, use red. */

        if (!no_cpu_meter_red && cur_utilization >= 150)
            cpu_color = cLRD;

#ifdef HAVE_AFFINITY

        if (cpu_aff >= 0)
        {

            SAYF(SP10 cGRA "[cpu%03u:%s%3u%%" cGRA "]\r" cRST,
                 MIN(cpu_aff, 999), cpu_color,
                 MIN(cur_utilization, 999));
        }
        else
        {

            SAYF(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST,
                 cpu_color, MIN(cur_utilization, 999));
        }

#else

        SAYF(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST,
             cpu_color, MIN(cur_utilization, 999));

#endif /* ^HAVE_AFFINITY */
    }
    else
        SAYF("\r");

    /* Hallelujah! */

    fflush(0);
}

/* Display quick statistics at the end of processing the input directory,
   plus a bunch of warnings. Some calibration stuff also ended up here,
   along with several hardcoded constants. Maybe clean up eventually. */
//在处理输入目录的末尾显示统计信息，以及一堆警告,以及几个硬编码的常量
static void show_init_stats(void)
{

    struct queue_entry *q = queue;
    u32 min_bits = 0, max_bits = 0;
    u64 min_us = 0, max_us = 0;
    u64 avg_us = 0;
    u32 max_len = 0;
    //依据之前从calibrate_case里得到的total_cal_us和total_cal_cycles，计算出单轮执行的时间avg_us，如果大于10000，就警告"The target binary is pretty slow! See %s/perf_tips.txt."
    if (total_cal_cycles)
        avg_us = total_cal_us / total_cal_cycles;

    while (q)
    {

        if (!min_us || q->exec_us < min_us)
            min_us = q->exec_us;
        if (q->exec_us > max_us)
            max_us = q->exec_us;

        if (!min_bits || q->bitmap_size < min_bits)
            min_bits = q->bitmap_size;
        if (q->bitmap_size > max_bits)
            max_bits = q->bitmap_size;

        if (q->len > max_len)
            max_len = q->len;

        q = q->next;
    }

    SAYF("\n");

    if (avg_us > (qemu_mode ? 50000 : 10000))
        WARNF(cLRD "The target binary is pretty slow! See %s/perf_tips.txt.",
              doc_path);

    /* Let's keep things moving with slow binaries. */

    if (avg_us > 50000)
        havoc_div = 10; /* 0-19 execs/sec   */
    else if (avg_us > 20000)
        havoc_div = 5; /* 20-49 execs/sec  */
    else if (avg_us > 10000)
        havoc_div = 2; /* 50-100 execs/sec */
    //如果不是resuming session，则对queue的大小和个数超限提出警告，且如果useless_at_start不为0，就警告有可以精简的样本
    if (!resuming_fuzz)
    {

        if (max_len > 50 * 1024)
            WARNF(cLRD "Some test cases are huge (%s) - see %s/perf_tips.txt!",
                  DMS(max_len), doc_path);
        else if (max_len > 10 * 1024)
            WARNF("Some test cases are big (%s) - see %s/perf_tips.txt.",
                  DMS(max_len), doc_path);

        if (useless_at_start && !in_bitmap)
            WARNF(cLRD "Some test cases look useless. Consider using a smaller set.");

        if (queued_paths > 100)
            WARNF(cLRD "You probably have far too many input files! Consider trimming down.");
        else if (queued_paths > 20)
            WARNF("You have lots of input files; try starting small.");
    }

    OKF("Here are some useful stats:\n\n"

        cGRA "    Test case count : " cRST "%u favored, %u variable, %u total\n" cGRA "       Bitmap range : " cRST "%u to %u bits (average: %0.02f bits)\n" cGRA "        Exec timing : " cRST "%s to %s us (average: %s us)\n",
        queued_favored, queued_variable, queued_paths, min_bits, max_bits,
        ((double)total_bitmap_size) / (total_bitmap_entries ? total_bitmap_entries : 1),
        DI(min_us), DI(max_us), DI(avg_us));
    //如果timeout_given为0，则根据avg_us来计算出exec_tmout，注意这里avg_us的单位是微秒，而exec_tmout单位是毫秒，所以需要除以1000
    if (!timeout_given)
    {

        /* Figure out the appropriate timeout. The basic idea is: 5x average or
           1x max, rounded up to EXEC_TM_ROUND ms and capped at 1 second.

           If the program is slow, the multiplier is lowered to 2x or 3x, because
           random scheduler jitter is less likely to have any impact, and because
           our patience is wearing thin =) */

        if (avg_us > 50000)
            exec_tmout = avg_us * 2 / 1000;
        else if (avg_us > 10000)
            exec_tmout = avg_us * 3 / 1000;
        else
            exec_tmout = avg_us * 5 / 1000;
        //然后在上面计算出来的exec_tmout和所有样例中执行时间最长的样例进行比较，取最大值赋给exec_tmout
        exec_tmout = MAX(exec_tmout, max_us / 1000);
        exec_tmout = (exec_tmout + EXEC_TM_ROUND) / EXEC_TM_ROUND * EXEC_TM_ROUND;
        //如果exec_tmout大于EXEC_TIMEOUT，就设置exec_tmout = EXEC_TIMEOUT
        if (exec_tmout > EXEC_TIMEOUT)
            exec_tmout = EXEC_TIMEOUT;

        ACTF("No -t option specified, so I'll use exec timeout of %u ms.",
             exec_tmout);

        timeout_given = 1;
    }
    else if (timeout_given == 3)
    {
        //如果timeout_give不为0，且为3，代表这是resuming session，直接打印"Applying timeout settings from resumed session (%u ms).", exec_tmout,此时的timeout_give是我们从历史记录里读取出的
        ACTF("Applying timeout settings from resumed session (%u ms).", exec_tmout);
    }

    /* In dumb mode, re-running every timing out test case with a generous time
       limit is very expensive, so let's select a more conservative default. */
    //如果是dumb_mode且没有设置环境变量AFL_HANG_TMOUT
    if (dumb_mode && !getenv("AFL_HANG_TMOUT"))
        hang_tmout = MIN(EXEC_TIMEOUT, exec_tmout * 2 + 100);

    OKF("All set and ready to roll!");
}

/* Find first power of two greater or equal to val (assuming val under
   2^31). */

static u32 next_p2(u32 val)
{

    u32 ret = 1;
    while (val > ret)
        ret <<= 1;
    return ret;
}

/* Trim all new test cases to save cycles when doing deterministic checks. The
   trimmer uses power-of-two increments somewhere between 1/16 and 1/1024 of
   file size, to keep the stage short and sweet. */
//在进行确定性检查时，修剪所有新的测试用例以节省周期。修剪器使用文件大小的1/16到1/1024之间的2次方增量，速度和效率的折中
static u8 trim_case(char **argv, struct queue_entry *q, u8 *in_buf)
{

    static u8 tmp[64];
    static u8 clean_trace[MAP_SIZE];

    u8 needs_write = 0, fault = 0;
    u32 trim_exec = 0;
    u32 remove_len;
    u32 len_p2;

    /* Although the trimmer will be less useful when variable behavior is
       detected, it will still work to some extent, so we don't check for
       this. */
    //如果这个case的大小len小于5字节，就直接返回
    if (q->len < 5)
        return 0;
    //设置stage_name的值为tmp，在bytes_trim_in的值里加上len，bytes_trim_in代表被trim过的字节数
    stage_name = tmp;
    bytes_trim_in += q->len;

    /* Select initial chunk len, starting with large steps. */
    //计算len_p2，其值是大于等于q->len的第一个2的幂次。（eg.如果len是5704,那么len_p2就是8192）
    len_p2 = next_p2(q->len);
    //取len_p2的1/16为remove_len，这是起始步长
    remove_len = MAX(len_p2 / TRIM_START_STEPS, TRIM_MIN_BYTES);

    /* Continue until the number of steps gets too high or the stepover
       gets too small. */
    //从文件长度1/16开始最到最小1/1024步长，设置移除文件的大小
    //进入while循环，终止条件是remove_len小于终止步长len_p2的1/1024,每轮循环步长会除2
    while (remove_len >= MAX(len_p2 / TRIM_END_STEPS, TRIM_MIN_BYTES))
    {

        u32 remove_pos = remove_len;
        //读入"trim %s/%s", DI(remove_len), DI(remove_len)到tmp中, 即stage_name = “trim 512/512”
        sprintf(tmp, "trim %s/%s", DI(remove_len), DI(remove_len));

        stage_cur = 0;
        stage_max = q->len / remove_len;
        //按选定的步长，移除，然后循环该文件
        //进入while循环，remove_pos < q->len,即每次前进remove_len个步长，直到整个文件都被遍历完为止
        while (remove_pos < q->len)
        {
            //由in_buf中remove_pos处开始，向后跳过remove_len个字节，写入到.cur_input里，然后运行一次fault = run_target，trim_execs计数器加一
            u32 trim_avail = MIN(remove_len, q->len - remove_pos);
            u32 cksum;
            //删除
            write_with_gap(in_buf, q->len, remove_pos, trim_avail);
            //执行
            fault = run_target(argv, exec_tmout);
            trim_execs++;

            if (stop_soon || fault == FAULT_ERROR)
                goto abort_trimming;

            /* Note that we don't keep track of crashes or hangs here; maybe TODO? */
            //检查trace_bit是否不一样
            cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

            /* If the deletion had no impact on the trace, make it permanent. This
               isn't perfect for variable-path inputs, but we're just making a
               best-effort pass, so it's not a big deal if we end up with false
               negatives every now and then. */
            //如果删除对跟踪没有影响，则使其永久。作者表明可能可变路径会对此产生一些影响，不过没有大碍
            //由所得trace_bits计算出一个cksum，和q->exec_cksum比较
            if (cksum == q->exec_cksum)
            {
                //从q->len中减去remove_len个字节，并由此重新计算出一个len_p2，这里注意一下while (remove_len >= MAX(len_p2 / TRIM_END_STEPS, TRIM_MIN_BYTES))
                u32 move_tail = q->len - remove_pos - trim_avail;

                q->len -= trim_avail;
                len_p2 = next_p2(q->len);
                //将in_buf+remove_pos+remove_len到最后的字节，前移到in_buf+remove_pos处，等于删除了remove_pos向后的remove_len个字节。
                memmove(in_buf + remove_pos, in_buf + remove_pos + trim_avail,
                        move_tail);

                /* Let's save a clean trace, which will be needed by
                   update_bitmap_score once we're done with the trimming stuff. */
                //保存之前的trace_bits，因为执行如果改变了trace_bit
                if (!needs_write)
                { //如果needs_write为0，则设置其为1，并保存当前trace_bits到clean_trace中

                    needs_write = 1;
                    memcpy(clean_trace, trace_bits, MAP_SIZE);
                }
            }
            else
                remove_pos += remove_len; // remove_pos加上remove_len，即前移remove_len个字节。注意，如果相等，就无需前移

            /* Since this can be slow, update the screen every now and then. */
            // trim过程可能比较慢，所以每执行stats_update_freq次，就刷新一次显示界面show_stats
            if (!(trim_exec++ % stats_update_freq))
                show_stats();
            stage_cur++;
        }

        remove_len >>= 1; //增加步长
    }

    /* If we have made changes to in_buf, we also need to update the on-disk
       version of the test case. */

    if (needs_write)
    {
        //删除原来的q->fname，创建一个新的q->fname，将in_buf里的内容写入，然后用clean_trace恢复trace_bits的值
        s32 fd;

        unlink(q->fname); /* ignore errors */

        fd = open(q->fname, O_WRONLY | O_CREAT | O_EXCL, 0600);

        if (fd < 0)
            PFATAL("Unable to create '%s'", q->fname);

        ck_write(fd, in_buf, q->len, q->fname);
        close(fd);

        memcpy(trace_bits, clean_trace, MAP_SIZE);
        update_bitmap_score(q);
    }

abort_trimming:

    bytes_trim_out += q->len;
    return fault;
}

/* Write a modified test case, run program, process results. Handle
   error conditions, returning 1 if it's time to bail out. This is
   a helper function for fuzz_one(). */
//写入文件并执行，然后处理结果，如果出现错误，就返回1
EXP_ST u8 common_fuzz_stuff(char **argv, u8 *out_buf, u32 len)
{

    u8 fault;
    //如果定义了post_handler,就通过out_buf = post_handler(out_buf, &len)处理一下out_buf，如果out_buf或者len有一个为0，则直接返回0
    if (post_handler)
    {
        //这里其实很有价值，尤其是如果需要对变异完的queue，做一层wrapper再写入的时候???
        out_buf = post_handler(out_buf, &len);
        if (!out_buf || !len)
            return 0;
    }
    //将变异写到文件中
    write_to_testcase(out_buf, len);

    fault = run_target(argv, exec_tmout);

    if (stop_soon)
        return 1;

    if (fault == FAULT_TMOUT)
    {
        //如果subseq_tmouts++ > TMOUT_LIMIT（默认250），就将cur_skipped_paths加一，直接返回1
        if (subseq_tmouts++ > TMOUT_LIMIT)
        {
            cur_skipped_paths++;
            return 1;
        }
    }
    else
        subseq_tmouts = 0; // subseq_tmout是连续超时数

    /* Users can hit us with SIGUSR1 to request the current input
       to be abandoned. */

    if (skip_requested)
    {
        //设置skip_requested为0，然后将cur_skipped_paths加一，直接返回1
        skip_requested = 0;
        cur_skipped_paths++;
        return 1;
    }

    /* This handles FAULT_ERROR for us: */
    //如果发现了新的路径才会加一
    queued_discovered += save_if_interesting(argv, out_buf, len, fault);
    //如果stage_cur除以stats_update_freq余数是0，或者其加一等于stage_max，就更新展示界面show_stats
    if (!(stage_cur % stats_update_freq) || stage_cur + 1 == stage_max)
        show_stats();

    return 0;
}

/* Helper to choose random block len for block operations in fuzz_one().
   Doesn't return zero, provided that max_len is > 0. */

static u32 choose_block_len(u32 limit)
{

    u32 min_value, max_value;
    u32 rlim = MIN(queue_cycle, 3);

    if (!run_over10m)
        rlim = 1;

    switch (UR(rlim))
    {

    case 0:
        min_value = 1;
        max_value = HAVOC_BLK_SMALL;
        break;

    case 1:
        min_value = HAVOC_BLK_SMALL;
        max_value = HAVOC_BLK_MEDIUM;
        break;

    default:

        if (UR(10))
        {

            min_value = HAVOC_BLK_MEDIUM;
            max_value = HAVOC_BLK_LARGE;
        }
        else
        {

            min_value = HAVOC_BLK_LARGE;
            max_value = HAVOC_BLK_XL;
        }
    }

    if (min_value >= limit)
        min_value = 1;

    return min_value + UR(MIN(max_value, limit) - min_value + 1);
}

/* Calculate case desirability score to adjust the length of havoc fuzzing.
   A helper function for fuzz_one(). Maybe some of these constants should
   go into config.h. */
//根据case的执行速度/bitmap的大小/case产生时间/路径深度等因素给case进行打分,返回值为一个分数，
//用来调整在havoc阶段的用时。使得执行时间短，代码覆盖高，新发现的，路径深度深的case拥有更多havoc变异的机会
//根据queue entry的执行速度、覆盖到的path数和路径深度来评估出一个得分，这个得分perf_score在后面havoc的时候使用
static u32 calculate_score(struct queue_entry *q)
{

    u32 avg_exec_us = total_cal_us / total_cal_cycles;
    u32 avg_bitmap_size = total_bitmap_size / total_bitmap_entries;
    u32 perf_score = 100; //满分

    /* Adjust score based on execution speed of this path, compared to the
       global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
       less expensive to fuzz, so we're giving them more air time. */
    //执行时间
    if (q->exec_us * 0.1 > avg_exec_us)
        perf_score = 10;
    else if (q->exec_us * 0.25 > avg_exec_us)
        perf_score = 25;
    else if (q->exec_us * 0.5 > avg_exec_us)
        perf_score = 50;
    else if (q->exec_us * 0.75 > avg_exec_us)
        perf_score = 75;
    else if (q->exec_us * 4 < avg_exec_us)
        perf_score = 300;
    else if (q->exec_us * 3 < avg_exec_us)
        perf_score = 200;
    else if (q->exec_us * 2 < avg_exec_us)
        perf_score = 150;

    /* Adjust score based on bitmap size. The working theory is that better
       coverage translates to better targets. Multiplier from 0.25x to 3x. */
    //命中的分支数
    if (q->bitmap_size * 0.3 > avg_bitmap_size)
        perf_score *= 3;
    else if (q->bitmap_size * 0.5 > avg_bitmap_size)
        perf_score *= 2;
    else if (q->bitmap_size * 0.75 > avg_bitmap_size)
        perf_score *= 1.5;
    else if (q->bitmap_size * 3 < avg_bitmap_size)
        perf_score *= 0.25;
    else if (q->bitmap_size * 2 < avg_bitmap_size)
        perf_score *= 0.5;
    else if (q->bitmap_size * 1.5 < avg_bitmap_size)
        perf_score *= 0.75;

    /* Adjust score based on handicap. Handicap is proportional to how late
       in the game we learned about this path. Latecomers are allowed to run
       for a bit longer until they catch up with the rest. */
    //经过fuzz的论数，轮数越多，排名越高
    if (q->handicap >= 4)
    {

        perf_score *= 4;
        q->handicap -= 4;
    }
    else if (q->handicap)
    {

        perf_score *= 2;
        q->handicap--;
    }

    /* Final adjustment based on input depth, under the assumption that fuzzing
       deeper test cases is more likely to reveal stuff that can't be
       discovered with traditional fuzzers. */
    // q->depth,它在每次add_to_queue的时候，会设置为cur_depth+1，而cur_depth是一个全局变量，一开始的初始值为0
    //处理输入时:在read_testcases的时候会调用add_to_queue，此时所有的input case的queue depth都会被设置为1
    //然后在后面fuzz_one的时候，会先设置cur_depth为当前queue的depth，然后这个queue经过mutate之后调用save_if_interesting,如果是interesting case，就会被add_to_queue，此时就建立起了queue之间的关联关系，所以由当前queue变异加入的新queue，深度都在当前queue的基础上再增加
    switch (q->depth)
    { //队列的深度

    case 0 ... 3:
        break;
    case 4 ... 7:
        perf_score *= 2;
        break;
    case 8 ... 13:
        perf_score *= 3;
        break;
    case 14 ... 25:
        perf_score *= 4;
        break;
    default:
        perf_score *= 5;
    }

    /* Make sure that we don't go over limit. */

    if (perf_score > HAVOC_MAX_MULT * 100)
        perf_score = HAVOC_MAX_MULT * 100;

    return perf_score;
}

/* Helper function to see if a particular change (xor_val = old ^ new) could
   be a product of deterministic bit flips with the lengths and stepovers
   attempted by afl-fuzz. *This is used to avoid dupes in some of the
   deterministic fuzzing operations that follow bit flips. We also
   return 1 if xor_val is zero, which implies that the old and attempted new
   values are identical and the exec would be a waste of time. */

static u8 could_be_bitflip(u32 xor_val)
{

    u32 sh = 0;

    if (!xor_val)
        return 1;

    /* Shift left until first bit set. */

    while (!(xor_val & 1))
    {
        sh++;
        xor_val >>= 1;
    }

    /* 1-, 2-, and 4-bit patterns are OK anywhere. */

    if (xor_val == 1 || xor_val == 3 || xor_val == 15)
        return 1;

    /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
       divisible by 8, since that's the stepover for these ops. */

    if (sh & 7)
        return 0;

    if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff)
        return 1;

    return 0;
}

/* Helper function to see if a particular value is reachable through
   arithmetic operations. Used for similar purposes. */

static u8 could_be_arith(u32 old_val, u32 new_val, u8 blen)
{

    u32 i, ov = 0, nv = 0, diffs = 0;

    if (old_val == new_val)
        return 1;

    /* See if one-byte adjustments to any byte could produce this result. */

    for (i = 0; i < blen; i++)
    {

        u8 a = old_val >> (8 * i),
           b = new_val >> (8 * i);

        if (a != b)
        {
            diffs++;
            ov = a;
            nv = b;
        }
    }

    /* If only one byte differs and the values are within range, return 1. */

    if (diffs == 1)
    {

        if ((u8)(ov - nv) <= ARITH_MAX ||
            (u8)(nv - ov) <= ARITH_MAX)
            return 1;
    }

    if (blen == 1)
        return 0;

    /* See if two-byte adjustments to any byte would produce this result. */

    diffs = 0;

    for (i = 0; i < blen / 2; i++)
    {

        u16 a = old_val >> (16 * i),
            b = new_val >> (16 * i);

        if (a != b)
        {
            diffs++;
            ov = a;
            nv = b;
        }
    }

    /* If only one word differs and the values are within range, return 1. */

    if (diffs == 1)
    {

        if ((u16)(ov - nv) <= ARITH_MAX ||
            (u16)(nv - ov) <= ARITH_MAX)
            return 1;

        ov = SWAP16(ov);
        nv = SWAP16(nv);

        if ((u16)(ov - nv) <= ARITH_MAX ||
            (u16)(nv - ov) <= ARITH_MAX)
            return 1;
    }

    /* Finally, let's do the same thing for dwords. */

    if (blen == 4)
    {

        if ((u32)(old_val - new_val) <= ARITH_MAX ||
            (u32)(new_val - old_val) <= ARITH_MAX)
            return 1;

        new_val = SWAP32(new_val);
        old_val = SWAP32(old_val);

        if ((u32)(old_val - new_val) <= ARITH_MAX ||
            (u32)(new_val - old_val) <= ARITH_MAX)
            return 1;
    }

    return 0;
}

/* Last but not least, a similar helper to see if insertion of an
   interesting integer is redundant given the insertions done for
   shorter blen. The last param (check_le) is set if the caller
   already executed LE insertion for current blen and wants to see
   if BE variant passed in new_val is unique. */

static u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le)
{

    u32 i, j;

    if (old_val == new_val)
        return 1;

    /* See if one-byte insertions from interesting_8 over old_val could
       produce new_val. */

    for (i = 0; i < blen; i++)
    {

        for (j = 0; j < sizeof(interesting_8); j++)
        {

            u32 tval = (old_val & ~(0xff << (i * 8))) |
                       (((u8)interesting_8[j]) << (i * 8));

            if (new_val == tval)
                return 1;
        }
    }

    /* Bail out unless we're also asked to examine two-byte LE insertions
       as a preparation for BE attempts. */

    if (blen == 2 && !check_le)
        return 0;

    /* See if two-byte insertions over old_val could give us new_val. */

    for (i = 0; i < blen - 1; i++)
    {

        for (j = 0; j < sizeof(interesting_16) / 2; j++)
        {

            u32 tval = (old_val & ~(0xffff << (i * 8))) |
                       (((u16)interesting_16[j]) << (i * 8));

            if (new_val == tval)
                return 1;

            /* Continue here only if blen > 2. */

            if (blen > 2)
            {

                tval = (old_val & ~(0xffff << (i * 8))) |
                       (SWAP16(interesting_16[j]) << (i * 8));

                if (new_val == tval)
                    return 1;
            }
        }
    }

    if (blen == 4 && check_le)
    {

        /* See if four-byte insertions could produce the same result
           (LE only). */

        for (j = 0; j < sizeof(interesting_32) / 4; j++)
            if (new_val == (u32)interesting_32[j])
                return 1;
    }

    return 0;
}

/* Take the current entry from the queue, fuzz it for a while. This
   function is a tad too long... returns 0 if fuzzed successfully, 1 if
   skipped or bailed out. */
//从queue中取出entry进行fuzz，成功返回0，跳过或退出的话返回1
/*
  bitflip、arithmetic、interest、dictionary 是 deterministic fuzzing 过程，属于dumb mode(-d) 和主 fuzzer(-M) 会进行的操作； havoc、splice 与前面不同是存在随机性，是
  所有fuzz都会进行的变异操作。文件变异是具有启发性判断的，应注意“避免浪费，减少消耗”的原则，即之前变异应该尽可能产生更大的效果，比如 eff_map 数组的设计；同时减少不必要的资源
  消耗，变异可能没啥好效果的话要及时止损。
*/
//一次变异是指一个比特的改变也算变异，根据编译策略，经过很多次变异之后，fuzz_one结束叫做一轮变异。

static u8 fuzz_one(char **argv)
{

    s32 len, fd, temp_len, i, j;
    u8 *in_buf, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
    u64 havoc_queued, orig_hit_cnt, new_hit_cnt;
    u32 splice_cycle = 0, perf_score = 100, orig_perf, prev_cksum, eff_cnt = 1;

    u8 ret_val = 1, doing_det = 0;

    u8 a_collect[MAX_AUTO_EXTRA];
    u32 a_len = 0;

#ifdef IGNORE_FINDS

    /* In IGNORE_FINDS mode, skip any entries that weren't in the
       initial data set. */

    if (queue_cur->depth > 1)
        return 1;

#else
    //根据是否有 pending_favored 和queue_cur的情况，按照概率进行跳过

    //如果pending_favored不为0，则对于queue_cur被fuzz过或者不是favored的，有99%的几率直接返回1
    if (pending_favored)
    {

        /* If we have any favored, non-fuzzed new arrivals in the queue,
           possibly skip to them at the expense of already-fuzzed or non-favored
           cases. */
        //根据是否有pending_favored和queue_cur的情况按照概率进行跳过
        if ((queue_cur->was_fuzzed || !queue_cur->favored) &&
            UR(100) < SKIP_TO_NEW_PROB)
            return 1;
    }
    else if (!dumb_mode && !queue_cur->favored && queued_paths > 10)
    { //如果pending_favored为0且queued_paths(即queue里的case总数)大于10

        /* Otherwise, still possibly skip non-favored cases, albeit less often.
           The odds of skipping stuff are higher for already-fuzzed inputs and
           lower for never-fuzzed entries. */
        //计算概率，种子会不会被跳过
        //如果queue_cycle大于1且queue_cur没有被fuzz过，则有75%的概率直接返回1
        if (queue_cycle > 1 && !queue_cur->was_fuzzed)
        {

            if (UR(100) < SKIP_NFAV_NEW_PROB)
                return 1;
        }
        else
        { //如果queue_cur被fuzz过，否则有95%的概率直接返回1

            if (UR(100) < SKIP_NFAV_OLD_PROB)
                return 1;
        }
    }

#endif /* ^IGNORE_FINDS */

    if (not_on_tty)
    {
        ACTF("Fuzzing test case #%u (%u total, %llu uniq crashes found)...",
             current_entry, queued_paths, unique_crashes);
        fflush(stdout);
    }

    /* Map the test case into memory. */

    fd = open(queue_cur->fname, O_RDONLY);

    if (fd < 0)
        PFATAL("Unable to open '%s'", queue_cur->fname);

    len = queue_cur->len;
    //打开该case对应的文件，并通过mmap映射到内存里，地址赋值给in_buf和orig_in
    orig_in = in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    if (orig_in == MAP_FAILED)
        PFATAL("Unable to mmap '%s'", queue_cur->fname);

    close(fd);

    /* We could mmap() out_buf as MAP_PRIVATE, but we end up clobbering every
       single byte anyway, so it wouldn't give us any performance or memory usage
       benefits. */
    //分配len大小的内存，并初始化为全0，然后将地址赋值给out_buf
    out_buf = ck_alloc_nozero(len);

    subseq_tmouts = 0;

    cur_depth = queue_cur->depth;

    /*******************************************
     * CALIBRATION (only if failed earlier on) *
     *******************************************/
    //假如当前项有校准错误，并且校准错误次数小于3次，那么就用calibrate_case进行测试
    if (queue_cur->cal_failed)
    {

        u8 res = FAULT_TMOUT;
        //假如当前项有校准错误，并且校准错误次数小于3次，那么就用calibrate_case再次校准
        if (queue_cur->cal_failed < CAL_CHANCES)
        {

            res = calibrate_case(argv, queue_cur, in_buf, queue_cycle - 1, 0);

            if (res == FAULT_ERROR)
                FATAL("Unable to execute target application");
        }

        if (stop_soon || res != crash_mode)
        {
            cur_skipped_paths++;
            goto abandon_entry;
        }
    }

    /************
     * TRIMMING *
     ************/
    //如果测试用例没有修剪过，那么调用函数trim_case对测试用例进行修剪  对种子大小进行修剪
    if (!dumb_mode && !queue_cur->trim_done)
    {

        u8 res = trim_case(argv, queue_cur, in_buf);

        if (res == FAULT_ERROR)
            FATAL("Unable to execute target application");

        if (stop_soon)
        {
            cur_skipped_paths++;
            goto abandon_entry;
        }

        /* Don't retry trimming, even if it failed. */

        queue_cur->trim_done = 1;
        //重新读取一次queue_cur->len到len中
        if (len != queue_cur->len)
            len = queue_cur->len;
    }
    //将in_buf拷贝len个字节到out_buf中
    memcpy(out_buf, in_buf, len);

    /*********************
     * PERFORMANCE SCORE *
     *********************/
    //修剪完毕之后，使用calculate_score对每个测试用例进行打分
    //分数 计算；对分数的计算（比如上下文敏感的情况，可以在里面调整分数的计算机制）
    //“分数计算”的函数论文中用到比较多
    orig_perf = perf_score = calculate_score(queue_cur);

    /* Skip right away if -d is given, if we have done deterministic fuzzing on
       this entry ourselves (was_fuzzed), or if it has gone through deterministic
       testing in earlier, resumed runs (passed_det). */
    //如果该queue已经完成deterministic阶段（也就是bit、ari、int、dic的确定性变异），则直接跳到havoc阶段
    if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->passed_det)
        goto havoc_stage;

    /* Skip deterministic fuzzing if exec path checksum puts this out of scope
       for this master instance. */

    if (master_max && (queue_cur->exec_cksum % master_max) != master_id - 1)
        goto havoc_stage;

    doing_det = 1;

    // deterministic阶段变异4个stage，变异过程中会多次调用函数common_fuzz_stuff函数，保存interesting 的种子
    /*********************************************
     * SIMPLE BITFLIP (+dictionary construction) *
     *********************************************/
    //按位翻转，1变为0，0变为1        位翻转（同时会有自动的字典生成【tokens】）
    /*
      (_bf) & 7)相当于模8，产生了（0、1、2、3、4、5、6、7）
      128是二进制的10000000.
      等式的右边相当于将128右移动0-7个单位产生了二进制从（10000000 - 1）
      (_bf) >> 3相当于_bf/8
      //对于FLIP_BIT(_ar, _b)来说，_bf最大为(len << 3)>>3还是len
    */
#define FLIP_BIT(_ar, _b)                       \
    do                                          \
    {                                           \
        u8 *_arf = (u8 *)(_ar);                 \
        u32 _bf = (_b);                         \
        _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
    } while (0)

    /* Single walking bit. */
    //设置stage_name为bitflip 1/1,_ar的取值是out_buf,而_bf的取值在[0: len << 3)
    //所以用_bf & 7能够得到0,1,2...7  0,1,2...7这样的取值一共len组，然后(_bf) >> 3又将[0: len<<3)映射回了[0: len)，对应到buf里的每个byte，
    stage_short = "flip1";
    stage_max = len << 3;
    stage_name = "bitflip 1/1";

    stage_val_type = STAGE_VAL_NONE;

    orig_hit_cnt = queued_paths + unique_crashes;

    prev_cksum = queue_cur->exec_cksum;
    //所以在从0-len*8的遍历过程中会通过异或运算，依次将每个位翻转，然后执行一次common_fuzz_stuff，然后再翻转回来
    //对于这个for循环来说，每运行8次循环_arf[i]（大小为一个字节）的下标i就会加一，i最大为len
    for (stage_cur = 0; stage_cur < stage_max; stage_cur++)
    {
        //在每8次为一组的循环中，128分别右移0、1、2、3、4、5、6、7位，将右移后产生的数字与_arf[i]进行异或翻转，而_arf[i]大小为一个字节，等价于对这个字节的每一位都做一次翻转异或
        stage_cur_byte = stage_cur >> 3;

        FLIP_BIT(out_buf, stage_cur);
        // common_fuzz_stuff执行变异后的结果，然后还原
        if (common_fuzz_stuff(argv, out_buf, len))
            goto abandon_entry;

        FLIP_BIT(out_buf, stage_cur);

        //在进行为翻转的时候，程序会随时注意翻转之后的变化。比如说，对于一段 xxxxxxxxIHDRxxxxxxxx 的
        //文件字符串，当改变 IHDR 任意一个都会导致奇怪的变化，这个时候，程序就会认为 IHDR 是一个可以让fuzzer很激动的“神仙值”--token
        //其实token的长度和数量都是可以控制的，在 config.h 中有定义，但是因为是在头文件宏定义的，修改之后需要重新编译使用。
        /* While flipping the least significant bit in every byte, pull of an extra
           trick to detect possible syntax tokens. In essence, the idea is that if
           you have a binary blob like this:

           xxxxxxxxIHDRxxxxxxxx

           ...and changing the leading and trailing bytes causes variable or no
           changes in program flow, but touching any character in the "IHDR" string
           always produces the same, distinctive path, it's highly likely that
           "IHDR" is an atomically-checked magic value of special significance to
           the fuzzed format.

           We do this here, rather than as a separate stage, because it's a nice
           way to keep the operation approximately "free" (i.e., no extra execs).

           Empirically, performing the check when flipping the least significant bit
           is advantageous, compared to doing it at the time of more disruptive
           changes, where the program flow may be affected in more violent ways.

           The caveat is that we won't generate dictionaries in the -d mode or -S
           mode - but that's probably a fair trade-off.

           This won't work particularly well with paths that exhibit variable
           behavior, but fails gracefully, so we'll carry out the checks anyway.

          */
        //怎么选择token，加到自动的字典里
        if (!dumb_mode && (stage_cur & 7) == 7)
        {

            u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

            if (stage_cur == stage_max - 1 && cksum == prev_cksum)
            {

                /* If at end of file and we are still collecting a string, grab the
                   final character and force output. */
                //在进行bitflip 1/1变异时，对于每个byte的最低位(least significant bit)翻转还进行了额外的处理：如果连续多个bytes的最低位被翻转后，程序的执行路径都未变化，而且与原始执行路径不一致，那么就把这一段连续的bytes判断是一条token。
                //比如对于SQL的SELECT *，如果SELECT被破坏，则肯定和正确的路径不一致，而被破坏之后的路径却肯定是一样的，比如AELECT和SBLECT，显然都是无意义的，而只有不破坏token，才有可能出现和原始执行路径一样的结果，所以AFL在这里就是在猜解关键字token
                if (a_len < MAX_AUTO_EXTRA)
                    a_collect[a_len] = out_buf[stage_cur >> 3];
                a_len++;

                if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
                    maybe_add_auto(a_collect, a_len);
            }
            else if (cksum != prev_cksum)
            {

                /* Otherwise, if the checksum has changed, see if we have something
                   worthwhile queued up, and collect that if the answer is yes. */

                if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
                    maybe_add_auto(a_collect, a_len);

                a_len = 0;
                prev_cksum = cksum;
            }

            /* Continue collecting string, but only if the bit flip actually made
               any difference - we don't want no-op tokens. */

            if (cksum != queue_cur->exec_cksum)
            {

                if (a_len < MAX_AUTO_EXTRA)
                    a_collect[a_len] = out_buf[stage_cur >> 3];
                a_len++;
            }
        }
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP1] += new_hit_cnt - orig_hit_cnt; // stage_finds[STAGE_FLIP1]的值加上在整个FLIP_BIT中新发现的路径和Crash总和
    stage_cycles[STAGE_FLIP1] += stage_max;                 // stage_cycles[STAGE_FLIP1]的值加上在整个FLIP_BIT中执行的target次数stage_max

    /* Two walking bits. */

    stage_name = "bitflip 2/1";
    stage_short = "flip2";
    stage_max = (len << 3) - 1;

    orig_hit_cnt = new_hit_cnt;

    for (stage_cur = 0; stage_cur < stage_max; stage_cur++)
    {

        stage_cur_byte = stage_cur >> 3;
        //连续翻转两位
        FLIP_BIT(out_buf, stage_cur);
        FLIP_BIT(out_buf, stage_cur + 1);
        // common_fuzz_stuff执行变异后的结果，然后还原
        if (common_fuzz_stuff(argv, out_buf, len))
            goto abandon_entry;

        FLIP_BIT(out_buf, stage_cur);
        FLIP_BIT(out_buf, stage_cur + 1);
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP2] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FLIP2] += stage_max;

    /* Four walking bits. */

    stage_name = "bitflip 4/1";
    stage_short = "flip4";
    stage_max = (len << 3) - 3;

    orig_hit_cnt = new_hit_cnt;

    for (stage_cur = 0; stage_cur < stage_max; stage_cur++)
    {

        stage_cur_byte = stage_cur >> 3;

        FLIP_BIT(out_buf, stage_cur);
        FLIP_BIT(out_buf, stage_cur + 1);
        FLIP_BIT(out_buf, stage_cur + 2);
        FLIP_BIT(out_buf, stage_cur + 3);

        if (common_fuzz_stuff(argv, out_buf, len))
            goto abandon_entry;

        FLIP_BIT(out_buf, stage_cur);
        FLIP_BIT(out_buf, stage_cur + 1);
        FLIP_BIT(out_buf, stage_cur + 2);
        FLIP_BIT(out_buf, stage_cur + 3);
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP4] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FLIP4] += stage_max;

    /* Effector map setup. These macros calculate:

       EFF_APOS      - position of a particular file offset in the map.
       EFF_ALEN      - length of a map with a particular number of bytes.
       EFF_SPAN_ALEN - map span for a sequence of bytes.
      这个数组在8/8是起作用，作用可能是，如果一个字节的翻转无法带来路径变化，
     */
//在进行bitflip 8/8变异时，AFL还生成了一个非常重要的信息：effector map。这个effector map几乎贯穿了整个deterministic fuzzing的始终
//具体地，在对每个byte进行翻转时，如果其造成执行路径与原始路径不一致，就将该byte在effector map中标记为1，即“有效”的，否则标记为0，即“无效”的
//这样做的逻辑是：如果一个byte完全翻转，都无法带来执行路径的变化，那么这个byte很有可能是属于”data”，而非”metadata”（例如size, flag等），对整个fuzzing的意义不大。所以，在随后的一些变异中，会参考effector map，跳过那些“无效”的byte，从而节省了执行资源
//由此，通过极小的开销（没有增加额外的执行次数），AFL又一次对文件格式进行了启发式的判断。看到这里，不得不叹服于AFL实现上的精妙。
//不过，在某些情况下并不会检测有效字符。第一种情况就是dumb mode或者从fuzzer，此时文件所有的字符都有可能被变异。第二、第三种情况与文件本身有关
/*
  为什么是 8/8 的时候出现？因为 8bit（比特）的时候是 1byte（字节），如果一个字节的翻转都无法带来路径变化，此byte极有可能是不会导致crash的数据，所以之后应该用一种思路避开无效byte。
标记是干什么用的？根据上面的分析，就很好理解了，标记好的数组可以为之后的变异服务，相当于提前“踩雷（踩掉无效byte的雷）”，相当于进行了启发式的判断。无效为0，有效为1。
达到了怎样的效果？要知道判断的时间开销，对不停循环的fuzzing过程来说是致命的，所以 eff_map 利用在这一次8/8的判断中，通过不大的空间开销，换取了可观的时间开销。(暂时是这样分析的，具体是否真的节约很多，不得而知)
*/

/*
  eff_map 这个变量，看代码的话，在变异fuzz_one阶段，这是个贯穿始终的数组，刚开始第一遍看代码其实不是理解的很深刻，现在理解的比较多了，也能理解作者为什么要加这个数组了：
fuzz_one函数将近两千行，每一个变异阶段都有自己的功能，怎么把上一阶段的信息用于下一阶段，需要一个在函数内通用的局部变量，可以看到fuzz_one一开始的局部变量有很多，有很多类型
    s32 len, fd, temp_len, i, j;
  u8  *in_buf, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
  u64 havoc_queued,  orig_hit_cnt, new_hit_cnt;
  u32 splice_cycle = 0, perf_score = 100, orig_perf, prev_cksum, eff_cnt = 1;
  u8  ret_val = 1, doing_det = 0;
  u8  a_collect[MAX_AUTO_EXTRA];
  u32 a_len = 0;

  eff_map的类型是u8（上篇解释过这种看不懂的，可以去types.h里找，这是一个uint8_t = unsigned char 形，8比特（0~255）），并且u8类型只有这一个是map命名形式的，在后面的注释中如果出现Effector map，说的就是这个变量。主要的作用就是标记，在初始化数组的地方有这么一段注释**Initialize effector map for the next step (see comments below). Always flag first and last byte as doing something.**把第一个和最后一个字节单独标记出来用作其他用途，这里其实就说明了，这个map是标记作用，那是标记什么呢，标记
  当前byte对应的map块是否需要进行阶段变异。如果是0意味着不需要变异，非0（比如1）就需要变异，比如一开始分析的 arithmetic 8/8 阶段就用过这个eff_map，此时已经它在bitflip阶段经过了改变了。
*/

/*
  type(_p) EFF_APOS(_p){
    // >> 是位移操作，把参数的二进制形式进行右移，每移动一位就减小2倍，所以这个函数的意思就是：
    返回传入参数_p除以（2的EFF_MAP_SCALE2次方）。
    同理另一个方向就是左移，是放大2的幂的倍数。
    return (_p / 8);
    // EFF_MAP_SCALE2 在文件config.h中出现，值为3，所以这里就是除以8的意思。
  }
  type(_x) EFF_REM(_x){
    //这里 & 是按位与，所以求的是 _x 与 ((1 << EFF_MAP_SCALE2) - 1)进行按位与，实际上就是跟 7 以二进制形式按位与
    return (_x & 7)
  }
  type(_l) EFF_ALEN(_l){
    //这里的 !! 是一个两次否，目的是归一化（又是一个骚操作，这个作者写代码真的是净整些这种，主要还是自己菜，菜是原罪）
    比如 r = !!a，如果a是整数0，则r=0，如果a是整数非0，则r=1。

    在a不是整数的情况下一般不这么用，但这里都是默认_l为整数的，毕竟字符型转成ascii码那不也是整数吗。
    return (EFF_APOS(_l) + !!EFF_REM(_l))
  }
  type(_p) EFF_SPAN_ALEN(_p, _l){
      return (EFF_APOS((_p) + (_l) - 1) - EFF_APOS(_p) + 1)
  }
*/
// EFF_APOS - position of a particular file offset in the map. 在map中的特定文件偏移位置。
// EFF_ALEN - length of a map with a particular number of bytes. 根据特定数量的字节数，计算得到的文件长度。 EFF_SPAN_ALEN - map span for a sequence of bytes. 跳过一块bytes
#define EFF_APOS(_p) ((_p) >> EFF_MAP_SCALE2)
#define EFF_REM(_x) ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
#define EFF_ALEN(_l) (EFF_APOS(_l) + !!EFF_REM(_l))
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l)-1) - EFF_APOS(_p) + 1)

    /* Initialize effector map for the next step (see comments below). Always
       flag first and last byte as doing something. */
    //数组的大小是 EFF_ALEN(len) （EFF_ALEN是一个宏定义的函数），数组元素只有 0/1 两种值,很明显是用来标记
    eff_map = ck_alloc(EFF_ALEN(len)); // len来自于队列当前结点queue_cur的成员len，是input length（输入长度），所以这里分配给eff_map的大小是 (文件大小/8) 向下取整，这里的 8 = 2^EFF_MAP_SCALE2。比如文件17bytes，那么这里的EFF_ALEN(_l)就是3。
    eff_map[0] = 1;

    if (EFF_APOS(len - 1) != 0)
    {
        eff_map[EFF_APOS(len - 1)] = 1;
        eff_cnt++;
    }

    /* Walking byte. */
    //设置stage_name为bitflip 8/8，以字节为单位，直接通过和0xff异或运算去翻转整个字节的位，然后执行一次，并记录
    stage_name = "bitflip 8/8";
    stage_short = "flip8";
    stage_max = len;

    orig_hit_cnt = new_hit_cnt;

    for (stage_cur = 0; stage_cur < stage_max; stage_cur++)
    {

        stage_cur_byte = stage_cur;

        out_buf[stage_cur] ^= 0xFF;
        // common_fuzz_stuff执行变异后的结果，然后还原
        if (common_fuzz_stuff(argv, out_buf, len))
            goto abandon_entry;

        /* We also use this stage to pull off a simple trick: we identify
           bytes that seem to have no effect on the current execution path
           even when fully flipped - and we skip them during more expensive
           deterministic stages, such as arithmetics or known ints. */

        if (!eff_map[EFF_APOS(stage_cur)])
        {

            u32 cksum;

            /* If in dumb mode or if the file is very short, just flag everything
               without wasting time on checksums. */

            if (!dumb_mode && len >= EFF_MIN_LEN)
                cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
            else
                cksum = ~queue_cur->exec_cksum;

            if (cksum != queue_cur->exec_cksum)
            {
                eff_map[EFF_APOS(stage_cur)] = 1;
                eff_cnt++;
            }
        }

        out_buf[stage_cur] ^= 0xFF;
    }

    /* If the effector map is more than EFF_MAX_PERC dense, just flag the
       whole thing as worth fuzzing, since we wouldn't be saving much time
       anyway. */

    if (eff_cnt != EFF_ALEN(len) &&
        eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC)
    {

        memset(eff_map, 1, EFF_ALEN(len));

        blocks_eff_select += EFF_ALEN(len);
    }
    else
    {

        blocks_eff_select += eff_cnt;
    }

    blocks_eff_total += EFF_ALEN(len);

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP8] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FLIP8] += stage_max;

    /* Two walking bytes. */
    //设置stage_name为bitflip 16/8，设置stage_max为len - 1，以字为单位和0xffff进行亦或运算，去翻转相邻的两个字节(即一个字的)的位
    if (len < 2)
        goto skip_bitflip;

    stage_name = "bitflip 16/8";
    stage_short = "flip16";
    stage_cur = 0;
    stage_max = len - 1;

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len - 1; i++)
    {

        /* Let's consult the effector map... */
        //这里要注意在翻转之前会先检查eff_map里对应于这两个字节的标志是否为0，如果为0，则这两个字节是无效的数据，stage_max减一，然后开始变异下一个字
        if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)])
        {
            stage_max--;
            continue;
        }

        stage_cur_byte = i;

        *(u16 *)(out_buf + i) ^= 0xFFFF;
        // common_fuzz_stuff执行变异后的结果，然后还原
        if (common_fuzz_stuff(argv, out_buf, len))
            goto abandon_entry;
        stage_cur++;

        *(u16 *)(out_buf + i) ^= 0xFFFF;
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP16] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FLIP16] += stage_max;

    if (len < 4)
        goto skip_bitflip;

    /* Four walking bytes. */
    //设置stage_name为bitflip 32/8，然后设置stage_max为len - 3，以双字为单位，直接通过和0xffffffff亦或运算去相邻四个字节的位，然后执行一次，并记录
    stage_name = "bitflip 32/8";
    stage_short = "flip32";
    stage_cur = 0;
    stage_max = len - 3;

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len - 3; i++)
    {

        /* Let's consult the effector map... */
        //在每次翻转之前会检查eff_map里对应于这四个字节的标志是否为0，如果是0，则这两个字节是无效的数据，stage_max减一，然后开始变异下一组双字
        if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
            !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)])
        {
            stage_max--;
            continue;
        }

        stage_cur_byte = i;

        *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;

        if (common_fuzz_stuff(argv, out_buf, len))
            goto abandon_entry;
        stage_cur++;

        *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_FLIP32] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_FLIP32] += stage_max;

skip_bitflip:

    if (no_arith)
        goto skip_arith;

    //在bitflip变异全部进行完成后，便进入下一个阶段：arithmetic

    /**********************
     * ARITHMETIC INC/DEC *
     **********************/
    //整数加/减算术运算
    //加减变异的上限，在config.h中的宏ARITH_MAX定义，默认为35，如果需要修改此值，在头文件中修改完之后，要进行编译才会生效。所以，对目标整数会进行+1, +2, …, +35, -1, -2, …, -35的变异。特别地，由于整数存在大端序和小端序两种表示方式，AFL会贴心地对这两种整数表示方式都进行变异
    //此外，AFL还会智能地跳过某些arithmetic变异。第一种情况就是前面提到的effector map：如果一个整数的所有bytes都被判断为“无效”，那么就跳过对整数的变异。第二种情况是之前bitflip已经生成过的变异：如果加/减某个数后，其效果与之前的某种bitflip相同，那么这次变异肯定在上一个阶段已经执行过了，此次便不会再执行
    //由于整数存在大端序和小端序两种表示，AFL会对这两种表示方式都进行变异。
    //前面也提到过AFL设计的巧妙之处，AFL尽力不浪费每一个变异，也会尽力让变异不冗余，从而达到快速高效的目标。AFL会跳过某些arithmetic变异：
    //在 eff_map 数组中对byte进行了 0/1 标记，如果一个整数的所有 bytes 都被判为无效，那么就认为整数无效，跳过此数的变异；
    //如果加减某数之后效果与之前某bitflip效果相同，认为此次变异在上一阶段已经执行过，此次不再执行；
    /* 8-bit arithmetics. */
    // arith 8/8，每次对8个bit进行加减运算，按照每8个bit的步长从头开始，即对文件的每个byte进行整数加减变异
    stage_name = "arith 8/8"; //当前进行的状态，这个在fuzz的时候用来在状态栏展示
    stage_short = "arith8";   //同上，是简短的状态名
    stage_cur = 0;
    stage_max = 2 * len * ARITH_MAX;
    /*ARITH_MAX就是加减变异的最大值限制35，
      文件大小len bytes，
      然后进行 +/- 操作乘以2，
      每个byte要进行的 +/- 操作各35次，
      所以这个stage_max意思就是将要进行多少次变异，但是之后要是没有进行有效变异就要给减去*/

    stage_val_type = STAGE_VAL_LE;

    orig_hit_cnt = new_hit_cnt; //暂存用于最后的计算

    for (i = 0; i < len; i++)
    {

        u8 orig = out_buf[i];

        /* Let's consult the effector map... */
        //如果当前i byte在eff_map对应位置是0，就跳过此次循环，进入for循环的下一次
        //并且此byte对应的变异无效，所以要减 2*ARITH_MAX

        if (!eff_map[EFF_APOS(i)])
        {
            stage_max -= 2 * ARITH_MAX;
            continue;
        }

        stage_cur_byte = i; //当前byte

        for (j = 1; j <= ARITH_MAX; j++)
        {

            u8 r = orig ^ (orig + j);

            /* Do arithmetic operations only if the result couldn't be a product
               of a bitflip. */
            //只有当arithmetic变异跟bitflip变异不重合时才会进行
            if (!could_be_bitflip(r))
            { //判断函数就是对是否重合进行判断的

                stage_cur_val = j;
                out_buf[i] = orig + j;

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;
            }
            else
                stage_max--; //如果没有进行变异，stage_max减一，因为这里属于无效操作

            r = orig ^ (orig - j);

            if (!could_be_bitflip(r))
            {

                stage_cur_val = -j;
                out_buf[i] = orig - j;

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;
            }
            else
                stage_max--;

            out_buf[i] = orig;
        }
    }

    new_hit_cnt = queued_paths + unique_crashes; //如果8/8期间有新crash的话会加到这里

    stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt; //这期间增加了的
    stage_cycles[STAGE_ARITH8] += stage_max;                 //如果之前没有有效变异的话stage_max这里就已经变成0了

    /* 16-bit arithmetics, both endians. */
    //每次对16个bit进行加减运算，按照每8个bit的步长从头开始，即对文件的每个word进行整数加减变异
    if (len < 2)
        goto skip_arith;

    stage_name = "arith 16/8";
    stage_short = "arith16";
    stage_cur = 0;
    stage_max = 4 * (len - 1) * ARITH_MAX;

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len - 1; i++)
    {

        u16 orig = *(u16 *)(out_buf + i);

        /* Let's consult the effector map... */

        if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)])
        {
            stage_max -= 4 * ARITH_MAX;
            continue;
        }

        stage_cur_byte = i;

        for (j = 1; j <= ARITH_MAX; j++)
        {

            u16 r1 = orig ^ (orig + j),
                r2 = orig ^ (orig - j),
                r3 = orig ^ SWAP16(SWAP16(orig) + j),
                r4 = orig ^ SWAP16(SWAP16(orig) - j);

            /* Try little endian addition and subtraction first. Do it only
               if the operation would affect more than one byte (hence the
               & 0xff overflow checks) and if it couldn't be a product of
               a bitflip. */

            stage_val_type = STAGE_VAL_LE;

            if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1))
            {

                stage_cur_val = j;
                *(u16 *)(out_buf + i) = orig + j;

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;
            }
            else
                stage_max--;

            if ((orig & 0xff) < j && !could_be_bitflip(r2))
            {

                stage_cur_val = -j;
                *(u16 *)(out_buf + i) = orig - j;

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;
            }
            else
                stage_max--;

            /* Big endian comes next. Same deal. */

            stage_val_type = STAGE_VAL_BE;

            if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3))
            {

                stage_cur_val = j;
                *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) + j);

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;
            }
            else
                stage_max--;

            if ((orig >> 8) < j && !could_be_bitflip(r4))
            {

                stage_cur_val = -j;
                *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) - j);

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;
            }
            else
                stage_max--;

            *(u16 *)(out_buf + i) = orig;
        }
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_ARITH16] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_ARITH16] += stage_max;

    /* 32-bit arithmetics, both endians. */
    //每次对32个bit进行加减运算，按照每8个bit的步长从头开始，即对文件的每个dword进行整数加减变异
    if (len < 4)
        goto skip_arith;

    stage_name = "arith 32/8";
    stage_short = "arith32";
    stage_cur = 0;
    stage_max = 4 * (len - 3) * ARITH_MAX;

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len - 3; i++)
    {

        u32 orig = *(u32 *)(out_buf + i);

        /* Let's consult the effector map... */

        if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
            !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)])
        {
            stage_max -= 4 * ARITH_MAX;
            continue;
        }

        stage_cur_byte = i;

        for (j = 1; j <= ARITH_MAX; j++)
        {

            u32 r1 = orig ^ (orig + j),
                r2 = orig ^ (orig - j),
                r3 = orig ^ SWAP32(SWAP32(orig) + j),
                r4 = orig ^ SWAP32(SWAP32(orig) - j);

            /* Little endian first. Same deal as with 16-bit: we only want to
               try if the operation would have effect on more than two bytes. */

            stage_val_type = STAGE_VAL_LE;

            if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1))
            {

                stage_cur_val = j;
                *(u32 *)(out_buf + i) = orig + j;

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;
            }
            else
                stage_max--;

            if ((orig & 0xffff) < j && !could_be_bitflip(r2))
            {

                stage_cur_val = -j;
                *(u32 *)(out_buf + i) = orig - j;

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;
            }
            else
                stage_max--;

            /* Big endian next. */

            stage_val_type = STAGE_VAL_BE;

            if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3))
            {

                stage_cur_val = j;
                *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) + j);

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;
            }
            else
                stage_max--;

            if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4))
            {

                stage_cur_val = -j;
                *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) - j);

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;
            }
            else
                stage_max--;

            *(u32 *)(out_buf + i) = orig;
        }
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_ARITH32] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_ARITH32] += stage_max;

skip_arith:

    /**********************
     * INTERESTING VALUES *
     **********************/
    //把一些特殊内容替换到原文件中；用于替换的”interesting values”，是AFL预设的一些比较特殊的数,这些数的定义在config.h文件中，基本
    //是些会造成溢出的数值。与前面的思想相同的，本着“避免浪费，减少消耗”的原则，eff_map数组中已经判定无效的就此轮跳过；如果 interesting value 达到
    //的效果跟 bitflip 或者 arithmetic 效果相同，也被认为是重复消耗，跳过。

    //每次对8个bit进替换，按照每8个bit的步长从头开始，即对文件的每个byte进行替换
    stage_name = "interest 8/8";
    stage_short = "int8";
    stage_cur = 0;
    stage_max = len * sizeof(interesting_8);

    stage_val_type = STAGE_VAL_LE;

    orig_hit_cnt = new_hit_cnt;

    /* Setting 8-bit integers. */

    for (i = 0; i < len; i++)
    {

        u8 orig = out_buf[i];

        /* Let's consult the effector map... */

        if (!eff_map[EFF_APOS(i)])
        {
            stage_max -= sizeof(interesting_8);
            continue;
        }

        stage_cur_byte = i;

        for (j = 0; j < sizeof(interesting_8); j++)
        {

            /* Skip if the value could be a product of bitflips or arithmetics. */

            if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
                could_be_arith(orig, (u8)interesting_8[j], 1))
            {
                stage_max--;
                continue;
            }

            stage_cur_val = interesting_8[j];
            out_buf[i] = interesting_8[j];

            if (common_fuzz_stuff(argv, out_buf, len))
                goto abandon_entry;

            out_buf[i] = orig;
            stage_cur++;
        }
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_INTEREST8] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_INTEREST8] += stage_max;

    /* Setting 16-bit integers, both endians. */
    //每次对16个bit进替换，按照每8个bit的步长从头开始，即对文件的每个word进行替换
    if (no_arith || len < 2)
        goto skip_interest;

    stage_name = "interest 16/8";
    stage_short = "int16";
    stage_cur = 0;
    stage_max = 2 * (len - 1) * (sizeof(interesting_16) >> 1);

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len - 1; i++)
    {

        u16 orig = *(u16 *)(out_buf + i);

        /* Let's consult the effector map... */

        if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)])
        {
            stage_max -= sizeof(interesting_16);
            continue;
        }

        stage_cur_byte = i;

        for (j = 0; j < sizeof(interesting_16) / 2; j++)
        {

            stage_cur_val = interesting_16[j];

            /* Skip if this could be a product of a bitflip, arithmetics,
               or single-byte interesting value insertion. */

            if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
                !could_be_arith(orig, (u16)interesting_16[j], 2) &&
                !could_be_interest(orig, (u16)interesting_16[j], 2, 0))
            {

                stage_val_type = STAGE_VAL_LE;

                *(u16 *)(out_buf + i) = interesting_16[j];

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;
            }
            else
                stage_max--;

            if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
                !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
                !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
                !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1))
            {

                stage_val_type = STAGE_VAL_BE;

                *(u16 *)(out_buf + i) = SWAP16(interesting_16[j]);
                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;
            }
            else
                stage_max--;
        }

        *(u16 *)(out_buf + i) = orig;
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_INTEREST16] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_INTEREST16] += stage_max;

    if (len < 4)
        goto skip_interest;

    /* Setting 32-bit integers, both endians. */
    //每次对32个bit进替换，按照每8个bit的步长从头开始，即对文件的每个dword进行替换
    stage_name = "interest 32/8";
    stage_short = "int32";
    stage_cur = 0;
    stage_max = 2 * (len - 3) * (sizeof(interesting_32) >> 2);

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len - 3; i++)
    {

        u32 orig = *(u32 *)(out_buf + i);

        /* Let's consult the effector map... */

        if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
            !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)])
        {
            stage_max -= sizeof(interesting_32) >> 1;
            continue;
        }

        stage_cur_byte = i;

        for (j = 0; j < sizeof(interesting_32) / 4; j++)
        {

            stage_cur_val = interesting_32[j];

            /* Skip if this could be a product of a bitflip, arithmetics,
               or word interesting value insertion. */

            if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
                !could_be_arith(orig, interesting_32[j], 4) &&
                !could_be_interest(orig, interesting_32[j], 4, 0))
            {

                stage_val_type = STAGE_VAL_LE;

                *(u32 *)(out_buf + i) = interesting_32[j];

                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;
            }
            else
                stage_max--;

            if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
                !could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
                !could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
                !could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1))
            {

                stage_val_type = STAGE_VAL_BE;

                *(u32 *)(out_buf + i) = SWAP32(interesting_32[j]);
                if (common_fuzz_stuff(argv, out_buf, len))
                    goto abandon_entry;
                stage_cur++;
            }
            else
                stage_max--;
        }

        *(u32 *)(out_buf + i) = orig;
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_INTEREST32] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_INTEREST32] += stage_max;

skip_interest:

    /********************
     * DICTIONARY STUFF *
     ********************/
    //进入到这个阶段，就接近deterministic fuzzing的尾声了
    //把自动生成或用户提供的token替换/插入到原文件中。
    // “用户提供的tokens” 是一开始通过 -x 选项指定的，如果没有则跳过对应的子阶段；“自动检测的tokens” 是第一个阶段 bitflip 生成的。

    if (!extras_cnt)
        goto skip_user_extras;

    /* Overwrite with user-supplied extras. */
    //-x的时候，用户提供的，直接覆盖
    //从头开始,将用户提供的tokens依次替换到原文件中,stage_max为extras_cnt * len
    stage_name = "user extras (over)"; //从头开始，将用户提供的tokens依次替换到原文件中
    stage_short = "ext_UO";
    stage_cur = 0;
    stage_max = extras_cnt * len;

    stage_val_type = STAGE_VAL_NONE;

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len; i++)
    {

        u32 last_len = 0;

        stage_cur_byte = i;

        /* Extras are sorted by size, from smallest to largest. This means
           that we don't have to worry about restoring the buffer in
           between writes at a particular offset determined by the outer
           loop. */

        for (j = 0; j < extras_cnt; j++)
        {

            /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
               skip them if there's no room to insert the payload, if the token
               is redundant, or if its entire span has no bytes set in the effector
               map. */

            if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
                extras[j].len > len - i ||
                !memcmp(extras[j].data, out_buf + i, extras[j].len) ||
                !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len)))
            {

                stage_max--;
                continue;
            }

            last_len = extras[j].len;
            memcpy(out_buf + i, extras[j].data, last_len);

            if (common_fuzz_stuff(argv, out_buf, len))
                goto abandon_entry;

            stage_cur++;
        }

        /* Restore all the clobbered memory. */
        memcpy(out_buf + i, in_buf + i, last_len);
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_EXTRAS_UO] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_EXTRAS_UO] += stage_max;

    /* Insertion of user-supplied extras. */
    //从头开始,将-x用户提供的tokens依次插入到原文件(种子)中,stage_max为extras_cnt * len
    stage_name = "user extras (insert)"; //从头开始，将用户提供的tokens依次插入到原文件中
    stage_short = "ext_UI";
    stage_cur = 0;
    stage_max = extras_cnt * len;

    orig_hit_cnt = new_hit_cnt;

    ex_tmp = ck_alloc(len + MAX_DICT_FILE);

    for (i = 0; i <= len; i++)
    {

        stage_cur_byte = i;

        for (j = 0; j < extras_cnt; j++)
        {

            if (len + extras[j].len > MAX_FILE)
            {
                stage_max--;
                continue;
            }

            /* Insert token */
            memcpy(ex_tmp + i, extras[j].data, extras[j].len);

            /* Copy tail */
            memcpy(ex_tmp + i + extras[j].len, out_buf + i, len - i);

            if (common_fuzz_stuff(argv, ex_tmp, len + extras[j].len))
            {
                ck_free(ex_tmp);
                goto abandon_entry;
            }

            stage_cur++;
        }

        /* Copy head */
        ex_tmp[i] = out_buf[i];
    }

    ck_free(ex_tmp);

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_EXTRAS_UI] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_EXTRAS_UI] += stage_max;

skip_user_extras:
    //用自动生成的字典，只提供overwrite的形式
    if (!a_extras_cnt)
        goto skip_extras;

    //从头开始,将自动检测的tokens依次替换到原文件中,stage_max为MIN(a_extras_cnt, USE_AUTO_EXTRAS) * len
    stage_name = "auto extras (over)"; //从头开始，将自动检测到的tokens依次替换到原文件中
    stage_short = "ext_AO";
    stage_cur = 0;
    stage_max = MIN(a_extras_cnt, USE_AUTO_EXTRAS) * len;

    stage_val_type = STAGE_VAL_NONE;

    orig_hit_cnt = new_hit_cnt;

    for (i = 0; i < len; i++)
    {

        u32 last_len = 0;

        stage_cur_byte = i;

        for (j = 0; j < MIN(a_extras_cnt, USE_AUTO_EXTRAS); j++)
        {

            /* See the comment in the earlier code; extras are sorted by size. */

            if (a_extras[j].len > len - i ||
                !memcmp(a_extras[j].data, out_buf + i, a_extras[j].len) ||
                !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, a_extras[j].len)))
            {

                stage_max--;
                continue;
            }

            last_len = a_extras[j].len;
            memcpy(out_buf + i, a_extras[j].data, last_len);

            if (common_fuzz_stuff(argv, out_buf, len))
                goto abandon_entry;

            stage_cur++;
        }

        /* Restore all the clobbered memory. */
        memcpy(out_buf + i, in_buf + i, last_len);
    }

    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_EXTRAS_AO] += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_EXTRAS_AO] += stage_max;

skip_extras:

    /* If we made this to here without jumping to havoc_stage or abandon_entry,
       we're properly done with deterministic steps and can mark it as such
       in the .state/ directory. */

    if (!queue_cur->passed_det)
        mark_as_det_done(queue_cur);

    /****************
     * RANDOM HAVOC *
     ****************/
    // havoc，顾名思义，是充满了各种随机生成的变异，是对原文件的“大破坏”。具体来说，havoc包含了对原文件的多轮变异，每一轮都是将多种方式组合（stacked）而成
    //对于非dumb mode的主fuzzer来说，完成了上述deterministic fuzzing后，便进入了充满随机性的这一阶段；对于dumb mode或者从fuzzer来说，则是直接从这一阶段开始
    /* 随即处理阶段，因为前面的阶段耗时长，所以，从第二轮开始，就直接跳到此处进行变异  */
havoc_stage:

    stage_cur_byte = -1;

    /* The havoc stage mutation code is also invoked when splicing files; if the
       splice_cycle variable is set, generate different descriptions and such. */

    if (!splice_cycle)
    {

        stage_name = "havoc";
        stage_short = "havoc";
        stage_max = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                    perf_score / havoc_div / 100;
    }
    else
    {

        static u8 tmp[32];

        perf_score = orig_perf;

        sprintf(tmp, "splice %u", splice_cycle);
        stage_name = tmp;
        stage_short = "splice";
        stage_max = SPLICE_HAVOC * perf_score / havoc_div / 100;
    }

    if (stage_max < HAVOC_MIN)
        stage_max = HAVOC_MIN;

    temp_len = len;

    orig_hit_cnt = queued_paths + unique_crashes;

    havoc_queued = queued_paths;

    /* We essentially just do several thousand runs (depending on perf_score)
       where we take the input file and make random stacked tweaks. */

    for (stage_cur = 0; stage_cur < stage_max; stage_cur++)
    {

        u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));

        stage_cur_val = use_stacking;
        // AFL会生成一个随机数（可能是use_stacking)，作为变异组合的数量，并根据这个数量，每次从上面那些方式中随机选取一个（可以参考高中数学的有放回摸球），依次作用到文件上（能量分配？？？？？）
        for (i = 0; i < use_stacking; i++)
        {

            switch (UR(15 + ((extras_cnt + a_extras_cnt) ? 2 : 0)))
            {

            case 0:

                /* Flip a single bit somewhere. Spooky! */
                //随机选取某个bit进行翻转
                FLIP_BIT(out_buf, UR(temp_len << 3));
                break;

            case 1:

                /* Set byte to interesting value. */
                //随机选取某个byte，将其设置为随机的interesting value
                out_buf[UR(temp_len)] = interesting_8[UR(sizeof(interesting_8))];
                break;

            case 2:

                /* Set word to interesting value, randomly choosing endian. */
                //随机选取某个word，并随机选取大、小端序，将其设置为随机的interesting value
                if (temp_len < 2)
                    break;

                if (UR(2))
                {

                    *(u16 *)(out_buf + UR(temp_len - 1)) =
                        interesting_16[UR(sizeof(interesting_16) >> 1)];
                }
                else
                {

                    *(u16 *)(out_buf + UR(temp_len - 1)) = SWAP16(
                        interesting_16[UR(sizeof(interesting_16) >> 1)]);
                }

                break;

            case 3:

                /* Set dword to interesting value, randomly choosing endian. */
                //随机选取某个dword，并随机选取大、小端序，将其设置为随机的interesting value
                if (temp_len < 4)
                    break;

                if (UR(2))
                {

                    *(u32 *)(out_buf + UR(temp_len - 3)) =
                        interesting_32[UR(sizeof(interesting_32) >> 2)];
                }
                else
                {

                    *(u32 *)(out_buf + UR(temp_len - 3)) = SWAP32(
                        interesting_32[UR(sizeof(interesting_32) >> 2)]);
                }

                break;

            case 4:

                /* Randomly subtract from byte. */
                //随机选取某个byte，对其减去一个随机数
                out_buf[UR(temp_len)] -= 1 + UR(ARITH_MAX);
                break;

            case 5:

                /* Randomly add to byte. */
                //随机选取某个byte，对其加上一个随机数
                out_buf[UR(temp_len)] += 1 + UR(ARITH_MAX);
                break;

            case 6:

                /* Randomly subtract from word, random endian. */
                //随机选取某个word，并随机选取大、小端序，对其减去一个随机数
                if (temp_len < 2)
                    break;

                if (UR(2))
                {

                    u32 pos = UR(temp_len - 1);

                    *(u16 *)(out_buf + pos) -= 1 + UR(ARITH_MAX);
                }
                else
                {

                    u32 pos = UR(temp_len - 1);
                    u16 num = 1 + UR(ARITH_MAX);

                    *(u16 *)(out_buf + pos) =
                        SWAP16(SWAP16(*(u16 *)(out_buf + pos)) - num);
                }

                break;

            case 7:

                /* Randomly add to word, random endian. */
                //随机选取某个word，并随机选取大、小端序，对其加上一个随机数
                if (temp_len < 2)
                    break;

                if (UR(2))
                {

                    u32 pos = UR(temp_len - 1);

                    *(u16 *)(out_buf + pos) += 1 + UR(ARITH_MAX);
                }
                else
                {

                    u32 pos = UR(temp_len - 1);
                    u16 num = 1 + UR(ARITH_MAX);

                    *(u16 *)(out_buf + pos) =
                        SWAP16(SWAP16(*(u16 *)(out_buf + pos)) + num);
                }

                break;

            case 8:

                /* Randomly subtract from dword, random endian. */
                //随机选取某个dword，并随机选取大、小端序，对其减去一个随机数
                if (temp_len < 4)
                    break;

                if (UR(2))
                {

                    u32 pos = UR(temp_len - 3);

                    *(u32 *)(out_buf + pos) -= 1 + UR(ARITH_MAX);
                }
                else
                {

                    u32 pos = UR(temp_len - 3);
                    u32 num = 1 + UR(ARITH_MAX);

                    *(u32 *)(out_buf + pos) =
                        SWAP32(SWAP32(*(u32 *)(out_buf + pos)) - num);
                }

                break;

            case 9:

                /* Randomly add to dword, random endian. */
                //随机选取某个dword，并随机选取大、小端序，对其加上一个随机数
                if (temp_len < 4)
                    break;

                if (UR(2))
                {

                    u32 pos = UR(temp_len - 3);

                    *(u32 *)(out_buf + pos) += 1 + UR(ARITH_MAX);
                }
                else
                {

                    u32 pos = UR(temp_len - 3);
                    u32 num = 1 + UR(ARITH_MAX);

                    *(u32 *)(out_buf + pos) =
                        SWAP32(SWAP32(*(u32 *)(out_buf + pos)) + num);
                }

                break;

            case 10:

                /* Just set a random byte to a random value. Because,
                   why not. We use XOR with 1-255 to eliminate the
                   possibility of a no-op. */
                //随机选取某个byte，将其设置为随机数
                out_buf[UR(temp_len)] ^= 1 + UR(255);
                break;

            case 11 ... 12:
            {

                /* Delete bytes. We're making this a bit more likely
                   than insertion (the next option) in hopes of keeping
                   files reasonably small. */
                //随机删除一段bytes
                u32 del_from, del_len;

                if (temp_len < 2)
                    break;

                /* Don't delete too much. */

                del_len = choose_block_len(temp_len - 1);

                del_from = UR(temp_len - del_len + 1);

                memmove(out_buf + del_from, out_buf + del_from + del_len,
                        temp_len - del_from - del_len);

                temp_len -= del_len;

                break;
            }

            case 13:

                if (temp_len + HAVOC_BLK_XL < MAX_FILE)
                {

                    /* Clone bytes (75%) or insert a block of constant bytes (25%). */
                    //随机选取一个位置，插入一段随机长度的内容，其中75%的概率是插入原文中随机位置的内容，25%的概率是插入一段随机选取的数
                    u8 actually_clone = UR(4);
                    u32 clone_from, clone_to, clone_len;
                    u8 *new_buf;

                    if (actually_clone)
                    {

                        clone_len = choose_block_len(temp_len);
                        clone_from = UR(temp_len - clone_len + 1);
                    }
                    else
                    {

                        clone_len = choose_block_len(HAVOC_BLK_XL);
                        clone_from = 0;
                    }

                    clone_to = UR(temp_len);

                    new_buf = ck_alloc_nozero(temp_len + clone_len);

                    /* Head */

                    memcpy(new_buf, out_buf, clone_to);

                    /* Inserted part */

                    if (actually_clone)
                        memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);
                    else
                        memset(new_buf + clone_to,
                               UR(2) ? UR(256) : out_buf[UR(temp_len)], clone_len);

                    /* Tail */
                    memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                           temp_len - clone_to);

                    ck_free(out_buf);
                    out_buf = new_buf;
                    temp_len += clone_len;
                }

                break;

            case 14:
            {

                /* Overwrite bytes with a randomly selected chunk (75%) or fixed
                   bytes (25%). */
                //随机选取一个位置，替换为一段随机长度的内容，其中75%的概率是替换成原文中随机位置的内容，25%的概率是替换成一段随机选取的数
                u32 copy_from, copy_to, copy_len;

                if (temp_len < 2)
                    break;

                copy_len = choose_block_len(temp_len - 1);

                copy_from = UR(temp_len - copy_len + 1);
                copy_to = UR(temp_len - copy_len + 1);

                if (UR(4))
                {

                    if (copy_from != copy_to)
                        memmove(out_buf + copy_to, out_buf + copy_from, copy_len);
                }
                else
                    memset(out_buf + copy_to,
                           UR(2) ? UR(256) : out_buf[UR(temp_len)], copy_len);

                break;
            }

            /* Values 15 and 16 can be selected only if there are any extras
               present in the dictionaries. */
            case 15:
            {
                //随机选取一个位置，用随机选取的token（用户提供的或自动生成的）替换
                /* Overwrite bytes with an extra. */

                if (!extras_cnt || (a_extras_cnt && UR(2)))
                {

                    /* No user-specified extras or odds in our favor. Let's use an
                       auto-detected one. */

                    u32 use_extra = UR(a_extras_cnt);
                    u32 extra_len = a_extras[use_extra].len;
                    u32 insert_at;

                    if (extra_len > temp_len)
                        break;

                    insert_at = UR(temp_len - extra_len + 1);
                    memcpy(out_buf + insert_at, a_extras[use_extra].data, extra_len);
                }
                else
                {

                    /* No auto extras or odds in our favor. Use the dictionary. */

                    u32 use_extra = UR(extras_cnt);
                    u32 extra_len = extras[use_extra].len;
                    u32 insert_at;

                    if (extra_len > temp_len)
                        break;

                    insert_at = UR(temp_len - extra_len + 1);
                    memcpy(out_buf + insert_at, extras[use_extra].data, extra_len);
                }

                break;
            }

            case 16:
            {

                u32 use_extra, extra_len, insert_at = UR(temp_len + 1);
                u8 *new_buf;
                //随机选取一个位置，用随机选取的token（用户提供的或自动生成的）插入
                /* Insert an extra. Do the same dice-rolling stuff as for the
                   previous case. */

                if (!extras_cnt || (a_extras_cnt && UR(2)))
                {

                    use_extra = UR(a_extras_cnt);
                    extra_len = a_extras[use_extra].len;

                    if (temp_len + extra_len >= MAX_FILE)
                        break;

                    new_buf = ck_alloc_nozero(temp_len + extra_len);

                    /* Head */
                    memcpy(new_buf, out_buf, insert_at);

                    /* Inserted part */
                    memcpy(new_buf + insert_at, a_extras[use_extra].data, extra_len);
                }
                else
                {

                    use_extra = UR(extras_cnt);
                    extra_len = extras[use_extra].len;

                    if (temp_len + extra_len >= MAX_FILE)
                        break;

                    new_buf = ck_alloc_nozero(temp_len + extra_len);

                    /* Head */
                    memcpy(new_buf, out_buf, insert_at);

                    /* Inserted part */
                    memcpy(new_buf + insert_at, extras[use_extra].data, extra_len);
                }

                /* Tail */
                memcpy(new_buf + insert_at + extra_len, out_buf + insert_at,
                       temp_len - insert_at);

                ck_free(out_buf);
                out_buf = new_buf;
                temp_len += extra_len;

                break;
            }
            }
        }

        if (common_fuzz_stuff(argv, out_buf, temp_len))
            goto abandon_entry;

        /* out_buf might have been mangled a bit, so let's restore it to its
           original size and shape. */

        if (temp_len < len)
            out_buf = ck_realloc(out_buf, len);
        temp_len = len;
        memcpy(out_buf, in_buf, len);

        /* If we're finding new stuff, let's run for a bit longer, limits
           permitting. */

        if (queued_paths != havoc_queued)
        {

            if (perf_score <= HAVOC_MAX_MULT * 100)
            {
                stage_max *= 2;
                perf_score *= 2;
            }

            havoc_queued = queued_paths;
        }
    }

    new_hit_cnt = queued_paths + unique_crashes;

    if (!splice_cycle)
    {
        stage_finds[STAGE_HAVOC] += new_hit_cnt - orig_hit_cnt;
        stage_cycles[STAGE_HAVOC] += stage_max;
    }
    else
    {
        stage_finds[STAGE_SPLICE] += new_hit_cnt - orig_hit_cnt;
        stage_cycles[STAGE_SPLICE] += stage_max;
    }

#ifndef IGNORE_FINDS

    /************
     * SPLICING *
     ************/
    //中文意思是“绞接”，此阶段会将两个文件拼接起来得到一个新的文件
    /* This is a last-resort strategy triggered by a full round with no findings.
       It takes the current input file, randomly selects another input, and
       splices them together at some offset, then relies on the havoc
       code to mutate that blob. */
    /*
      AFL会在文件队列中随机选择一个文件与当前文件进行对比，如果差别不大就重新再选；如果差异明显，就随机选取位置两个文件都一切两半。
      最后将当前文件的头与随机文件的尾拼接起来得到新文件。当然了本着“减少消耗”的原则拼接后的文件应该与上一个文件对比，如果未发生变化应该过滤掉。
    */
retry_splicing:

    if (use_splicing && splice_cycle++ < SPLICE_CYCLES &&
        queued_paths > 1 && queue_cur->len > 1)
    {

        struct queue_entry *target;
        u32 tid, split_at;
        u8 *new_buf;
        s32 f_diff, l_diff;

        /* First of all, if we've modified in_buf for havoc, let's clean that
           up... */

        if (in_buf != orig_in)
        {
            ck_free(in_buf);
            in_buf = orig_in;
            len = queue_cur->len;
        }

        /* Pick a random queue entry and seek to it. Don't splice with yourself. */

        do
        {
            tid = UR(queued_paths);
        } while (tid == current_entry);

        splicing_with = tid;
        target = queue;

        while (tid >= 100)
        {
            target = target->next_100;
            tid -= 100;
        }
        while (tid--)
            target = target->next;

        /* Make sure that the target has a reasonable length. */

        while (target && (target->len < 2 || target == queue_cur))
        {
            target = target->next;
            splicing_with++;
        }

        if (!target)
            goto retry_splicing;

        /* Read the testcase into a new buffer. */

        fd = open(target->fname, O_RDONLY);

        if (fd < 0)
            PFATAL("Unable to open '%s'", target->fname);

        new_buf = ck_alloc_nozero(target->len);

        ck_read(fd, new_buf, target->len, target->fname);

        close(fd);

        /* Find a suitable splicing location, somewhere between the first and
           the last differing byte. Bail out if the difference is just a single
           byte or so. */

        locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

        if (f_diff < 0 || l_diff < 2 || f_diff == l_diff)
        {
            ck_free(new_buf);
            goto retry_splicing;
        }

        /* Split somewhere between the first and last differing byte. */

        split_at = f_diff + UR(l_diff - f_diff);

        /* Do the thing. */

        len = target->len;
        memcpy(new_buf, in_buf, split_at);
        in_buf = new_buf;

        ck_free(out_buf);
        out_buf = ck_alloc_nozero(len);
        memcpy(out_buf, in_buf, len);

        goto havoc_stage;
    }

#endif /* !IGNORE_FINDS */
       //什么都没发现
    ret_val = 0;

abandon_entry:

    splicing_with = -1;

    /* Update pending_not_fuzzed count if we made it through the calibration
       cycle and have not seen this entry before. */

    if (!stop_soon && !queue_cur->cal_failed && !queue_cur->was_fuzzed)
    {
        queue_cur->was_fuzzed = 1;
        pending_not_fuzzed--;
        if (queue_cur->favored)
            pending_favored--;
    }

    munmap(orig_in, queue_cur->len);

    if (in_buf != orig_in)
        ck_free(in_buf);
    ck_free(out_buf);
    ck_free(eff_map);

    return ret_val;

#undef FLIP_BIT
}

/* Grab interesting test cases from other fuzzers. */
//并行fuzz
//读取其他sync文件夹下的queue文件，然后保存到自己的queue里
//这个函数就是先读取有哪些fuzzer文件夹，然后读取其他fuzzer文件夹下的queue文件夹里的case，并依次执行，如果发现了新path，就保存到自己的queue文件夹里，而且将最后一个sync的case id写入到.synced/其他fuzzer文件夹名文件里，以避免重复运行
static void sync_fuzzers(char **argv)
{

    DIR *sd;
    struct dirent *sd_ent;
    u32 sync_cnt = 0;

    sd = opendir(sync_dir);
    if (!sd)
        PFATAL("Unable to open '%s'", sync_dir);

    stage_max = stage_cur = 0;
    cur_depth = 0;

    /* Look at the entries created for every other fuzzer in the sync directory. */
    // while循环读取该文件夹下的目录和文件
    while ((sd_ent = readdir(sd)))
    {

        static u8 stage_tmp[128];

        DIR *qd;
        struct dirent *qd_ent;
        u8 *qd_path, *qd_synced_path;
        u32 min_accept = 0, next_min_accept;

        s32 id_fd;

        /* Skip dot files and our own output directory. */
        //跳过.开头的文件和sync_id即我们自己的输出文件夹
        if (sd_ent->d_name[0] == '.' || !strcmp(sync_id, sd_ent->d_name))
            continue;

        /* Skip anything that doesn't have a queue/ subdirectory. */

        qd_path = alloc_printf("%s/%s/queue", sync_dir, sd_ent->d_name);

        if (!(qd = opendir(qd_path)))
        {
            ck_free(qd_path);
            continue;
        }

        /* Retrieve the ID of the last seen test case. */

        qd_synced_path = alloc_printf("%s/.synced/%s", out_dir, sd_ent->d_name);

        id_fd = open(qd_synced_path, O_RDWR | O_CREAT, 0600);

        if (id_fd < 0)
            PFATAL("Unable to create '%s'", qd_synced_path);
        //读取out_dir/.synced/sd_ent->d_name文件即id_fd里的前4个字节到min_accept里，设置next_min_accept为min_accept，这个值代表之前从这个文件夹里读取到的最后一个queue的id
        if (read(id_fd, &min_accept, sizeof(u32)) > 0)
            lseek(id_fd, 0, SEEK_SET);

        next_min_accept = min_accept;

        /* Show stats */
        //设置stage_name为sprintf(stage_tmp, "sync %u", ++sync_cnt);，设置stage_cur为0，stage_max为0
        sprintf(stage_tmp, "sync %u", ++sync_cnt);
        stage_name = stage_tmp;
        stage_cur = 0;
        stage_max = 0;

        /* For every file queued by this fuzzer, parse ID and see if we have looked at
           it before; exec a test case if not. */
        //循环读取sync_dir/sd_ent->d_name/queue文件夹里的目录和文件
        while ((qd_ent = readdir(qd)))
        {

            u8 *path;
            s32 fd;
            struct stat st;
            //跳过.开头的文件和标识小于min_accept的文件，因为这些文件应该已经被sync过了
            if (qd_ent->d_name[0] == '.' ||
                sscanf(qd_ent->d_name, CASE_PREFIX "%06u", &syncing_case) != 1 ||
                syncing_case < min_accept)
                continue;

            /* OK, sounds like a new one. Let's give it a try. */
            //如果标识syncing_case大于等于next_min_accept，就设置next_min_accept为syncing_case + 1
            if (syncing_case >= next_min_accept)
                next_min_accept = syncing_case + 1;

            path = alloc_printf("%s/%s", qd_path, qd_ent->d_name);

            /* Allow this to fail in case the other fuzzer is resuming or so... */

            fd = open(path, O_RDONLY);

            if (fd < 0)
            {
                ck_free(path);
                continue;
            }

            if (fstat(fd, &st))
                PFATAL("fstat() failed");

            /* Ignore zero-sized or oversized files. */
            //开始同步这个case
            //如果case大小为0或者大于MAX_FILE(默认是1M),就不进行sync
            if (st.st_size && st.st_size <= MAX_FILE)
            {

                u8 fault;
                // mmap这个文件到内存mem里，然后write_to_testcase(mem, st.st_size),并run_target,然后通过save_if_interesting来决定是否要导入这个文件到自己的queue里，如果发现了新的path，就导入
                u8 *mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

                if (mem == MAP_FAILED)
                    PFATAL("Unable to mmap '%s'", path);

                /* See what happens. We rely on save_if_interesting() to catch major
                   errors and save the test case. */

                write_to_testcase(mem, st.st_size);

                fault = run_target(argv, exec_tmout);

                if (stop_soon)
                    return;

                syncing_party = sd_ent->d_name;
                queued_imported += save_if_interesting(argv, mem, st.st_size, fault); //如果save_if_interesting返回1，queued_imported计数器就加1
                syncing_party = 0;

                munmap(mem, st.st_size);
                // stage_cur计数器加一，如果stage_cur是stats_update_freq的倍数，就刷新一次展示界面
                if (!(stage_cur++ % stats_update_freq))
                    show_stats();
            }

            ck_free(path);
            close(fd);
        }
        //向id_fd写入当前的next_min_accept值
        ck_write(id_fd, &next_min_accept, sizeof(u32), qd_synced_path);

        close(id_fd);
        closedir(qd);
        ck_free(qd_path);
        ck_free(qd_synced_path);
    }

    closedir(sd);
}

/* Handle stop signal (Ctrl-C, etc). */

static void handle_stop_sig(int sig)
{

    stop_soon = 1;

    if (child_pid > 0)
        kill(child_pid, SIGKILL);
    if (forksrv_pid > 0)
        kill(forksrv_pid, SIGKILL);
}

/* Handle skip request (SIGUSR1). */

static void handle_skipreq(int sig)
{

    skip_requested = 1;
}

/* Handle timeout (SIGALRM). */

static void handle_timeout(int sig)
{

    if (child_pid > 0)
    {

        child_timed_out = 1;
        kill(child_pid, SIGKILL);
    }
    else if (child_pid == -1 && forksrv_pid > 0)
    {

        child_timed_out = 1;
        kill(forksrv_pid, SIGKILL);
    }
}

/* Do a PATH search and find target binary to see that it exists and
   isn't a shell script - a common and painful mistake. We also check for
   a valid ELF header and for evidence of AFL instrumentation. */
//检查指定路径要执行的程序是否存在，是否为shell脚本，同时检查elf文件头是否合法及程序是否被插桩
EXP_ST void check_binary(u8 *fname)
{

    u8 *env_path = 0;
    struct stat st;

    s32 fd;
    u8 *f_data;
    u32 f_len = 0;

    ACTF("Validating target binary...");

    if (strchr(fname, '/') || !(env_path = getenv("PATH")))
    {

        target_path = ck_strdup(fname);
        if (stat(target_path, &st) || !S_ISREG(st.st_mode) ||
            !(st.st_mode & 0111) || (f_len = st.st_size) < 4)
            FATAL("Program '%s' not found or not executable", fname);
    }
    else
    {

        while (env_path)
        {

            u8 *cur_elem, *delim = strchr(env_path, ':');

            if (delim)
            {

                cur_elem = ck_alloc(delim - env_path + 1);
                memcpy(cur_elem, env_path, delim - env_path);
                delim++;
            }
            else
                cur_elem = ck_strdup(env_path);

            env_path = delim;

            if (cur_elem[0])
                target_path = alloc_printf("%s/%s", cur_elem, fname);
            else
                target_path = ck_strdup(fname);

            ck_free(cur_elem);

            if (!stat(target_path, &st) && S_ISREG(st.st_mode) &&
                (st.st_mode & 0111) && (f_len = st.st_size) >= 4)
                break;

            ck_free(target_path);
            target_path = 0;
        }

        if (!target_path)
            FATAL("Program '%s' not found or not executable", fname);
    }

    if (getenv("AFL_SKIP_BIN_CHECK"))
        return;

    /* Check for blatant user errors. */

    if ((!strncmp(target_path, "/tmp/", 5) && !strchr(target_path + 5, '/')) ||
        (!strncmp(target_path, "/var/tmp/", 9) && !strchr(target_path + 9, '/')))
        FATAL("Please don't keep binaries in /tmp or /var/tmp");

    fd = open(target_path, O_RDONLY);

    if (fd < 0)
        PFATAL("Unable to open '%s'", target_path);

    f_data = mmap(0, f_len, PROT_READ, MAP_PRIVATE, fd, 0);

    if (f_data == MAP_FAILED)
        PFATAL("Unable to mmap file '%s'", target_path);

    close(fd);

    if (f_data[0] == '#' && f_data[1] == '!')
    {

        SAYF("\n" cLRD "[-] " cRST
             "Oops, the target binary looks like a shell script. Some build systems will\n"
             "    sometimes generate shell stubs for dynamically linked programs; try static\n"
             "    library mode (./configure --disable-shared) if that's the case.\n\n"

             "    Another possible cause is that you are actually trying to use a shell\n"
             "    wrapper around the fuzzed component. Invoking shell can slow down the\n"
             "    fuzzing process by a factor of 20x or more; it's best to write the wrapper\n"
             "    in a compiled language instead.\n");

        FATAL("Program '%s' is a shell script", target_path);
    }

#ifndef __APPLE__

    if (f_data[0] != 0x7f || memcmp(f_data + 1, "ELF", 3))
        FATAL("Program '%s' is not an ELF binary", target_path);

#else

    if (f_data[0] != 0xCF || f_data[1] != 0xFA || f_data[2] != 0xED)
        FATAL("Program '%s' is not a 64-bit Mach-O binary", target_path);

#endif /* ^!__APPLE__ */

    if (!qemu_mode && !dumb_mode &&
        !memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1))
    {

        SAYF("\n" cLRD "[-] " cRST
             "Looks like the target binary is not instrumented! The fuzzer depends on\n"
             "    compile-time instrumentation to isolate interesting test cases while\n"
             "    mutating the input data. For more information, and for tips on how to\n"
             "    instrument binaries, please see %s/README.\n\n"

             "    When source code is not available, you may be able to leverage QEMU\n"
             "    mode support. Consult the README for tips on how to enable this.\n"

             "    (It is also possible to use afl-fuzz as a traditional, \"dumb\" fuzzer.\n"
             "    For that, you can use the -n option - but expect much worse results.)\n",
             doc_path);

        FATAL("No instrumentation detected");
    }

    if (qemu_mode &&
        memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1))
    {

        SAYF("\n" cLRD "[-] " cRST
             "This program appears to be instrumented with afl-gcc, but is being run in\n"
             "    QEMU mode (-Q). This is probably not what you want - this setup will be\n"
             "    slow and offer no practical benefits.\n");

        FATAL("Instrumentation found in -Q mode");
    }

    if (memmem(f_data, f_len, "libasan.so", 10) ||
        memmem(f_data, f_len, "__msan_init", 11))
        uses_asan = 1;

    /* Detect persistent & deferred init signatures in the binary. */

    if (memmem(f_data, f_len, PERSIST_SIG, strlen(PERSIST_SIG) + 1))
    {

        OKF(cPIN "Persistent mode binary detected.");
        setenv(PERSIST_ENV_VAR, "1", 1);
        persistent_mode = 1;
    }
    else if (getenv("AFL_PERSISTENT"))
    {

        WARNF("AFL_PERSISTENT is no longer supported and may misbehave!");
    }

    if (memmem(f_data, f_len, DEFER_SIG, strlen(DEFER_SIG) + 1))
    {

        OKF(cPIN "Deferred forkserver binary detected.");
        setenv(DEFER_ENV_VAR, "1", 1);
        deferred_mode = 1;
    }
    else if (getenv("AFL_DEFER_FORKSRV"))
    {

        WARNF("AFL_DEFER_FORKSRV is no longer supported and may misbehave!");
    }

    if (munmap(f_data, f_len))
        PFATAL("unmap() failed");
}

/* Trim and possibly create a banner for the run. */

static void fix_up_banner(u8 *name)
{

    if (!use_banner)
    {

        if (sync_id)
        {

            use_banner = sync_id;
        }
        else
        {

            u8 *trim = strrchr(name, '/');
            if (!trim)
                use_banner = name;
            else
                use_banner = trim + 1;
        }
    }

    if (strlen(use_banner) > 40)
    {

        u8 *tmp = ck_alloc(44);
        sprintf(tmp, "%.40s...", use_banner);
        use_banner = tmp;
    }
}

/* Check if we're on TTY. */

static void check_if_tty(void)
{

    struct winsize ws;

    if (getenv("AFL_NO_UI"))
    {
        OKF("Disabling the UI because AFL_NO_UI is set.");
        not_on_tty = 1;
        return;
    }
    //通过ioctl读取window size
    if (ioctl(1, TIOCGWINSZ, &ws))
    {
        //如果报错为ENOTTY，则表示当前不在一个tty终端执行，设置not_on_tty为1
        if (errno == ENOTTY)
        {
            OKF("Looks like we're not running on a tty, so I'll be a bit less verbose.");
            not_on_tty = 1;
        }

        return;
    }
}

/* Check terminal dimensions after resize. */

static void check_term_size(void)
{

    struct winsize ws;

    term_too_small = 0;

    if (ioctl(1, TIOCGWINSZ, &ws))
        return;

    if (ws.ws_row < 25 || ws.ws_col < 80)
        term_too_small = 1;
}

/* Display usage hints. */

static void usage(u8 *argv0)
{

    SAYF("\n%s [ options ] -- /path/to/fuzzed_app [ ... ]\n\n"

         "Required parameters:\n\n"

         "  -i dir        - input directory with test cases\n"
         "  -o dir        - output directory for fuzzer findings\n\n"

         "Execution control settings:\n\n"

         "  -f file       - location read by the fuzzed program (stdin)\n"
         "  -t msec       - timeout for each run (auto-scaled, 50-%u ms)\n"
         "  -m megs       - memory limit for child process (%u MB)\n"
         "  -Q            - use binary-only instrumentation (QEMU mode)\n\n"

         "Fuzzing behavior settings:\n\n"

         "  -d            - quick & dirty mode (skips deterministic steps)\n"
         "  -n            - fuzz without instrumentation (dumb mode)\n"
         "  -x dir        - optional fuzzer dictionary (see README)\n\n"

         "Other stuff:\n\n"

         "  -T text       - text banner to show on the screen\n"
         "  -M / -S id    - distributed mode (see parallel_fuzzing.txt)\n"
         "  -C            - crash exploration mode (the peruvian rabbit thing)\n\n"

         "For additional tips, please consult %s/README.\n\n",

         argv0, EXEC_TIMEOUT, MEM_LIMIT, doc_path);

    exit(1);
}

/* Prepare output directories and fds. */
//该函数用于准备输出文件夹和文件描述符
EXP_ST void setup_dirs_fds(void)
{

    u8 *tmp;
    s32 fd;

    ACTF("Setting up output directories...");
    /* 并行情况的处理:如果sync_id，且创建sync_dir文件夹并设置权限为0700，如果报错单errno不是 EEXIST ，抛出异常 */
    if (sync_id && mkdir(sync_dir, 0700) && errno != EEXIST)
        PFATAL("Unable to create '%s'", sync_dir);

    if (mkdir(out_dir, 0700))
    { // 创建out_dir， 权限为0700

        if (errno != EEXIST)
            PFATAL("Unable to create '%s'", out_dir);

        maybe_delete_out_dir();
    }
    else
    {

        if (in_place_resume) //创建成功
            FATAL("Resume attempted but old output directory not found");

        out_dir_fd = open(out_dir, O_RDONLY); // 以只读模式打开，返回fd：out_dir_fd

#ifndef __sun

        if (out_dir_fd < 0 || flock(out_dir_fd, LOCK_EX | LOCK_NB))
            PFATAL("Unable to flock() output directory.");

#endif /* !__sun */
    }

    /* Queue directory for any starting & discovered paths. */
    //队列目录
    tmp = alloc_printf("%s/queue", out_dir);
    if (mkdir(tmp, 0700))
        PFATAL("Unable to create '%s'", tmp); // 创建 out_dir/queue 文件夹，权限为0700
    ck_free(tmp);

    /* Top-level directory for queue metadata used for session
       resume and related tasks. */

    tmp = alloc_printf("%s/queue/.state/", out_dir); // 创建 out_dir/queue/.state 文件夹，用于保存session resume 和相关tasks的队列元数据
    if (mkdir(tmp, 0700))
        PFATAL("Unable to create '%s'", tmp);
    ck_free(tmp);

    /* Directory for flagging queue entries that went through
       deterministic fuzzing in the past. */

    tmp = alloc_printf("%s/queue/.state/deterministic_done/", out_dir);
    if (mkdir(tmp, 0700))
        PFATAL("Unable to create '%s'", tmp);
    ck_free(tmp);

    /* Directory with the auto-selected dictionary entries. */

    tmp = alloc_printf("%s/queue/.state/auto_extras/", out_dir);
    if (mkdir(tmp, 0700))
        PFATAL("Unable to create '%s'", tmp);
    ck_free(tmp);

    /* The set of paths currently deemed redundant. */

    tmp = alloc_printf("%s/queue/.state/redundant_edges/", out_dir);
    if (mkdir(tmp, 0700))
        PFATAL("Unable to create '%s'", tmp);
    ck_free(tmp);

    /* The set of paths showing variable behavior. */

    tmp = alloc_printf("%s/queue/.state/variable_behavior/", out_dir);
    if (mkdir(tmp, 0700))
        PFATAL("Unable to create '%s'", tmp);
    ck_free(tmp);

    /* Sync directory for keeping track of cooperating fuzzers. */
    //同步文件夹，多线程跑的时候，用于keeping track
    if (sync_id)
    {

        tmp = alloc_printf("%s/.synced/", out_dir);

        if (mkdir(tmp, 0700) && (!in_place_resume || errno != EEXIST))
            PFATAL("Unable to create '%s'", tmp);

        ck_free(tmp);
    }

    /* All recorded crashes. */

    tmp = alloc_printf("%s/crashes", out_dir);
    if (mkdir(tmp, 0700))
        PFATAL("Unable to create '%s'", tmp);
    ck_free(tmp);

    /* All recorded hangs. */

    tmp = alloc_printf("%s/hangs", out_dir);
    if (mkdir(tmp, 0700))
        PFATAL("Unable to create '%s'", tmp);
    ck_free(tmp);

    /* Generally useful file descriptors. */

    dev_null_fd = open("/dev/null", O_RDWR);
    if (dev_null_fd < 0)
        PFATAL("Unable to open /dev/null");

    dev_urandom_fd = open("/dev/urandom", O_RDONLY);
    if (dev_urandom_fd < 0)
        PFATAL("Unable to open /dev/urandom");

    /* Gnuplot output file. */

    tmp = alloc_printf("%s/plot_data", out_dir);
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        PFATAL("Unable to create '%s'", tmp);
    ck_free(tmp);

    plot_file = fdopen(fd, "w");
    if (!plot_file)
        PFATAL("fdopen() failed");

    fprintf(plot_file, "# unix_time, cycles_done, cur_path, paths_total, "
                       "pending_total, pending_favs, map_size, unique_crashes, "
                       "unique_hangs, max_depth, execs_per_sec\n");
    /* ignore errors */
}

/* Setup the output file for fuzzed data, if not using -f. */

EXP_ST void setup_stdio_file(void)
{

    u8 *fn = alloc_printf("%s/.cur_input", out_dir);

    unlink(fn); /* Ignore errors */

    out_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);

    if (out_fd < 0)
        PFATAL("Unable to create '%s'", fn);

    ck_free(fn);
}

/* Make sure that core dumps don't go to a program. */
//确保核心转储不会进入程序
static void check_crash_handling(void)
{

#ifdef __APPLE__

    /* Yuck! There appears to be no simple C API to query for the state of
       loaded daemons on MacOS X, and I'm a bit hesitant to do something
       more sophisticated, such as disabling crash reporting via Mach ports,
       until I get a box to test the code. So, for now, we check for crash
       reporting the awful way. */

    if (system("launchctl list 2>/dev/null | grep -q '\\.ReportCrash$'"))
        return;

    SAYF("\n" cLRD "[-] " cRST
         "Whoops, your system is configured to forward crash notifications to an\n"
         "    external crash reporting utility. This will cause issues due to the\n"
         "    extended delay between the fuzzed binary malfunctioning and this fact\n"
         "    being relayed to the fuzzer via the standard waitpid() API.\n\n"
         "    To avoid having crashes misinterpreted as timeouts, please run the\n"
         "    following commands:\n\n"

         "    SL=/System/Library; PL=com.apple.ReportCrash\n"
         "    launchctl unload -w ${SL}/LaunchAgents/${PL}.plist\n"
         "    sudo launchctl unload -w ${SL}/LaunchDaemons/${PL}.Root.plist\n");

    if (!getenv("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"))
        FATAL("Crash reporter detected");

#else

    /* This is Linux specific, but I don't think there's anything equivalent on
     *BSD, so we can just let it slide for now. */

    s32 fd = open("/proc/sys/kernel/core_pattern", O_RDONLY);
    u8 fchar;

    if (fd < 0)
        return;

    ACTF("Checking core_pattern...");

    if (read(fd, &fchar, 1) == 1 && fchar == '|')
    {

        SAYF("\n" cLRD "[-] " cRST
             "Hmm, your system is configured to send core dump notifications to an\n"
             "    external utility. This will cause issues: there will be an extended delay\n"
             "    between stumbling upon a crash and having this information relayed to the\n"
             "    fuzzer via the standard waitpid() API.\n\n"

             "    To avoid having crashes misinterpreted as timeouts, please log in as root\n"
             "    and temporarily modify /proc/sys/kernel/core_pattern, like so:\n\n"

             "    echo core >/proc/sys/kernel/core_pattern\n");

        if (!getenv("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"))
            FATAL("Pipe at the beginning of 'core_pattern'");
    }

    close(fd);

#endif /* ^__APPLE__ */
}

/* Check CPU governor. */
//主要是cpu调度算法
static void check_cpu_governor(void)
{

    FILE *f;
    u8 tmp[128];
    u64 min = 0, max = 0;

    if (getenv("AFL_SKIP_CPUFREQ"))
        return;

    f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "r");
    if (!f)
        return;

    ACTF("Checking CPU scaling governor...");

    if (!fgets(tmp, 128, f))
        PFATAL("fgets() failed");

    fclose(f);

    if (!strncmp(tmp, "perf", 4))
        return;

    f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq", "r");

    if (f)
    {
        if (fscanf(f, "%llu", &min) != 1)
            min = 0;
        fclose(f);
    }

    f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", "r");

    if (f)
    {
        if (fscanf(f, "%llu", &max) != 1)
            max = 0;
        fclose(f);
    }

    if (min == max)
        return;

    SAYF("\n" cLRD "[-] " cRST
         "Whoops, your system uses on-demand CPU frequency scaling, adjusted\n"
         "    between %llu and %llu MHz. Unfortunately, the scaling algorithm in the\n"
         "    kernel is imperfect and can miss the short-lived processes spawned by\n"
         "    afl-fuzz. To keep things moving, run these commands as root:\n\n"

         "    cd /sys/devices/system/cpu\n"
         "    echo performance | tee cpu*/cpufreq/scaling_governor\n\n"

         "    You can later go back to the original state by replacing 'performance' with\n"
         "    'ondemand'. If you don't want to change the settings, set AFL_SKIP_CPUFREQ\n"
         "    to make afl-fuzz skip this check - but expect some performance drop.\n",
         min / 1024, max / 1024);

    FATAL("Suboptimal CPU scaling governor");
}

/* Count the number of logical CPU cores. */
// 逻辑核的数量；不是有多少cpu内核
static void get_core_count(void)
{

    u32 cur_runnable = 0;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)

    size_t s = sizeof(cpu_core_count);

    /* On *BSD systems, we can just use a sysctl to get the number of CPUs. */

#ifdef __APPLE__

    if (sysctlbyname("hw.logicalcpu", &cpu_core_count, &s, NULL, 0) < 0)
        return;

#else

    int s_name[2] = {CTL_HW, HW_NCPU};

    if (sysctl(s_name, 2, &cpu_core_count, &s, NULL, 0) < 0)
        return;

#endif /* ^__APPLE__ */

#else

#ifdef HAVE_AFFINITY

    cpu_core_count = sysconf(_SC_NPROCESSORS_ONLN);

#else

    FILE *f = fopen("/proc/stat", "r");
    u8 tmp[1024];

    if (!f)
        return;

    while (fgets(tmp, sizeof(tmp), f))
        if (!strncmp(tmp, "cpu", 3) && isdigit(tmp[3]))
            cpu_core_count++;

    fclose(f);

#endif /* ^HAVE_AFFINITY */

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

    if (cpu_core_count > 0)
    {

        cur_runnable = (u32)get_runnable_processes();

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)

        /* Add ourselves, since the 1-minute average doesn't include that yet. */

        cur_runnable++;

#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

        OKF("You have %u CPU core%s and %u runnable tasks (utilization: %0.0f%%).",
            cpu_core_count, cpu_core_count > 1 ? "s" : "",
            cur_runnable, cur_runnable * 100.0 / cpu_core_count);

        if (cpu_core_count > 1)
        {

            if (cur_runnable > cpu_core_count * 1.5)
            {

                WARNF("System under apparent load, performance may be spotty.");
            }
            else if (cur_runnable + 1 <= cpu_core_count)
            {

                OKF("Try parallel jobs - see %s/parallel_fuzzing.txt.", doc_path);
            }
        }
    }
    else
    {

        cpu_core_count = 0;
        WARNF("Unable to figure out the number of CPU cores.");
    }
}

/* Validate and fix up out_dir and sync_dir when using -S. */

static void fix_up_sync(void)
{
    //如果通过 -M或者-S指定了 sync_id，则更新 out_dir 和 sync_dir 的值：设置 sync_dir 的值为 out_dir，设置 out_dir 的值为out_dir/sync_id
    u8 *x = sync_id;

    if (dumb_mode)
        FATAL("-S / -M and -n are mutually exclusive");

    if (skip_deterministic)
    {

        if (force_deterministic)
            FATAL("use -S instead of -M -d");
        else
            FATAL("-S already implies -d");
    }

    while (*x)
    {

        if (!isalnum(*x) && *x != '_' && *x != '-')
            FATAL("Non-alphanumeric fuzzer ID specified via -S or -M");

        x++;
    }

    if (strlen(sync_id) > 32)
        FATAL("Fuzzer ID too long");

    x = alloc_printf("%s/%s", out_dir, sync_id);

    sync_dir = out_dir;
    out_dir = x;

    if (!force_deterministic)
    {
        skip_deterministic = 1;
        use_splicing = 1;
    }
}

/* Handle screen resize (SIGWINCH). */

static void handle_resize(int sig)
{
    clear_screen = 1;
}

/* Check ASAN options. */

static void check_asan_opts(void)
{
    //读取环境变量ASAN_OPTIONS和MSAN_OPTIONS，并做一些检查
    u8 *x = getenv("ASAN_OPTIONS");

    if (x)
    {

        if (!strstr(x, "abort_on_error=1"))
            FATAL("Custom ASAN_OPTIONS set without abort_on_error=1 - please fix!");

        if (!strstr(x, "symbolize=0"))
            FATAL("Custom ASAN_OPTIONS set without symbolize=0 - please fix!");
    }

    x = getenv("MSAN_OPTIONS");

    if (x)
    {

        if (!strstr(x, "exit_code=" STRINGIFY(MSAN_ERROR)))
            FATAL("Custom MSAN_OPTIONS set without exit_code=" STRINGIFY(MSAN_ERROR) " - please fix!");

        if (!strstr(x, "symbolize=0"))
            FATAL("Custom MSAN_OPTIONS set without symbolize=0 - please fix!");
    }
}

/* Detect @@ in args. */
//识别参数中是否有“@@”，如果有，则替换为 out_dir/.cur_input ，没有则返回
EXP_ST void detect_file_args(char **argv)
{

    u32 i = 0;
    u8 *cwd = getcwd(NULL, 0);

    if (!cwd)
        PFATAL("getcwd() failed");

    while (argv[i])
    {

        u8 *aa_loc = strstr(argv[i], "@@"); // 查找@@

        if (aa_loc)
        {

            u8 *aa_subst, *n_arg;

            /* If we don't have a file name chosen yet, use a safe default. */

            if (!out_file)
                out_file = alloc_printf("%s/.cur_input", out_dir);

            /* Be sure that we're always using fully-qualified paths. */

            if (out_file[0] == '/')
                aa_subst = out_file;
            else
                aa_subst = alloc_printf("%s/%s", cwd, out_file);

            /* Construct a replacement argv value. */

            *aa_loc = 0;
            n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
            argv[i] = n_arg;
            *aa_loc = '@';

            if (out_file[0] != '/')
                ck_free(aa_subst);
        }

        i++;
    }

    free(cwd); /* not tracked */
}

/* Set up signal handlers. More complicated that needs to be, because libc on
   Solaris doesn't resume interrupted reads(), sets SA_RESETHAND when you call
   siginterrupt(), and does other stupid things. */
//设置语句柄(注册必要的信号处理函数).注册信号处理函数，设置信号句柄
EXP_ST void setup_signal_handlers(void)
{

    struct sigaction sa;

    sa.sa_handler = NULL;
    sa.sa_flags = SA_RESTART;
    sa.sa_sigaction = NULL;

    sigemptyset(&sa.sa_mask);

    /* Various ways of saying "stop". */
    // SIGHUP/SIGINT/SIGTERM	处理各种“stop”情况
    sa.sa_handler = handle_stop_sig;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Exec timeout notifications. */
    // SIGALRM	处理超时的情况
    sa.sa_handler = handle_timeout;
    sigaction(SIGALRM, &sa, NULL);

    /* Window resize */
    // SIGWINCH	处理窗口大小
    sa.sa_handler = handle_resize;
    sigaction(SIGWINCH, &sa, NULL);

    /* SIGUSR1: skip entry */
    // USR1:user defined signal 1，留给用户自定义的信号，这里定义为skip request
    sa.sa_handler = handle_skipreq;
    sigaction(SIGUSR1, &sa, NULL);

    /* Things we don't care about. */
    // SIGSTP/SIGPIPE	不是很重要的一些信号，可以不用关心
    sa.sa_handler = SIG_IGN;
    sigaction(SIGTSTP, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
}

/* Rewrite argv for QEMU. */

static char **get_qemu_argv(u8 *own_loc, char **argv, int argc)
{

    char **new_argv = ck_alloc(sizeof(char *) * (argc + 4));
    u8 *tmp, *cp, *rsl, *own_copy;

    /* Workaround for a QEMU stability glitch. */

    setenv("QEMU_LOG", "nochain", 1);

    memcpy(new_argv + 3, argv + 1, sizeof(char *) * argc);

    new_argv[2] = target_path;
    new_argv[1] = "--";

    /* Now we need to actually find the QEMU binary to put in argv[0]. */

    tmp = getenv("AFL_PATH");

    if (tmp)
    {

        cp = alloc_printf("%s/afl-qemu-trace", tmp);

        if (access(cp, X_OK))
            FATAL("Unable to find '%s'", tmp);

        target_path = new_argv[0] = cp;
        return new_argv;
    }

    own_copy = ck_strdup(own_loc);
    rsl = strrchr(own_copy, '/');

    if (rsl)
    {

        *rsl = 0;

        cp = alloc_printf("%s/afl-qemu-trace", own_copy);
        ck_free(own_copy);

        if (!access(cp, X_OK))
        {

            target_path = new_argv[0] = cp;
            return new_argv;
        }
    }
    else
        ck_free(own_copy);

    if (!access(BIN_PATH "/afl-qemu-trace", X_OK))
    {

        target_path = new_argv[0] = ck_strdup(BIN_PATH "/afl-qemu-trace");
        return new_argv;
    }

    SAYF("\n" cLRD "[-] " cRST
         "Oops, unable to find the 'afl-qemu-trace' binary. The binary must be built\n"
         "    separately by following the instructions in qemu_mode/README.qemu. If you\n"
         "    already have the binary installed, you may need to specify AFL_PATH in the\n"
         "    environment.\n\n"

         "    Of course, even without QEMU, afl-fuzz can still work with binaries that are\n"
         "    instrumented at compile time with afl-gcc. It is also possible to use it as a\n"
         "    traditional \"dumb\" fuzzer by specifying '-n' in the command line.\n");

    FATAL("Failed to locate 'afl-qemu-trace'.");
}

/* Make a copy of the current command line. */

static void save_cmdline(u32 argc, char **argv)
{

    u32 len = 1, i;
    u8 *buf;

    for (i = 0; i < argc; i++)
        len += strlen(argv[i]) + 1;

    buf = orig_cmdline = ck_alloc(len);

    for (i = 0; i < argc; i++)
    {

        u32 l = strlen(argv[i]);

        memcpy(buf, argv[i], l);
        buf += l;

        if (i != argc - 1)
            *(buf++) = ' ';
    }

    *buf = 0;
}

#ifndef AFL_LIB

/* Main entry point */

int main(int argc, char **argv)
{
    //局部变量
    s32 opt;
    u64 prev_queued = 0;
    u32 sync_interval_cnt = 0, seek_to;
    u8 *extras_dir = 0;
    u8 mem_limit_given = 0;                     //是否内存限制
    u8 exit_1 = !!getenv("AFL_BENCH_JUST_ONE"); //设定只跑一次
    char **use_argv;                            //用户输入的参数

    struct timeval tv;
    struct timezone tz;

    //显示，自定义调试头文件中定义的
    SAYF(cCYA "afl-fuzz " cBRI VERSION cRST " by <lcamtuf@google.com>\n");

    //文件路径
    doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;

    //时间
    gettimeofday(&tv, &tz);
    srandom(tv.tv_sec ^ tv.tv_usec ^ getpid());
    //上面main中的变量主要是在main内使用，和main外面的关系不大，后面修改的时候上面的变量最好不动

    // while循环读取来自命令行的参数输入，判断条件是“命令行”中是否还有输入参数，通过switch-case实现
    // argc是参数的个数，argv[0]是程序地址，argv[1]是第一个参数，argv[2]是第二个参数。。。以此类推
    while ((opt = getopt(argc, argv, "+i:o:f:m:t:T:dnCB:S:M:x:Q")) > 0)

        switch (opt)
        {
        //对afl进行修改的时候，如果需要外界输入参数的话，可以从这里先入手，然后倒推到开头，整理出afl实现过程中的参数变化过程。
        case 'i': /* input dir */ //输入文件夹，包含所有的测试用例

            if (in_dir)
                FATAL("Multiple -i options not supported");
            in_dir = optarg;

            if (!strcmp(in_dir, "-"))
                in_place_resume = 1;

            break;

        case 'o': /* output dir */ //输入文件夹，用来存储所有的中间结果和最终结果

            if (out_dir)
                FATAL("Multiple -o options not supported");
            out_dir = optarg;
            break;

        case 'M':
        { /* master sync ID */ //设置主fuzzer（master)

            u8 *c;

            if (sync_id)
                FATAL("Multiple -S or -M options not supported");
            sync_id = ck_strdup(optarg);

            if ((c = strchr(sync_id, ':')))
            {

                *c = 0;

                if (sscanf(c + 1, "%u/%u", &master_id, &master_max) != 2 ||
                    !master_id || !master_max || master_id > master_max ||
                    master_max > 1000000)
                    FATAL("Bogus master ID passed to -M");
            }

            force_deterministic = 1;
        }

        break;

        case 'S': //设置从属fuzzer（slave）

            if (sync_id)
                FATAL("Multiple -S or -M options not supported");
            sync_id = ck_strdup(optarg);
            break;

        case 'f': /* target file */ //将测试用例的内容作为fuzzer的输入

            if (out_file)
                FATAL("Multiple -f options not supported");
            out_file = optarg;
            break;

        case 'x': /* dictionary */ //设置用户提供的tokens。指定字典，变异阶段会使用

            if (extras_dir)
                FATAL("Multiple -x options not supported");
            extras_dir = optarg;
            break;

        case 't':
        { /* timeout */ //设置程序运行超时的时间，单位ms。因为后面阶段是while循环，这里可以通过设置t来实现定时停止fuzzing

            u8 suffix = 0;

            if (timeout_given)
                FATAL("Multiple -t options not supported");

            if (sscanf(optarg, "%u%c", &exec_tmout, &suffix) < 1 ||
                optarg[0] == '-')
                FATAL("Bad syntax used for -t");

            if (exec_tmout < 5)
                FATAL("Dangerously low value of -t");

            if (suffix == '+')
                timeout_given = 2;
            else
                timeout_given = 1;

            break;
        }

        case 'm':
        { /* mem limit */ //设置分配的内存空间

            u8 suffix = 'M';

            if (mem_limit_given)
                FATAL("Multiple -m options not supported");
            mem_limit_given = 1;

            if (!strcmp(optarg, "none"))
            {

                mem_limit = 0;
                break;
            }

            if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 ||
                optarg[0] == '-')
                FATAL("Bad syntax used for -m");

            switch (suffix)
            {

            case 'T':
                mem_limit *= 1024 * 1024;
                break;
            case 'G':
                mem_limit *= 1024;
                break;
            case 'k':
                mem_limit /= 1024;
                break;
            case 'M':
                break;

            default:
                FATAL("Unsupported suffix or bad syntax for -m");
            }

            if (mem_limit < 5)
                FATAL("Dangerously low value of -m");

            if (sizeof(rlim_t) == 4 && mem_limit > 2000)
                FATAL("Value of -m out of range on 32-bit systems");
        }

        break;

        case 'd': /* skip deterministic */

            if (skip_deterministic)
                FATAL("Multiple -d options not supported");
            skip_deterministic = 1;
            use_splicing = 1;
            break;

        case 'B': /* load bitmap */

            /* This is a secret undocumented option! It is useful if you find
               an interesting test case during a normal fuzzing process, and want
               to mutate it without rediscovering any of the test cases already
               found during an earlier run.

               To use this mode, you need to point -B to the fuzz_bitmap produced
               by an earlier run for the exact same binary... and that's it.

               I only used this once or twice to get variants of a particular
               file, so I'm not making this an official setting. */

            if (in_bitmap)
                FATAL("Multiple -B options not supported");

            in_bitmap = optarg;
            read_bitmap(in_bitmap);
            break;

        case 'C': /* crash mode */

            if (crash_mode)
                FATAL("Multiple -C options not supported");
            crash_mode = FAULT_CRASH;
            break;

        case 'n': /* dumb mode */

            if (dumb_mode)
                FATAL("Multiple -n options not supported");
            if (getenv("AFL_DUMB_FORKSRV"))
                dumb_mode = 2;
            else
                dumb_mode = 1;

            break;

        case 'T': /* banner */

            if (use_banner)
                FATAL("Multiple -T options not supported");
            use_banner = optarg;
            break;

        case 'Q': /* QEMU mode */ //这个模式是用于没有源码的情况下进行fuzz

            if (qemu_mode)
                FATAL("Multiple -Q options not supported");
            qemu_mode = 1;

            if (!mem_limit_given)
                mem_limit = MEM_LIMIT_QEMU;

            break;

        default:
            //如果输入错误，提示使用手册（在进行修改时，可以在这个函数usage(argv[0]里进行修改)
            usage(argv[0]);
        }

    //初始化和环境设置，为fuzz作准备
    if (optind == argc || !in_dir || !out_dir)
        usage(argv[0]);

    setup_signal_handlers(); //设置信号句柄
    check_asan_opts();       //检查ASAN选项，其中ASAN是一个快速内存错误检测工具

    if (sync_id)
        fix_up_sync();

    if (!strcmp(in_dir, out_dir)) //比较输入输出路径（文件夹）是否一致
        FATAL("Input and output directories can't be the same");

    if (dumb_mode)
    {

        if (crash_mode)
            FATAL("-C and -n are mutually exclusive");
        if (qemu_mode)
            FATAL("-Q and -n are mutually exclusive");
    }

    if (getenv("AFL_NO_FORKSRV"))
        no_forkserver = 1;
    if (getenv("AFL_NO_CPU_RED"))
        no_cpu_meter_red = 1;
    if (getenv("AFL_NO_ARITH"))
        no_arith = 1;
    if (getenv("AFL_SHUFFLE_QUEUE"))
        shuffle_queue = 1;
    if (getenv("AFL_FAST_CAL"))
        fast_cal = 1;

    if (getenv("AFL_HANG_TMOUT"))
    {
        hang_tmout = atoi(getenv("AFL_HANG_TMOUT"));
        if (!hang_tmout)
            FATAL("Invalid value of AFL_HANG_TMOUT");
    }

    if (dumb_mode == 2 && no_forkserver)
        FATAL("AFL_DUMB_FORKSRV and AFL_NO_FORKSRV are mutually exclusive");

    if (getenv("AFL_PRELOAD"))
    {
        setenv("LD_PRELOAD", getenv("AFL_PRELOAD"), 1);
        setenv("DYLD_INSERT_LIBRARIES", getenv("AFL_PRELOAD"), 1);
    }

    if (getenv("AFL_LD_PRELOAD"))
        FATAL("Use AFL_PRELOAD instead of AFL_LD_PRELOAD");

    save_cmdline(argc, argv); //保存命令行参数

    fix_up_banner(argv[optind]); //修建并创建一个运行横幅

    check_if_tty(); //检查是否在tty终端上运行

    get_core_count(); //获取核心数量

#ifdef HAVE_AFFINITY
    bind_to_free_cpu(); //构建绑定到特定核心的进程列表。如果什么也找不到，返回-1。假设一个4k cpu的上限
#endif                  /* HAVE_AFFINITY */

    check_crash_handling(); //确保核心转储不会进入程序
    check_cpu_governor();   //检查CPU管理者

    setup_post();         //加载后处理器，如果可用的话
    setup_shm();          // 设置共享内存块&&各种覆盖状态,影响参数g_shm_file_path，g_shm_fd，g_shm_base，trace_bits,trace_bits参数就是在这里设置并初始化置零的。
    init_count_class16(); //初始化统计计数桶

    setup_dirs_fds(); //设置输出目录和文件描述符,影响sync_id。主要是和out向关的操作
    read_testcases(); //从输入目录中读取所有测试用例，然后对它们进行排队测试。在启动时被调用
    load_auto();      //自动加载字典

    pivot_inputs(); //在输出目录中为输入测试用例创建硬链接，选择好名称并相应地旋转。

    if (extras_dir)
        load_extras(extras_dir); //通过用户指定-x指定的字典（extras目录）中读取extras并按大小排序

    if (!timeout_given)
        find_timeout(); //如果有-t的设置了自己的超时，那么会触发这个函数
    //检查是否有@@，通过文件
    detect_file_args(argv + optind + 1);
    //标准输入流
    if (!out_file)
        setup_stdio_file(); //如果没有使用-f，则为fuzzed data设置输出目录

    check_binary(argv[optind]); //搜索路径，找到目标二进制文件，检查文件是否存在，是否为shell脚本，同时检查ELF头以及程序是否被插桩
    //上面是初始化和环境设置，为fuzz作准备

    start_time = get_cur_time(); //获取开始时间

    if (qemu_mode) //检查是不是QEMU_MODE
        use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind);
    else
        use_argv = argv + optind;

    //主循环前的准备工作,校验初始种子，对种子进行处理
    perform_dry_run(use_argv); // afl关键函数,执行 input 文件夹下的预先准备的所有测试用例，生成初始化的 queue 和 bitmap，只对初始输入执行一次

    //精简队列。对初始队列进行筛选（更新favored entry）。遍历top_rated[]中的queue，然后提取出发现新edge的entry，并标记为favored，
    //使得在下次遍历queue时，这些entry能获得更多执行fuzz的机会
    cull_queue();

    show_init_stats(); //在处理输入目录的末尾显示快速统计信息，并添加一系列警告。一些校准的东西也在这里结束了，还有一些硬编码的常量。也许最终会清理干净。
    //开始真正的fuzz
    seek_to = find_start_position(); //在恢复时，尝试找到要开始的队列位置。只有在恢复时，以及在可以找到原始fuzzer_stats时，这才有意义。
    //写到out/fuzz_stats
    write_stats_file(0, 0, 0); //更新一些状态文件
    save_auto();               //自动保存extras，目录/queue/.state/autoextras/auto

    //在main函数中一共只用了两次goto，都是为了结束afl的fuzz过程；
    //还用到stop_soon变量，这是个标志变量，表示是否按下Ctrl-c，所以ctrl-c是用来停止afl的
    if (stop_soon)
        goto stop_fuzzing;

    /* Woop woop woop */

    if (!not_on_tty)
    {
        sleep(4);
        start_time += 4000;
        if (stop_soon)
            goto stop_fuzzing;
    }

    //主循环
    while (1)
    {

        u8 skipped_fuzz;
        //更新队列
        cull_queue(); // 对queue进行筛选;精简队列
        //如果queue_cur为空，代表所有queue都被执行完一轮
        if (!queue_cur)
        { //判断queue_cur队列是否为空，如果是，则表示已经完成对队列的遍历（所有queue都被执行完一轮），初始化相关参数，重新开始遍历队列

            queue_cycle++;     //计数器，代表所有queue被完整执行了多少轮,现在在进行第几轮的循环
            current_entry = 0; //设置current_entry为0，和queue_cur为queue首元素，开始新一轮fuzz. 现在fuzz的是第几个值
            cur_skipped_paths = 0;
            queue_cur = queue; //准备开始新的一轮

            //如果是resume fuzz情况，则先检查seek_to是否为空，如果不为空，就从seek_to指定的queue项开始执行
            while (seek_to)
            { //找到queue入口的testcase，seek_to = find_start_position()；直接跳到该testcase
                current_entry++;
                seek_to--;
                queue_cur = queue_cur->next;
            }
            //刷新展示界面
            show_stats();

            if (not_on_tty)
            {
                ACTF("Entering queue cycle %llu.", queue_cycle);
                fflush(stdout);
            }

            /* If we had a full queue cycle with no new finds, try
               recombination strategies next. */
            //如果一整个队列循环都没新发现，尝试重组策略
            //如果在一轮执行之后的queue里的case数，和执行之前一样，代表在完整的一轮执行里都没有发现任何一个新的case   队列没有更新的话，没有产生interesting的种子
            if (queued_paths == prev_queued)
            {

                if (use_splicing)
                    cycles_wo_finds++;
                else
                    use_splicing = 1; // use_splicing=1代表我们接下来要通过splice重组queue里的case
            }
            else
                cycles_wo_finds = 0;

            prev_queued = queued_paths;
            //并行fuzz
            if (sync_id && queue_cycle == 1 && getenv("AFL_IMPORT_FIRST"))
                sync_fuzzers(use_argv);
        }

        //调用关键函数fuzz_one()对该testcase进行fuzz
        //对queue_cur所对应文件进行fuzz，包括(跳过-calibrate_case-修剪测试用例-对用例评分-确定性变异或直接havoc&ssplice)
        //执行skipped_fuzz = fuzz_one(use_argv)来对queue_cur进行一次测试
        skipped_fuzz = fuzz_one(use_argv); //注意fuzz_one并不一定真的执行当前queue_cur，它是有一定策略的，如果不执行，就直接返回1，否则返回0
        //上面的变异完成后，AFL会对文件队列的下一个进行变异处理。当队列中的全部文件都变异测试后，就完成了一个”cycle”，
        //这个就是AFL状态栏右上角的”cycles done”。而正如cycle的意思所说，整个队列又会从第一个文件开始，再次进行变异，
        //不过与第一次变异不同的是，这一次就不需要再进行deterministic fuzzing了。如果用户不停止AFL，那么seed文件将会一遍遍的变异下去

        //判断是否结束，更新queue_cur和current_entry
        if (!stop_soon && sync_id && !skipped_fuzz)
        {
            // 如果skipped_fuzz为0且存在sync_id，表示要进行一次sync
            if (!(sync_interval_cnt++ % SYNC_INTERVAL))
                sync_fuzzers(use_argv);
        }

        if (!stop_soon && exit_1)
            stop_soon = 2;
        //如果按下ctrl-c跳出循环
        if (stop_soon)
            break;
        //开始测试下一个queue
        queue_cur = queue_cur->next;
        current_entry++;
    } //结束while

    if (queue_cur)
        show_stats();

    write_bitmap();
    write_stats_file(0, 0, 0);
    save_auto();

/*利用goto强制跳到结束，作者用了不少goto跳转，比如在变异阶段的skip_bitflip等，虽然最开始学c的时候，老师也说用goto不好，但是实际情况是用goto真香，在跳转中用的好很好用。*/
stop_fuzzing:

    SAYF(CURSOR_SHOW cLRD "\n\n+++ Testing aborted %s +++\n" cRST,
         stop_soon == 2 ? "programmatically" : "by user");

    /* Running for more than 30 minutes but still doing first cycle? */
    /* 运行超过三十分钟，还是第一轮fuzz，就给出提示，说明刚刚的fuzz过程不太行。
    这时候可以考虑考虑什么情况下会这样，用例数量太多？用例不够精简？程序复杂？程序设置了陷阱让你一直在里面跑来跑去？*/
    if (queue_cycle == 1 && get_cur_time() - start_time > 30 * 60 * 1000)
    {

        SAYF("\n" cYEL "[!] " cRST
             "Stopped during the first cycle, results may be incomplete.\n"
             "    (For info on resuming, see %s/README.)\n",
             doc_path);
    }
    //善后工作
    fclose(plot_file);
    destroy_queue();
    destroy_extras();
    ck_free(target_path);
    ck_free(sync_id);

    alloc_report();

    OKF("We're done here. Have a nice day!\n");

    exit(0);
}

#endif /* !AFL_LIB */
