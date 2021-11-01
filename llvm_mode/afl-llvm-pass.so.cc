/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */
/*
  llvm_mode 的插桩思路就是通过编写pass来实现信息记录，对每个基本块都插入探针，具体代码在 afl-llvm-pass.so.cc 文件中，初始化和forkserver操作通过链接完成.

  主要是当通过 afl-clang-fast 调用 clang 时，这个pass被插入到 LLVM 中，告诉编译器添加与 `afl-as.h 中大致等效的代码.
  afl-llvm-pass.so.cc 文件实现了 LLVM-mode 下的一个插桩 LLVM Pass
*/
#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;
//Program: Files, Functions, Basic Blocks, Statements
//llvm的层次关系，粗略理解就是Module相当于你的程序，里面包含所有Function和全局变量，而Function里包含所有BasicBlock和函数参数，BasicBlock里包含所有Instruction,Instruction包含Opcode和Operands

namespace {
  //transformer pass: AFLCoveragee，继承自 ModulePass，实现了一个 runOnModule 函数(该函数中点分析)
  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;

      // StringRef getPassName() const override {
      //  return "American Fuzzy Lop Instrumentation";
      // }

  };

}


char AFLCoverage::ID = 0;

//该文件的关键函数
bool AFLCoverage::runOnModule(Module &M) {
  //通过getContext来获取LLVMContext，其保存了整个程序里分配的类型和常量信息（进程上下文）
  LLVMContext &C = M.getContext();
  //通过这个Context来获取type实例Int8Ty和Int32Ty
  //Type是所有type类的一个超类。每个Value都有一个Type，所以这经常被用于寻找指定类型的Value。Type不能直接实例化，只能通过其子类实例化。
  //某些基本类型(VoidType、LabelType、FloatType和DoubleType)有隐藏的子类。之所以隐藏它们，是因为除了Type类提供的功能之外，它们没有提
  //供任何有用的功能，除了将它们与Type的其他子类区分开来之外。所有其他类型都是DerivedType的子类。Types可以被命名，但这不是必需的。一个给
  //定Type在任何时候都只存在一个实例。这允许使用Type实例的地址相等来执行type相等。也就是说，给定两个Type*值，如果指针相同，则types相同。
  IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");

  } else be_quiet = 1;

  /* Decide instrumentation ratio */
  //读取环境变量AFL_INST_RATIO给变量inst_ratio，其值默认为100，这个值代表一个插桩概率，本来应该每个分支都必定插桩，而这是一个随机的概率决定是否要在这个分支插桩
  //设置插桩密度：读取环境变量 AFL_INST_RATIO ，并赋值给 inst_ratio，其值默认为100，范围为 1～100，该值表示插桩概率
  char* inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */
  //获取全局变量中指向共享内存的指针，以及上一个基础块的随机编号
  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  GlobalVariable *AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
      0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

  /* Instrument all the things! */

  int inst_blocks = 0;
  //遍历每个基本块，找到此基本块中适合插入instrument的位置，后续通过初始化IRBuilder的一个实例进行插入
  for (auto &F : M)
    for (auto &BB : F) {

      BasicBlock::iterator IP = BB.getFirstInsertionPt();  
      IRBuilder<> IRB(&(*IP));

      if (AFL_R(100) >= inst_ratio) continue;     //如果大于插桩密度，进行随机插桩

      /* Make up cur_loc */
      //随机创建一个当前基本块的编号，并通过插入load指令来获取前一个基本块的编号
      unsigned int cur_loc = AFL_R(MAP_SIZE);

      ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);     //随机创建当前基本块ID

      /* Load prev_loc */

      LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);             // 获取上一个基本块的随机ID
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

      /* Load SHM pointer */
      //通过插入load指令来获取共享内存的地址，并通过CreateGEP函数来获取共享内存里指定index的地址，这个index通过cur_loc和prev_loc取xor计算得到
      LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *MapPtrIdx =
          IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));        //调用 CreateGEP 函数获取共享内存中指定index的地址

      /* Update bitmap */
      //通过插入load指令来读取对应index地址的值，并通过插入add指令来将其加一，然后通过创建store指令将新值写入，更新共享内存
      LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
      Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
      IRB.CreateStore(Incr, MapPtrIdx)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Set prev_loc to cur_loc >> 1 */
      //将当前cur_loc的值右移一位，然后通过插入store指令，更新__afl_prev_loc的值
      StoreInst *Store =
          IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
      Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      inst_blocks++;    //插桩计数加一

    }

  /* Say something nice. */
  //扫描下一个BB，根据设置是否为quiet模式等，并判断 inst_blocks 是否为0，如果为0则说明没有进行插桩
  if (!be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%).",
             inst_blocks, getenv("AFL_HARDEN") ? "hardened" :
             ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ?
              "ASAN/MSAN" : "non-hardened"), inst_ratio);

  }

  return true;

}

/*
  总的来说就是通过遍历每个基本块，向其中插入实现了如下伪代码功能的instruction ir来进行插桩

  cur_location = <COMPILE_TIME_RANDOM>; 
  shared_mem[cur_location ^ prev_location]++; 
  prev_location = cur_location >> 1;
*/

//注册pass。对pass进行注册，其核心功能为向PassManager注册新的pass，每个pass相互独立
//这些都是向PassManager来注册新的pass，每个pass彼此独立，通过PM统一注册和调度，更加模块化
static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}

//简单的理解就是当我创建了一个类RegisterStandardPasses之后，就会调用它的构造函数，然后调用PassManagerBuilder::addGlobalExtension，这是一个静态函数，这个
//函数会创建一个tuple保存Ty和Fn还有一个id，并将其添加到一个静态全局vector里，以供PassManagerBuilder在需要的时候，将其添加到PM里。
//而这个添加的时机就是ExtensionPointTy来指定的。

static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
