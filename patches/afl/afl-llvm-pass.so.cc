/*
   american fuzzy lop++ - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

#define AFL_LLVM_PASS

#include "config.h"
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <list>
#include <string>
#include <fstream>
#include <sys/time.h>

#include "llvm/Config/llvm-config.h"
#if LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR < 5
typedef long double max_align_t;
#endif

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#if LLVM_VERSION_MAJOR > 3 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/CFG.h"
#else
#include "llvm/DebugInfo.h"
#include "llvm/Support/CFG.h"
#endif

#ifdef AF

#include <cstdio>
#include <cxxabi.h>
#include <algorithm>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include "llvm/Analysis/TargetLibraryInfo.h"
#include <bits/stdc++.h>

std::string demangle(const char* name) 
{
  int status = -1; 
  std::unique_ptr<char, void(*)(void*)> res { abi::__cxa_demangle(name, NULL, NULL, &status), std::free };
  return (status == 0) ? res.get() : std::string(name);
}


#endif


using namespace llvm;

namespace {

class AFLCoverage : public ModulePass {

 public:
  static char ID;
  AFLCoverage() : ModulePass(ID) {

    char *instWhiteListFilename = getenv("AFL_LLVM_WHITELIST");
    if (instWhiteListFilename) {

      std::string   line;
      std::ifstream fileStream;
      fileStream.open(instWhiteListFilename);
      if (!fileStream) report_fatal_error("Unable to open AFL_LLVM_WHITELIST");
      getline(fileStream, line);
      while (fileStream) {

        myWhitelist.push_back(line);
        getline(fileStream, line);

      }

    }

  }

  // Taken from
  // https://stackoverflow.com/questions/48333206/how-to-check-if-a-target-of-an-llvm-allocainst-is-a-function-pointer/48334548
  bool isFunctionPointerType(Type *type) {
    if(PointerType *pointerType = dyn_cast<PointerType>(type)) {
        return isFunctionPointerType(pointerType->getElementType());
    }
    else if (type->isFunctionTy()) {
        return true;
    }
    return false;
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<TargetLibraryInfoWrapperPass>();
    AU.setPreservesAll();
  }

  // ripped from aflgo
  static bool isBlacklisted(const Function *F) {

    static const char *Blacklist[] = {

        "asan.",
        "llvm.",
        "sancov.",
        "__ubsan_handle_",
        #ifdef AF
        "__sanitizer_cov_function_entry",
        // Create blacklist of functions that will not be instrumented with pruning callbacks
        // due to being a global constructor or being a child callee of a global constructor
        // These constructors may be called before the function activation bitmap is initialized
        // hence we need to ignore such functions.
        "cgc_initialize_flag_page",
        "cgc_try_init_prng",
        "cgc_init_prng",
        "cgc_aes_get_bytes",
        "cgc_gen_block",
        "AES128_ECB_encrypt",
        "KeyExpansion",
        "Cipher",
        "AddRoundKey",
        "SubBytes",
        "ShiftRows",
        "MixColumns",
        "getSBoxValue",
        "BlockCopy",
        "xtime",
        "cgc_xor"
	    // These functions form a part of the libcgc and as such does not make sense to instrument these
        // "_pcre_find_bracket",
        // "_pcre_is_newline",
        // "_pcre_ord2utf",
        // "_pcre_valid_utf",
        // "_pcre_was_newline",
        // "_pcre_xclass",
        // "cgc__terminate",
        // "cgc_add_list_to_class",
        // "cgc_adjust_recurse",
        // "cgc_alloc_main",
        // "cgc_allocate",
        // "cgc_append_buf",
        // "cgc_append_slice",
        // "cgc_append_var",
        // "cgc_assign_from_pcre",
        // "cgc_assign_from_slice",
        // "cgc_buffered_receive",
        // "cgc_calloc",
        // "cgc_check_escape",
        // "cgc_check_posix_syntax",
        // "cgc_check_timeout",
        // "cgc_coalesce",
        // "cgc_compare_opcodes",
        // "cgc_compile_branch",
        // "cgc_compile_regex",
        // "cgc_could_be_empty_branch",
        // "cgc_data_match",
        // "cgc_deallocate",
        // "cgc_delay",
        // "cgc_delimited_read",
        // "cgc_fdprintf",
        // "cgc_fdwait",
        // "cgc_find_firstassertedchar",
        // "cgc_find_fixedlength",
        // "cgc_find_minlength",
        // "cgc_free",
        // "cgc_get_chr_property_list",
        // "cgc_get_size_class",
        // "cgc_getenv",
        // "cgc_init_regex",
        // "cgc_insert_into_flist",
        // "cgc_internal_dfa_exec",
        // "cgc_is_anchored",
        // "cgc_is_startline",
        // "cgc_isalnum",
        // "cgc_isalpha",
        // "cgc_isascii",
        // "cgc_isblank",
        // "cgc_iscntrl",
        // "cgc_isdigit",
        // "cgc_isgraph",
        // "cgc_islower",
        // "cgc_isprint",
        // "cgc_ispunct",
        // "cgc_isspace",
        // "cgc_isupper",
        // "cgc_isxdigit",
        // "cgc_length_read",
        // "cgc_malloc",
        // "cgc_match",
        // "cgc_memchr",
        // "cgc_memcmp",
        // "cgc_memcpy",
        // "cgc_memmove",
        // "cgc_memset",
        // "cgc_negotiate_type1",
        // "cgc_negotiate_type2",
        // "cgc_output_number_printf",
        // "cgc_output_number_sprintf",
        // "cgc_pcre_assign_jit_stack",
        // "cgc_pcre_config",
        // "cgc_pcre_jit_free_unused_memory",
        // "cgc_pcre_jit_stack_alloc",
        // "cgc_pcre_jit_stack_free",
        // "cgc_pcre_refcount",
        // "cgc_pcre_version",
        // "cgc_putenv",
        // "cgc_random",
        // "cgc_realloc",
        // "cgc_receive",
        // "cgc_regex_match",
        // "cgc_remove_from_flist",
        // "cgc_set_nottype_bits",
        // "cgc_set_start_bits",
        // "cgc_set_type_bits",
        // "cgc_sprintf",
        // "cgc_strcasecmp",
        // "cgc_strcat",
        // "cgc_strchr",
        // "cgc_strcmp",
        // "cgc_strcpy",
        // "cgc_strdup",
        // "cgc_strlen",
        // "cgc_strncasecmp",
        // "cgc_strncmp",
        // "cgc_strncpy",
        // "cgc_strsep",
        // "cgc_strtol",
        // "cgc_strtoul",
        // "cgc_submit_type2",
        // "cgc_toascii",
        // "cgc_tolower",
        // "cgc_toupper",
        // "cgc_transmit",
        // "cgc_transmit_all",
        // "cgc_type1_negotiate",
        // "cgc_type2_negotiate",
        // "cgc_type2_submit",
        // "cgc_var_match",
        // "pcre_compile",
        // "pcre_compile2",
        // "pcre_copy_named_substring",
        // "pcre_copy_substring",
        // "pcre_dfa_exec",
        // "pcre_exec",
        // "pcre_free_study",
        // "pcre_free_substring",
        // "pcre_free_substring_list",
        // "pcre_fullinfo",
        // "pcre_get_named_substring",
        // "pcre_get_stringnumber",
        // "pcre_get_stringtable_entries",
        // "pcre_get_substring",
        // "pcre_get_substring_list",
        // "pcre_maketables",
        // "pcre_match",
        // "pcre_pattern_to_host_byte_order",
        // "pcre_study",
        // // PHP-specific functions
        // "resolve_addslashes",
        // "resolve_base64_encode",
        // "resolve_base64_decode",
        // "resolve_stripslashes"
        #endif
    };

    for (auto const &BlacklistFunc : Blacklist) {

      if (F->getName().startswith(BlacklistFunc)) { return true; }

    }

    return false;

  }

  bool runOnModule(Module &M) override;

  // StringRef getPassName() const override {

  //  return "American Fuzzy Lop Instrumentation";
  // }

 protected:
  std::list<std::string> myWhitelist;
  uint32_t function_minimum_size = 1;

};

}  // namespace

char AFLCoverage::ID = 0;

bool AFLCoverage::runOnModule(Module &M) {

  LLVMContext &C = M.getContext();

  IntegerType *   Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *   Int32Ty = IntegerType::getInt32Ty(C);
  struct timeval  tv;
  struct timezone tz;
  u32             rand_seed;
  unsigned int    cur_loc = 0;

  /* Setup random() so we get Actually Random(TM) outputs from AFL_R() */
  gettimeofday(&tv, &tz);
  rand_seed = tv.tv_sec ^ tv.tv_usec ^ getpid();
  AFL_SR(rand_seed);

  /* Show a banner */

  char be_quiet = 0;

  if ((isatty(2) && !getenv("AFL_QUIET")) || getenv("AFL_DEBUG") != NULL) {

    SAYF(cCYA "afl-llvm-pass" VERSION cRST " by <lszekeres@google.com>\n");

  } else

    be_quiet = 1;

  /* Decide instrumentation ratio */

  char *       inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  #ifdef AF
    // // Create a list of library functions
    const TargetLibraryInfo &TLI = getAnalysis<TargetLibraryInfoWrapperPass>().getTLI();
    LibFunc inbuilt_func;
    std::set<StringRef> builtins;
    for (auto &F : M) {
        if (TLI.getLibFunc(F, inbuilt_func)) {
        // fprintf(stderr, "\n Library Function:%s", F.getName().str().c_str());
        builtins.insert(F.getFunction().getName());
        }
    }

    int32_t FnIdx;
    FILE *fp = nullptr;
    FILE *fp_stdlib = nullptr;
    static const char *const SanCovFunctionEntryName = 
      "__sanitizer_cov_function_entry";
    Type *VoidTy = Type::getVoidTy(C);
    FunctionCallee SanCovFunctionEntry;
    SanCovFunctionEntry = 
      M.getOrInsertFunction(SanCovFunctionEntryName, VoidTy, Int32Ty);

    // Initialize the function counter or read it from a file if its already been
    // initialized
    
    // Source: https://stackoverflow.com/questions/17708885/flock-removing-locked-file-without-race-condition
    // Since compilation units can be compiled in parallel across multiple cores, there
    // is a possible concurrency problem with two compilation units reading the counter
    // file in parallel, making the function indices to be incorrectly assigned. This
    // can be remediated by putting a mutex on the global counter file ensuring that 
    // at any point in time only one file has access to the file for reading and updating it.
    
    // Acquire the mutex
    struct stat st0;
    struct stat st1;
    int fd;
    while (1) {
        // Insert random sleep to ensure that two processes do not simultaneously create the lock file
	// This was done when it was observed in some CGC binaries that certain functions were being given duplicate ID's
        int timeout = rand() % 10000;
        usleep(timeout);
    	fd = open("/tmp/counter.lock", O_CREAT);
    	flock(fd, LOCK_EX);

    	fstat(fd, &st0);
    	stat("/tmp/counter.lock", &st1);
    	if(st0.st_ino == st1.st_ino) break;

    	close(fd);
    }

    if (FILE *file = fopen("/tmp/fn_counter.txt", "r")) {
        char buffer[100];
        // If file exists, read function counter from file
        fgets(buffer, 100, file); 
        FnIdx = (int32_t) atoi(buffer);
        fclose(file);
    }
    else {
        FnIdx = 0;
    }
    fp = fopen("/tmp/fn_indices.txt", "a+");
    fp_stdlib = fopen("/tmp/instrumented_stdlib.txt", "a+");
  #endif

#if LLVM_VERSION_MAJOR < 9
  char *neverZero_counters_str = getenv("AFL_LLVM_NOT_ZERO");
#endif

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  #ifdef AF

  GlobalVariable *AFLContext = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_ctx", 0,
      GlobalVariable::GeneralDynamicTLSModel, 0, false);

  GlobalVariable *AFLIsIndirect = new GlobalVariable(
      M, Int8Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_is_indirect", 0,
      GlobalVariable::GeneralDynamicTLSModel, 0, false);

  #endif

#ifdef __ANDROID__
  GlobalVariable *AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc");
#else
  GlobalVariable *AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc", 0,
      GlobalVariable::GeneralDynamicTLSModel, 0, false);
#endif
  ConstantInt *Zero = ConstantInt::get(Int8Ty, 0);
  ConstantInt *One = ConstantInt::get(Int8Ty, 1);

  LoadInst *PrevCtx = NULL;  // Previous caller context 
  LoadInst *PrevInd = NULL;  // Previous state of indirect call flag 

  /* Instrument all the things! */

  int inst_blocks = 0;
  

  for (auto &F : M) {
    
    int has_calls = 0;

    if (isBlacklisted(&F)) continue;

    for (auto &BB : F) {

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<>          IRB(&(*IP));
      #ifdef AF
        bool IsEntryBB = &BB == &F.getEntryBlock();
        if (IsEntryBB) { 

          // load the context ID of the previous function and write to to a local
          // variable on the stack
          PrevCtx = IRB.CreateLoad(AFLContext);
          PrevCtx->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
          PrevCtx->setVolatile(true);

          fprintf(fp, "%s::%s:%d\n", demangle(&(*M.getName().str().c_str())).c_str(), (demangle(F.getName().str().c_str())).c_str(), FnIdx);
          IRB.CreateCall(SanCovFunctionEntry, ConstantInt::get(Int32Ty, FnIdx));

          // does the function have calls? and is any of the calls larger than one
          // basic block?
          for (auto &BB : F) {
            if (has_calls) break;
            for (auto &IN : BB) {
              CallInst *callInst = nullptr;
              if ((callInst = dyn_cast<CallInst>(&IN))) {
                Function *Callee = callInst->getCalledFunction();
                // if (!Callee || Callee->size() < function_minimum_size)
                if (!Callee)
                  continue;
                else {
                  has_calls = 1;
                  break;
                }
              }
            }
          }

          // if yes we store a context ID for this function in the global var
          if (has_calls) {
            ConstantInt *NewCtx = ConstantInt::get(Int32Ty, FnIdx);
            StoreInst *  StoreCtx = IRB.CreateStore(NewCtx, AFLContext);
            StoreCtx->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, None));
            StoreCtx->setVolatile(true);
          }

          FnIdx++;
        }

        // Check if the basic block is a function terminator, if it is and the function calls other functions then put in restore ctx
        if (has_calls) {
          Instruction *Inst = BB.getTerminator();
          if (isa<ReturnInst>(Inst) || isa<ResumeInst>(Inst)) {

            IRBuilder<> Post_IRB(Inst);
            StoreInst * RestoreCtx = Post_IRB.CreateStore(PrevCtx, AFLContext);
            RestoreCtx->setMetadata(M.getMDKindID("nosanitize"),
                                    MDNode::get(C, None));
            RestoreCtx->setVolatile(true);

          }
        }

        // Check if the basic block is an indirect function call, if so update global variable which indicates that an indirect
        // call edge was triggered. Also, store the current calling context (direct/indirect). After the call restore the current
        // calling context (indirect/direct) 
        for (auto &IN : BB) {
          int is_call_stmt = 0;
          llvm::Function *calledFunction = NULL;
          // Check for CallInst or InvokeInst.
          if (llvm::InvokeInst *ii = llvm::dyn_cast<llvm::InvokeInst>(&IN)) {
            is_call_stmt = 1;
            calledFunction = ii->getCalledFunction();
          } else if (llvm::CallInst *ci = llvm::dyn_cast<llvm::CallInst>(&IN)) {
            is_call_stmt = 1;
            if (!ci->isInlineAsm()) {
              calledFunction = ci->getCalledFunction();
            }
          }

          // If the instruction is not a call statement, break
          if (! is_call_stmt) {
              continue;
          }

          // Check if function is called indirectly through a constant pointer.
          if (calledFunction == NULL) {
            llvm::Value *calledValue = NULL;
            // Check for CallInst or InvokeInst.
            if (llvm::InvokeInst *ii = llvm::dyn_cast<llvm::InvokeInst>(&IN)) {
              calledValue = ii->getCalledValue();
            } else if (llvm::CallInst *ci =
                           llvm::dyn_cast<llvm::CallInst>(&IN)) {
              if (!ci->isInlineAsm()) {
                calledValue = ci->getCalledValue();
              }
            }
            if (calledValue) {
              calledFunction = llvm::dyn_cast<llvm::Function>(
                  calledValue->stripPointerCasts());
            }
          }


          BasicBlock::iterator it(IN);
          IRBuilder<> IRIndPre(&(*it));
          // it++;
          // IRBuilder<> IRIndPost(&(*it));
          // If true, we have identified an indirect call
          // fprintf(stderr, "Checking function:%s\n", calledFunction->getName().str().c_str());
          if (calledFunction == NULL) {
            // fprintf(stderr, "Indirect from:%s\n", F.getName().str().c_str());
            // Store in a local variable the current status of the is_ind_call global variable
            // PrevInd = IRIndPre.CreateLoad(AFLIsIndirect);
            // PrevInd->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            // PrevInd->setVolatile(true);

            // Store in the is_ind_call global variable that an indirect call is occurring
            StoreInst *StoreInd = IRIndPre.CreateStore(One, AFLIsIndirect);
            StoreInd->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, None));
            StoreInd->setVolatile(true);

            // After the call returns restore the previous status of the indirect call variable
            // StoreInst * RestoreInd = IRIndPost.CreateStore(PrevInd, AFLIsIndirect);
            // RestoreInd->setMetadata(M.getMDKindID("nosanitize"),
            //                         MDNode::get(C, None));
            // RestoreInd->setVolatile(true);
          }
          // Check if it is a direct call to a builtin but with atleast one of the arguments being a function pointer.
          // We want to catch cases where stdlib functions (eg. qsort) are being called with functions from
          // the fuzz target as arguments. In such cases we optimistically turn on the indirect call edge flag
          // and mark any calls happening inside the stdlib function to target functions as indirect calls
          else if (builtins.count(calledFunction->getName())) { 
            fprintf(fp_stdlib, "\nBuilt-in identified:%s", calledFunction->getName().str().c_str());
            for(auto arg = calledFunction->arg_begin(); arg != calledFunction->arg_end(); ++arg) { 
              Type *Ty = arg->getType();
              if (PointerType *PT = dyn_cast<PointerType>(Ty)) {
                // We have identified a function pointer
                if (isFunctionPointerType(PT)) {
                  fprintf(fp_stdlib, "\nPointer type argument identifed for builtin:%s", calledFunction->getName().str().c_str());
                  // Store in the is_ind_call global variable that an indirect call is occurring
                  StoreInst *StoreInd = IRIndPre.CreateStore(One, AFLIsIndirect);
                  StoreInd->setMetadata(M.getMDKindID("nosanitize"),
                                        MDNode::get(C, None));
                  StoreInd->setVolatile(true);
                }
              }
            }
          }
          // else if (! calledFunction->isDeclaration()) {
          //   fprintf(stderr, "Built-in identified:%s\n", calledFunction->getName().str().c_str());
          //   for(auto arg = calledFunction->arg_begin(); arg != calledFunction->arg_end(); ++arg) { 
          //     Type *Ty = arg->getType();
          //     if (PointerType *PT = dyn_cast<PointerType>(Ty)) {
          //       // We have identified a function pointer
          //       if (isFunctionPointerType(PT)) {
          //         // Store in the is_ind_call global variable that an indirect call is occurring
          //         StoreInst *StoreInd = IRIndPre.CreateStore(One, AFLIsIndirect);
          //         StoreInd->setMetadata(M.getMDKindID("nosanitize"),
          //                               MDNode::get(C, None));
          //         StoreInd->setVolatile(true);
          //       }
          //     }
          //   }
          // }
          // We have identified a direct call
          else {
            // Check if the callee is a blacklisted function then we ignore it
            if (isBlacklisted(calledFunction)) continue;

            // fprintf(stderr, "Direct:%s -> %s\n", F.getName().str().c_str(), calledFunction->getName().str().c_str());
            // PrevInd = IRIndPre.CreateLoad(AFLIsIndirect);
            // PrevInd->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            // PrevInd->setVolatile(true);

            StoreInst *StoreInd = IRIndPre.CreateStore(Zero, AFLIsIndirect);
            StoreInd->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, None));
            StoreInd->setVolatile(true);

            // StoreInst * RestoreInd = IRIndPost.CreateStore(PrevInd, AFLIsIndirect);
            // RestoreInd->setMetadata(M.getMDKindID("nosanitize"),
            //                         MDNode::get(C, None));
            // RestoreInd->setVolatile(true);
          }
        }



      #endif

      if (!myWhitelist.empty()) {

        bool instrumentBlock = false;

        /* Get the current location using debug information.
         * For now, just instrument the block if we are not able
         * to determine our location. */
        DebugLoc Loc = IP->getDebugLoc();
#if LLVM_VERSION_MAJOR >= 4 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR >= 7)
        if (Loc) {

          DILocation *cDILoc = dyn_cast<DILocation>(Loc.getAsMDNode());

          unsigned int instLine = cDILoc->getLine();
          StringRef    instFilename = cDILoc->getFilename();

          if (instFilename.str().empty()) {

            /* If the original location is empty, try using the inlined location
             */
            DILocation *oDILoc = cDILoc->getInlinedAt();
            if (oDILoc) {

              instFilename = oDILoc->getFilename();
              instLine = oDILoc->getLine();

            }

          }

          (void)instLine;

          /* Continue only if we know where we actually are */
          if (!instFilename.str().empty()) {

            for (std::list<std::string>::iterator it = myWhitelist.begin();
                 it != myWhitelist.end(); ++it) {

              /* We don't check for filename equality here because
               * filenames might actually be full paths. Instead we
               * check that the actual filename ends in the filename
               * specified in the list. */
              if (instFilename.str().length() >= it->length()) {

                if (instFilename.str().compare(
                        instFilename.str().length() - it->length(),
                        it->length(), *it) == 0) {

                  instrumentBlock = true;
                  break;

                }

              }

            }

          }

        }

#else
        if (!Loc.isUnknown()) {

          DILocation cDILoc(Loc.getAsMDNode(C));

          unsigned int instLine = cDILoc.getLineNumber();
          StringRef    instFilename = cDILoc.getFilename();

          (void)instLine;

          /* Continue only if we know where we actually are */
          if (!instFilename.str().empty()) {

            for (std::list<std::string>::iterator it = myWhitelist.begin();
                 it != myWhitelist.end(); ++it) {

              /* We don't check for filename equality here because
               * filenames might actually be full paths. Instead we
               * check that the actual filename ends in the filename
               * specified in the list. */
              if (instFilename.str().length() >= it->length()) {

                if (instFilename.str().compare(
                        instFilename.str().length() - it->length(),
                        it->length(), *it) == 0) {

                  instrumentBlock = true;
                  break;

                }

              }

            }

          }

        }

#endif

        /* Either we couldn't figure out our location or the location is
         * not whitelisted, so we skip instrumentation. */
        if (!instrumentBlock) continue;

      }

      if (AFL_R(100) >= inst_ratio) continue;

      /* Make up cur_loc */

      // cur_loc++;
      cur_loc = AFL_R(MAP_SIZE);

/* There is a problem with Ubuntu 18.04 and llvm 6.0 (see issue #63).
   The inline function successors() is not inlined and also not found at runtime
   :-( As I am unable to detect Ubuntu18.04 heree, the next best thing is to
   disable this optional optimization for LLVM 6.0.0 and Linux */
#if !(LLVM_VERSION_MAJOR == 6 && LLVM_VERSION_MINOR == 0) || !defined __linux__
      // only instrument if this basic block is the destination of a previous
      // basic block that has multiple successors
      // this gets rid of ~5-10% of instrumentations that are unnecessary
      // result: a little more speed and less map pollution
      int more_than_one = -1;
      // fprintf(stderr, "BB %u: ", cur_loc);
      for (pred_iterator PI = pred_begin(&BB), E = pred_end(&BB); PI != E;
           ++PI) {

        BasicBlock *Pred = *PI;

        int count = 0;
        if (more_than_one == -1) more_than_one = 0;
        // fprintf(stderr, " %p=>", Pred);

        for (succ_iterator SI = succ_begin(Pred), E = succ_end(Pred); SI != E;
             ++SI) {

          BasicBlock *Succ = *SI;

          // if (count > 0)
          //  fprintf(stderr, "|");
          if (Succ != NULL) count++;
          // fprintf(stderr, "%p", Succ);

        }

        if (count > 1) more_than_one = 1;

      }

      // fprintf(stderr, " == %d\n", more_than_one);
      if (more_than_one != 1) continue;
#endif
      ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

      /* Load prev_loc */

      LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

      /* Load SHM pointer */

      LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *MapPtrIdx =
          IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

      /* Update bitmap */

      LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
      Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      Value *Incr = IRB.CreateAdd(Counter, One);

#if LLVM_VERSION_MAJOR < 9
      if (neverZero_counters_str !=
          NULL) {  // with llvm 9 we make this the default as the bug in llvm is
                   // then fixed
#endif
        /* hexcoder: Realize a counter that skips zero during overflow.
         * Once this counter reaches its maximum value, it next increments to 1
         *
         * Instead of
         * Counter + 1 -> Counter
         * we inject now this
         * Counter + 1 -> {Counter, OverflowFlag}
         * Counter + OverflowFlag -> Counter
         */
        /*       // we keep the old solutions just in case
                 // Solution #1
                 if (neverZero_counters_str[0] == '1') {

                   CallInst *AddOv =
           IRB.CreateBinaryIntrinsic(Intrinsic::uadd_with_overflow, Counter,
           ConstantInt::get(Int8Ty, 1));
                   AddOv->setMetadata(M.getMDKindID("nosanitize"),
           MDNode::get(C, None)); Value *SumWithOverflowBit = AddOv; Incr =
           IRB.CreateAdd(IRB.CreateExtractValue(SumWithOverflowBit, 0),  // sum
                                        IRB.CreateZExt( // convert from one bit
           type to 8 bits type IRB.CreateExtractValue(SumWithOverflowBit, 1), //
           overflow Int8Ty));
                  // Solution #2

                  } else if (neverZero_counters_str[0] == '2') {

                     auto cf = IRB.CreateICmpEQ(Counter,
           ConstantInt::get(Int8Ty, 255)); Value *HowMuch =
           IRB.CreateAdd(ConstantInt::get(Int8Ty, 1), cf); Incr =
           IRB.CreateAdd(Counter, HowMuch);
                  // Solution #3

                  } else if (neverZero_counters_str[0] == '3') {

        */
        // this is the solution we choose because llvm9 should do the right
        // thing here
        auto cf = IRB.CreateICmpEQ(Incr, Zero);
        auto carry = IRB.CreateZExt(cf, Int8Ty);
        Incr = IRB.CreateAdd(Incr, carry);
/*
         // Solution #4

         } else if (neverZero_counters_str[0] == '4') {

            auto cf = IRB.CreateICmpULT(Incr, ConstantInt::get(Int8Ty, 1));
            auto carry = IRB.CreateZExt(cf, Int8Ty);
            Incr = IRB.CreateAdd(Incr, carry);

         } else {

            fprintf(stderr, "Error: unknown value for AFL_NZERO_COUNTS: %s
   (valid is 1-4)\n", neverZero_counters_str); exit(-1);

         }

*/
#if LLVM_VERSION_MAJOR < 9

      }

#endif

      IRB.CreateStore(Incr, MapPtrIdx)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Set prev_loc to cur_loc >> 1 */

      StoreInst *Store =
          IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
      Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      inst_blocks++;

    }

  }

  /* Say something nice. */

  #ifdef AF
    FILE *file = fopen("/tmp/fn_counter.txt", "w+"); 
    char tmpbuffer[100];
    sprintf(tmpbuffer, "%d", FnIdx);
    fprintf(file, "%s", tmpbuffer);
    fclose(file);
    fclose(fp);
    fclose(fp_stdlib);

    // Release the mutex
    unlink("/tmp/counter.lock");
    flock(fd, LOCK_UN);
  #endif

  if (!be_quiet) {

    if (!inst_blocks)
      WARNF("No instrumentation targets found.");
    else {

      char modeline[100];
      snprintf(modeline, sizeof(modeline), "%s%s%s%s",
               getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
               getenv("AFL_USE_ASAN") ? ", ASAN" : "",
               getenv("AFL_USE_MSAN") ? ", MSAN" : "",
               getenv("AFL_USE_UBSAN") ? ", UBSAN" : "");
      OKF("Instrumented %u locations (%s mode, ratio %u%%).", inst_blocks,
          modeline, inst_ratio);

    }

  }

  return true;

}

static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}

static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);

