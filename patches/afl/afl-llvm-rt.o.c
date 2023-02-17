/*
   american fuzzy lop++ - LLVM instrumentation bootstrap
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski

   LLVM integration design comes from Laszlo Szekeres.

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is the rewrite of afl-as.h's main_payload.

*/

#ifdef __ANDROID__
#include "android-ashmem.h"
#endif
#include "config.h"
#include "types.h"
#include "cmplog.h"
#ifdef AF
#include "helper.h"
#include "utarray.h"
#include <stdbool.h>
#include <limits.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <errno.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>

/* This is a somewhat ugly hack for the experimental 'trace-pc-guard' mode.
   Basically, we need to make sure that the forkserver is initialized after
   the LLVM-generated runtime initialization pass, not before. */

#ifdef USE_TRACE_PC
#define CONST_PRIO 5
#else
#define CONST_PRIO 0
#endif                                                     /* ^USE_TRACE_PC */

#include <sys/mman.h>
#include <fcntl.h>

/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to
   run. It will end up as .comm, so it shouldn't be too wasteful. */

u8  __afl_area_initial[MAP_SIZE];
u8* __afl_area_ptr = __afl_area_initial;

#ifdef __ANDROID__
u32 __afl_prev_loc;
u32 __afl_final_loc;
#else
__thread u32 __afl_prev_loc;
__thread u32 __afl_final_loc;
__thread u32 __afl_prev_ctx ;
__thread u8 __afl_is_indirect;
#endif

struct cmp_map* __afl_cmp_map;
__thread u32    __afl_cmp_counter;

// Create function activation map and call edge tracking struct
// as shared data structure
#ifdef AF
// # define BITMAP_SIZE 128 // Total no.of functions possible 32 * 64
// Create Function bitmap
// static u32 fnbitmap[BITMAP_SIZE];

// Create dynamic array that will hold unique id's corresponding to call edges
// UT_icd s_long_icd = {sizeof(s64), NULL, NULL, NULL};
// static UT_array* calledges; 

FILE *logfp;
extern u8 funcmap_init;

int get_func_bit(char *line) {
  int bit;
  char *token, *tofree, *string;
  char *prev_token;
  // printf("\nLine:%s", line);
  tofree = string = strdup(line);
  while ((token = strsep(&string, ":")) != NULL) {
      prev_token = token;
  }
  strtok(prev_token, "\n");
  bit = atoi(strdup(prev_token));
  free(tofree);
  return bit;
}

// // Bitmap helper library
// // Source: https://stackoverflow.com/questions/1225998/what-is-a-bitmap-in-c/1226129
// enum { BITS_PER_WORD = sizeof(u32) * CHAR_BIT };
// #define WORD_OFFSET(b) ((b) / BITS_PER_WORD)
// #define BIT_OFFSET(b)  ((b) % BITS_PER_WORD)

u32* __af_fnbitmap_ptr;
struct calledge_arr* __af_calledge_arr_ptr;
static u8 calledge_init;
static u8 funcmaps_init;
#ifdef TRACE_METRIC
u64* __af_tracelength_ptr; // Keeps track of the number of functions executed by an input
struct af_input_stats* __af_input_stats_ptr;
static u8 inputstats_init;
#endif

#endif

/* Running in persistent mode? */

static u8 is_persistent;

/* SHM setup. */

static void __afl_map_shm(void) {


  u8* id_str = getenv(SHM_ENV_VAR);

  /* If we're running under AFL, attach to the appropriate region, replacing the
     early-stage __afl_area_initial region that is needed to allow some really
     hacky .init code to work correctly in projects such as OpenSSL. */

  if (id_str) {
    #ifdef LOG
        logfp = fopen("/tmp/log.txt", "a+");
        fprintf(logfp, "\nSHM_ENV_VAR found");
        fclose(logfp);
    #endif

    #ifdef USEMMAP
        const char*    shm_file_path = id_str;
        int            shm_fd = -1;
        unsigned char* shm_base = NULL;
    
        /* create the shared memory segment as if it was a file */
        shm_fd = shm_open(shm_file_path, O_RDWR, 0600);
        if (shm_fd == -1) {
    
          printf("shm_open() failed\n");
          exit(1);
    
        }
    
        /* map the shared memory segment to the address space of the process */
        shm_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
        if (shm_base == MAP_FAILED) {
    
          close(shm_fd);
          shm_fd = -1;
    
          printf("mmap() failed\n");
          exit(2);
    
        }
    
        __afl_area_ptr = shm_base;
    #else
        u32 shm_id = atoi(id_str);
    
        __afl_area_ptr = shmat(shm_id, NULL, 0);
    #endif

    /* Whooooops. */

    if (__afl_area_ptr == (void*)-1) _exit(1);

    /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */

    __afl_area_ptr[0] = 1;

  }

  id_str = getenv(CMPLOG_SHM_ENV_VAR);

  if (id_str) {

    #ifdef USEMMAP
        const char*    shm_file_path = id_str;
        int            shm_fd = -1;
        unsigned char* shm_base = NULL;
    
        /* create the shared memory segment as if it was a file */
        shm_fd = shm_open(shm_file_path, O_RDWR, 0600);
        if (shm_fd == -1) {
    
          printf("shm_open() failed\n");
          exit(1);
    
        }
    
        /* map the shared memory segment to the address space of the process */
        shm_base = mmap(0, sizeof(struct cmp_map), PROT_READ | PROT_WRITE,
                        MAP_SHARED, shm_fd, 0);
        if (shm_base == MAP_FAILED) {
    
          close(shm_fd);
          shm_fd = -1;
    
          printf("mmap() failed\n");
          exit(2);
    
        }
    
        __afl_cmp_map = shm_base;
    #else
        u32 shm_id = atoi(id_str);
    
        __afl_cmp_map = shmat(shm_id, NULL, 0);
    #endif
    
        if (__afl_cmp_map == (void*)-1) _exit(1);
    
  }

  #ifdef AF
      // Get funcmap SHM handle
      id_str = getenv(FUNCMAP_SHM_ENV_VAR);

      if (id_str) {
          funcmaps_init = 1;
          #ifdef LOG
              logfp = fopen("/tmp/log.txt", "a+");
              fprintf(logfp, "\nFUNCMAP_SHM_ENV_VAR found");
              fclose(logfp);
          #endif
          #ifdef USEMMAP
          //TODO: Support mmap-based setup if SHM support not present
              _exit(1);
          #else
              u32 shm_id = atoi(id_str);
              __af_fnbitmap_ptr = shmat(shm_id, NULL, 0);
          #endif
          if (__af_fnbitmap_ptr == (void*)-1) _exit(1);
      }

      // Get calledge arr SHM handle
      id_str = getenv(CALLEDGE_SHM_ENV_VAR);
      if (id_str) {
        calledge_init = 1;
        #ifdef LOG
            logfp = fopen("/tmp/log.txt", "a+");
            fprintf(logfp, "\nCALLEDGE_SHM_ENV_VAR found");
            fclose(logfp);
        #endif
        __af_calledge_arr_ptr = (struct calledge_arr*)calloc(1, sizeof(struct calledge_arr));
        #ifdef USEMMAP
        //TODO: Support mmap-based setup if SHM support not present
            _exit(1);
        #else
            u32 shm_id = atoi(id_str);
            void *tmp_ptr = shmat(shm_id, NULL, 0);
        #endif
            __af_calledge_arr_ptr->numelements = (u32*) tmp_ptr;
            __af_calledge_arr_ptr->limit = (u32*) tmp_ptr + 1;
            __af_calledge_arr_ptr->base_ptr = (s64*) tmp_ptr + 2; 
        #ifdef LOG
            logfp = fopen("/tmp/log.txt", "a+");
            fprintf(logfp, "\nNumelements:%u, Limit:%u", *(__af_calledge_arr_ptr->numelements), *(__af_calledge_arr_ptr->limit));
            fclose(logfp);
        #endif
        if (__af_calledge_arr_ptr == (void*)-1) _exit(1);
      
      // Setup SHM var to keep track of function trace length for a input
      #ifdef TRACE_METRIC
        id_str = getenv(INPUTSTATS_ENV_VAR);
        #ifdef LOG
            logfp = fopen("/tmp/log.txt", "a+");
            fprintf(logfp, "\nINPUTSTATS_ENV_VAR found");
            fclose(logfp);
        #endif

        if (id_str) {
          inputstats_init = 1;
          #ifdef USEMMAP
          //TODO: Support mmap-based setup if SHM support not present
              _exit(1);
          #else
            u32 shm_id = atoi(id_str);
            void *tmp_ptr = shmat(shm_id, NULL, 0);
            __af_input_stats_ptr = (struct af_input_stats*)calloc(1, sizeof(struct af_input_stats));
            __af_input_stats_ptr->tracelength_ptr = (u64*) tmp_ptr;
            #ifdef LOG
                logfp = fopen("/tmp/log.txt", "a+");
                fprintf(logfp, "\nTracelength initialized:%u", *(__af_input_stats_ptr->tracelength_ptr));
                fclose(logfp);
            #endif
          #endif
        }
      #endif
      }
  #endif

}

/* Fork server logic. */

static void __afl_start_forkserver(void) {

  static u8 tmp[4];
  s32       child_pid;

  u8 child_stopped = 0;

  void (*old_sigchld_handler)(int) = 0;  // = signal(SIGCHLD, SIG_DFL);

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  while (1) {

    u32 was_killed;
    int status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */

    if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);

    /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */

    if (child_stopped && was_killed) {

      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) _exit(1);

    }

    if (!child_stopped) {

      /* Once woken up, create a clone of our process. */

      child_pid = fork();
      if (child_pid < 0) _exit(1);

      /* In child process: close fds, resume execution. */

      if (!child_pid) {

        signal(SIGCHLD, old_sigchld_handler);

        close(FORKSRV_FD);
        close(FORKSRV_FD + 1);
        return;

      }

    } else {

      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */

      kill(child_pid, SIGCONT);
      child_stopped = 0;

    }

    /* In parent process: write PID to pipe, then wait for child. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);

    if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0)
      _exit(1);

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */

    if (WIFSTOPPED(status)) child_stopped = 1;

    /* Relay wait status to pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);

  }

}

/* A simplified persistent mode handler, used as explained in
 * llvm_mode/README.md. */

int __afl_persistent_loop(unsigned int max_cnt) {

  static u8  first_pass = 1;
  static u32 cycle_cnt;

  if (first_pass) {

    /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
       On subsequent calls, the parent will take care of that, but on the first
       iteration, it's our job to erase any trace of whatever happened
       before the loop. */

    if (is_persistent) {

      memset(__afl_area_ptr, 0, MAP_SIZE);
      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;

    }

    cycle_cnt = max_cnt;
    first_pass = 0;
    return 1;

  }

  if (is_persistent) {

    if (--cycle_cnt) {

      raise(SIGSTOP);

      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;

      return 1;

    } else {

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

  #ifdef PREINIT_CHECK
    logfp = fopen("/tmp/log.txt", "a+");
    fprintf(logfp, "\n---------");
    fprintf(logfp, "\nInit called");
    fclose(logfp);
  #endif
  static u8 init_done;
  u8* funcbitmap_file = getenv(FNINDICES_VAR);

  if (!init_done) {

    __afl_map_shm();

    // If so, see if there is an activation file passed to it, if so use it
    // otherwise activate the entire activation map
    if (funcbitmap_file) {
      // Allocate a structure to hold the bitmap
      __af_fnbitmap_ptr = (u32*)calloc(1, MAP_SIZE);  
      #ifdef LOG
        logfp = fopen("/tmp/log.txt", "a+");
        fprintf(logfp, "\nRunning in standalone mode, reading activation file");
        fclose(logfp);
      #endif
      FILE *fp;
      fp = fopen(funcbitmap_file, "r");
      char *line = NULL;
      size_t len = 0;
      int func_bit;
      int bmp_idx = 0;
      ssize_t read;
      while ((read = getline(&line, &len, fp)) != -1) {
  	strtok(line, "\n");
  	func_bit = atoi(strdup(line));
	set_bit(func_bit);
	#ifdef LOG
          logfp = fopen("/tmp/log.txt", "a+");
          fprintf(logfp, "\nSetting bit:%d", func_bit); 
          fclose(logfp);
        #endif
      }
      fclose(fp);
      free(line);
    }
    else if (! funcmaps_init ) {
        // Allocate a structure to hold the bitmap
        __af_fnbitmap_ptr = (u32*)calloc(1, MAP_SIZE);  
        #ifdef LOG
          logfp = fopen("/tmp/log.txt", "a+");
          fprintf(logfp, "\nFunction init not performed, activating entire bitmap");
          fclose(logfp);
        #endif
        u32 mapped_size = MAP_SIZE / sizeof(u32);
        for (int x = 0; x < mapped_size; x++)
           __af_fnbitmap_ptr[x] |= 0xFFFFFFFF; 
    } else {
      #ifdef LOG
        logfp = fopen("/tmp/log.txt", "a+");
        fprintf(logfp, "\nFunction init has been performed, not touching function activation map");
        fclose(logfp);
      #endif
    }
      
    // if (! __af_calledge_arr_ptr) {
    if (! calledge_init) {
      #ifdef LOG
        logfp = fopen("/tmp/log.txt", "a+");
        fprintf(logfp, "\nBeing run in standalone mode..creating calledge arr");
        fclose(logfp);
      #endif
      // Create calledge control structure if binary is being run in standalone mode
      void *tmp_ptr = (void *)calloc(1, MAP_SIZE);  
      __af_calledge_arr_ptr = (struct calledge_arr*)calloc(1, sizeof(struct calledge_arr));
      __af_calledge_arr_ptr->numelements = (u32*) tmp_ptr;
      __af_calledge_arr_ptr->limit = (u32*) tmp_ptr + 1;
      __af_calledge_arr_ptr->base_ptr = (s64*) tmp_ptr + 2; 

      *(__af_calledge_arr_ptr->limit) = (MAP_SIZE - 8) / sizeof(s64) ;
    }
    #ifdef AF
      #ifdef TRACE_METRIC
        if (! inputstats_init) {
          #ifdef LOG
            logfp = fopen("/tmp/log.txt", "a+");
            fprintf(logfp, "\nBeing run in standalone mode..creating af_input_stats");
            fclose(logfp);
          #endif
          void *tmp_ptr = (void *)calloc(1, sizeof(u64));  
          __af_input_stats_ptr = (struct af_input_stats*)calloc(1, sizeof(struct af_input_stats));
          __af_input_stats_ptr->tracelength_ptr = (u64*) tmp_ptr;
        }
     #endif
   #endif

    __afl_start_forkserver();
    init_done = 1;
  }
}


//======== SieveFuzz-specific functionality ===============
//
#ifdef AF

void set_bit(int n) { 
    __af_fnbitmap_ptr[WORD_OFFSET(n)] |= ((u32) 1 << BIT_OFFSET(n));
}

void clear_bit(int n) {
    __af_fnbitmap_ptr[WORD_OFFSET(n)] &= ~((u32) 1 << BIT_OFFSET(n)); 
}

int get_bit(u32 n) {
    u32 bit = __af_fnbitmap_ptr[WORD_OFFSET(n)] & ((u32) 1 << BIT_OFFSET(n));
    return bit != 0; 
}


// SieveFuzz-specific modifications
// void __sanitizer_cov_function_entry_init(u8* initfile) { 
// 
//   // FILE *fp;
//   // char *line = NULL;
//   // size_t len = 0;
//   // ssize_t read;
//   // int func_bit;
//   // int bmp_idx = 0;
//   // // Open log
//   // #ifdef LOG
//   // logfp = fopen("/tmp/log.txt", "a+");
//   // #endif 
//  
//   // // Zero initialize the bitmap
//   // for(int x = 0; x < BITMAP_SIZE; x++) {
//   //   fnbitmap[x] = (u32) 0;
//   // }
//   // // Initialize the dynamic array for call edges
//   // utarray_new(calledges, &s_long_icd);
// 
//   // // Initialize the bitmap based on initfile 
//   // // XXX: No init file will exist only in two possible scenarios:
//   // // 1) User forgot to provide an init file
//   // // 2) During target compilation, some intermediary binaries are created and executed (eg. conftest)
//   // // 1 is erroneous while 2 is benign. However, assuming user sanity and 2 might prevent the compilation
//   // // from erroring out incorrectly. So, in the case of no initfile being
//   // // provided we activate the entire function bitmap. This is done under the implicit assumption that Scenario 2
//   // // is the default which is being triggered.
//   // // A more involved check to ensure that this is done only in the case of 2 and not 1 would be to check creation
//   // // time of `/tmp/fn_indices.txt` and ensure that it is within an acceptable delta from the current unix time but
//   // // we leave that since right now we are merely doing prototype testing under controlled conditions
//   // if (!initfile) { 
//   //   // Activate the entire bitmap  
//   //   for(int x = 0; x < BITMAP_SIZE; x++) {
//   //     fnbitmap[x] = (u32) UINT_MAX;
//   //   }
//   //   #ifdef LOG
//   //   fprintf(logfp, "\nActivating entire bitmap");
//   //   #endif
//   //   // exit(1);
//   // } else {
//   //   fp = fopen(initfile, "r");
//   //   while ((read = getline(&line, &len, fp)) != -1) {
//   //     func_bit = get_func_bit(line);
//   //     // printf("\nFunc bit:%d", func_bit);
//   //     if (func_bit) {
//   //   #ifdef LOG
//   //       fprintf(logfp, "\nSetting bit:%d", bmp_idx); 
//   //       #endif
//   //       // printf("\nSetting bit:%d", bmp_idx);
//   //       set_bit(bmp_idx);
//   //     }
//   //     bmp_idx += 1;
//   //   }
//   //   fclose(fp);
//   //   free(line);
//   // }
//   // #ifdef LOG
//   // fclose(logfp);
//   // #endif
// }
// 
// Given the caller and callee id, generates a unique
// ID identifying the edge. The edge ID is created from
// a 64-bit signed integer by putting the caller in the higher-order
// 32 bits and the callee in the lower order 32 bits.
s64 get_edge_id(u32 caller, u32 callee) {
    s64 id = (s64) caller << 32 | callee;
    // Check to ensure that overflow has not occurred while creating this unique id
    if (id < 0) {
        printf("\nOverflow detected during edge ID creation");
        exit(1);
    }
    return id; 
}

// Given the edge ID, get caller and callee (end points of edge)
// Caller is in the higher order bits so its retrieved by shifting right by 32 bits
// Callee is in the lower order bits so its retrieved by masking the higher order bits
void get_end_points(s64 edge_id, u32 *caller, u32 *callee) {
    *caller = (edge_id) >> 32 ;
    *callee = (edge_id) & 0xFFFFFFFF ;
}



void __sanitizer_cov_function_entry(u32 id) {

  // Update the function trace length counter
  #ifdef AF
  #ifdef TRACE_METRIC
  *(__af_input_stats_ptr->tracelength_ptr) += 1;
  #endif
  #endif

  #ifdef PREINIT_CHECK
    logfp = fopen("/tmp/log.txt", "a+");
    fprintf(logfp, "\n---------");
    fprintf(logfp, "\nID: %d", id);
    fclose(logfp);
    return; 
  #else
  // Update dynamic array with the call edge only if its an indirect call
  if (__afl_is_indirect) {
      #ifdef LOG
        logfp = fopen("/tmp/log.txt", "a+");
        fprintf(logfp, "\n---------");
        fprintf(logfp, "\nIndirect call observed");
        fclose(logfp);
      #endif
      s64 edge_id = get_edge_id(__afl_prev_ctx, id);
      int calledge_idx = 0;
      bool new_edge = true;
      while (calledge_idx < *(__af_calledge_arr_ptr->numelements)) {
          if (__af_calledge_arr_ptr->base_ptr[calledge_idx] == edge_id) {
              #ifdef LOG
                logfp = fopen("/tmp/log.txt", "a+");
                fprintf(logfp, "\nEdge seen already..discarding");
                fclose(logfp);
              #endif
              new_edge = false;
          }
          calledge_idx += 1;
      }
      if (new_edge) {
        if (calledge_idx == *(__af_calledge_arr_ptr->limit)) {
            fprintf(stderr, "[-] ERROR: Call edge tracking limit overflow. Please make calledge limit larger.\n");
            abort();
        }
        #ifdef LOG
          logfp = fopen("/tmp/log.txt", "a+");
          fprintf(logfp, "\nNew edge");
          fclose(logfp);
        #endif
        *(__af_calledge_arr_ptr->numelements) += 1;
        __af_calledge_arr_ptr->base_ptr[calledge_idx] = edge_id;
      }
  }
  // Open log
  #ifdef LOG
    logfp = fopen("/tmp/log.txt", "a+");
    fprintf(logfp, "\n==========");
    fprintf(logfp, "\nCaller:%d Callee:%d", __afl_prev_ctx, id);
    fclose(logfp);
  #endif 
  
  u32 bit = get_bit(id);
  #ifdef LOG
    logfp = fopen("/tmp/log.txt", "a+");
    fprintf(logfp, "\nBit is:%u", bit);
    fclose(logfp);
  #endif
  if (! bit) {
       // printf("\nExiting"); 
       #ifdef LOG
         logfp = fopen("/tmp/log.txt", "a+");
         fprintf(logfp, "\nNot allowed..exiting", bit);
         fclose(logfp);
       #endif
       exit(1);
  }
  #endif

  // Enables function tracing to allow for which functions are triggered while executing
  // an input 
  #ifdef USE_FUNCTION_TRACE 
    FILE *fp = fopen("/tmp/func_triggered.txt", "a+");
    fprintf(fp, "\n%d", id);
    fclose(fp);
  #endif
  
}

// // Extract from file if func is to be enabled
// int get_func_bit(char *line) {
//   int bit;
//   char *token, *tofree, *string;
//   char *prev_token;
//   // printf("\nLine:%s", line);
//   tofree = string = strdup(line);
//   while ((token = strsep(&string, ":")) != NULL) {
//       prev_token = token;
//   }
//   strtok(prev_token, "\n");
//   bit = atoi(strdup(prev_token));
//   free(tofree);
//   return bit;
// }
#endif

/* Proper initialization routine. */

__attribute__((constructor(CONST_PRIO))) void __afl_auto_init(void) {

  is_persistent = !!getenv(PERSIST_ENV_VAR);

  if (getenv(DEFER_ENV_VAR)) return;

  __afl_manual_init();

}

/* The following stuff deals with supporting -fsanitize-coverage=trace-pc-guard.
   It remains non-operational in the traditional, plugin-backed LLVM mode.
   For more info about 'trace-pc-guard', see llvm_mode/README.md.

   The first function (__sanitizer_cov_trace_pc_guard) is called back on every
   edge (as opposed to every basic block). */

void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {

  __afl_area_ptr[*guard]++;

}

/* Init callback. Populates instrumentation IDs. Note that we're using
   ID of 0 as a special value to indicate non-instrumented bits. That may
   still touch the bitmap, but in a fairly harmless way. */

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

  *(start++) = R(MAP_SIZE - 1) + 1;

  while (start < stop) {

    if (R(100) < inst_ratio)
      *start = R(MAP_SIZE - 1) + 1;
    else
      *start = 0;

    start++;

  }

}

///// CmpLog instrumentation

void __cmplog_ins_hook1(uint8_t Arg1, uint8_t Arg2) {

  return;

}

void __cmplog_ins_hook2(uint16_t Arg1, uint16_t Arg2) {

  if (!__afl_cmp_map) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= CMP_MAP_W - 1;

  __afl_cmp_map->headers[k].type = CMP_TYPE_INS;

  u32 hits = __afl_cmp_map->headers[k].hits;
  __afl_cmp_map->headers[k].hits = hits + 1;
  // if (!__afl_cmp_map->headers[k].cnt)
  //  __afl_cmp_map->headers[k].cnt = __afl_cmp_counter++;

  __afl_cmp_map->headers[k].shape = 1;
  //__afl_cmp_map->headers[k].type = CMP_TYPE_INS;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = Arg1;
  __afl_cmp_map->log[k][hits].v1 = Arg2;

}

void __cmplog_ins_hook4(uint32_t Arg1, uint32_t Arg2) {

  if (!__afl_cmp_map) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= CMP_MAP_W - 1;

  __afl_cmp_map->headers[k].type = CMP_TYPE_INS;

  u32 hits = __afl_cmp_map->headers[k].hits;
  __afl_cmp_map->headers[k].hits = hits + 1;

  __afl_cmp_map->headers[k].shape = 3;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = Arg1;
  __afl_cmp_map->log[k][hits].v1 = Arg2;

}

void __cmplog_ins_hook8(uint64_t Arg1, uint64_t Arg2) {

  if (!__afl_cmp_map) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= CMP_MAP_W - 1;

  __afl_cmp_map->headers[k].type = CMP_TYPE_INS;

  u32 hits = __afl_cmp_map->headers[k].hits;
  __afl_cmp_map->headers[k].hits = hits + 1;

  __afl_cmp_map->headers[k].shape = 7;

  hits &= CMP_MAP_H - 1;
  __afl_cmp_map->log[k][hits].v0 = Arg1;
  __afl_cmp_map->log[k][hits].v1 = Arg2;

}

#if defined(__APPLE__)
#pragma weak __sanitizer_cov_trace_const_cmp1 = __cmplog_ins_hook1
#pragma weak __sanitizer_cov_trace_const_cmp2 = __cmplog_ins_hook2
#pragma weak __sanitizer_cov_trace_const_cmp4 = __cmplog_ins_hook4
#pragma weak __sanitizer_cov_trace_const_cmp8 = __cmplog_ins_hook8

#pragma weak __sanitizer_cov_trace_cmp1 = __cmplog_ins_hook1
#pragma weak __sanitizer_cov_trace_cmp2 = __cmplog_ins_hook2
#pragma weak __sanitizer_cov_trace_cmp4 = __cmplog_ins_hook4
#pragma weak __sanitizer_cov_trace_cmp8 = __cmplog_ins_hook8
#else
void __sanitizer_cov_trace_const_cmp1(uint8_t Arg1, uint8_t Arg2)
    __attribute__((alias("__cmplog_ins_hook1")));
void __sanitizer_cov_trace_const_cmp2(uint16_t Arg1, uint16_t Arg2)
    __attribute__((alias("__cmplog_ins_hook2")));
void __sanitizer_cov_trace_const_cmp4(uint32_t Arg1, uint32_t Arg2)
    __attribute__((alias("__cmplog_ins_hook4")));
void __sanitizer_cov_trace_const_cmp8(uint64_t Arg1, uint64_t Arg2)
    __attribute__((alias("__cmplog_ins_hook8")));

void __sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2)
    __attribute__((alias("__cmplog_ins_hook1")));
void __sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2)
    __attribute__((alias("__cmplog_ins_hook2")));
void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2)
    __attribute__((alias("__cmplog_ins_hook4")));
void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2)
    __attribute__((alias("__cmplog_ins_hook8")));
#endif                                                /* defined(__APPLE__) */

void __sanitizer_cov_trace_switch(uint64_t Val, uint64_t* Cases) {

  for (uint64_t i = 0; i < Cases[0]; i++) {

    uintptr_t k = (uintptr_t)__builtin_return_address(0) + i;
    k = (k >> 4) ^ (k << 8);
    k &= CMP_MAP_W - 1;

    __afl_cmp_map->headers[k].type = CMP_TYPE_INS;

    u32 hits = __afl_cmp_map->headers[k].hits;
    __afl_cmp_map->headers[k].hits = hits + 1;

    __afl_cmp_map->headers[k].shape = 7;

    hits &= CMP_MAP_H - 1;
    __afl_cmp_map->log[k][hits].v0 = Val;
    __afl_cmp_map->log[k][hits].v1 = Cases[i + 2];

  }

}

// POSIX shenanigan to see if an area is mapped.
// If it is mapped as X-only, we have a problem, so maybe we should add a check
// to avoid to call it on .text addresses
static int area_is_mapped(void* ptr, size_t len) {

  char* p = ptr;
  char* page = (char*)((uintptr_t)p & ~(sysconf(_SC_PAGE_SIZE) - 1));

  int r = msync(page, (p - page) + len, MS_ASYNC);
  if (r < 0) return errno != ENOMEM;
  return 1;

}

void __cmplog_rtn_hook(void* ptr1, void* ptr2) {

  if (!area_is_mapped(ptr1, 32) || !area_is_mapped(ptr2, 32)) return;

  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= CMP_MAP_W - 1;

  __afl_cmp_map->headers[k].type = CMP_TYPE_RTN;

  u32 hits = __afl_cmp_map->headers[k].hits;
  __afl_cmp_map->headers[k].hits = hits + 1;

  __afl_cmp_map->headers[k].shape = 31;

  hits &= CMP_MAP_RTN_H - 1;
  __builtin_memcpy(((struct cmpfn_operands*)__afl_cmp_map->log[k])[hits].v0,
                   ptr1, 32);
  __builtin_memcpy(((struct cmpfn_operands*)__afl_cmp_map->log[k])[hits].v1,
                   ptr2, 32);

}
