/*
   american fuzzy lop++ - shared memory related code
   -------------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#define AFL_MAIN

#ifdef __ANDROID__
#include "android-ashmem.h"
#endif
#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"
#include "sharedmem.h"
#include "cmplog.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>

#ifndef USEMMAP
#include <sys/ipc.h>
#include <sys/shm.h>
#endif

extern unsigned char *trace_bits;

#ifdef USEMMAP
/* ================ Proteas ================ */
int            g_shm_fd = -1;
unsigned char *g_shm_base = NULL;
char           g_shm_file_path[L_tmpnam];
/* ========================================= */
#else
static s32 shm_id;                     /* ID of the SHM region              */
static s32 cmplog_shm_id;
#endif

int             cmplog_mode;
struct cmp_map *cmp_map;

#ifdef AF

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

static s32 funcbitmap_shm_id; // Function activation bitmap ID
static u32 *__af_fnbitmap_ptr; // Function activation bitmap SHM ptr
static s32 calledge_shm_id; // Calledge ID
//XXX: Initially when we were keeping track of all edges we had set it to 1 because there
// was a calledge from init to main that we were trying to ignore recording. Now since we
// only record indirect calls so we can turn it back to 0
u32 prev_num_calledges = 0; // Last seen number of recorded edges
FILE *logfp;


struct calledge_arr* calledge_arr_ptr; // Calledge array ptr
#ifdef TRACE_METRIC
struct af_input_stats* input_stat_ptr;
static s32 input_stat_shm_id;
#endif 

void set_bit(int n) { 
    __af_fnbitmap_ptr[WORD_OFFSET(n)] |= ((u32) 1 << BIT_OFFSET(n));
}

void turn_on_funcbmp() {
    #ifdef LOG
      logfp = fopen("/tmp/log.txt", "a+");
      fprintf(logfp, "Turning on activation bitmap");
      fclose(logfp);
    #endif 
    u32 mapped_size = MAP_SIZE / sizeof(u32);
    for (int x = 0; x < mapped_size; x++)
        __af_fnbitmap_ptr[x] |= 0xFFFFFFFF; 
}

void turn_off_funcbmp() {
    #ifdef LOG
      logfp = fopen("/tmp/log.txt", "a+");
      fprintf(logfp, "Turning off activation bitmap");
      fclose(logfp);
    #endif 
    u32 mapped_size = MAP_SIZE / sizeof(u32);
    for (int x = 0; x < mapped_size; x++)
        __af_fnbitmap_ptr[x] &= 0x00000000; 
}

void clear_bit(int n) {
    __af_fnbitmap_ptr[WORD_OFFSET(n)] &= ~((u32) 1 << BIT_OFFSET(n)); 
}

#endif


/* Get rid of shared memory (atexit handler). */

void remove_shm(void) {

#ifdef USEMMAP
  if (g_shm_base != NULL) {

    munmap(g_shm_base, MAP_SIZE);
    g_shm_base = NULL;

  }

  if (g_shm_fd != -1) {

    close(g_shm_fd);
    g_shm_fd = -1;

  }

#else
  shmctl(shm_id, IPC_RMID, NULL);
  if (cmplog_mode) shmctl(cmplog_shm_id, IPC_RMID, NULL);
  #ifdef AF
  shmctl(funcbitmap_shm_id, IPC_RMID, NULL);
  shmctl(calledge_shm_id, IPC_RMID, NULL);
  #endif
#endif

}

/* Configure shared memory. */

void setup_shm(unsigned char dumb_mode) {

#ifdef USEMMAP
  /* generate random file name for multi instance */

  /* thanks to f*cking glibc we can not use tmpnam securely, it generates a
   * security warning that cannot be suppressed */
  /* so we do this worse workaround */
  snprintf(g_shm_file_path, L_tmpnam, "/afl_%d_%ld", getpid(), random());

  /* create the shared memory segment as if it was a file */
  g_shm_fd = shm_open(g_shm_file_path, O_CREAT | O_RDWR | O_EXCL, 0600);
  if (g_shm_fd == -1) { PFATAL("shm_open() failed"); }

  /* configure the size of the shared memory segment */
  if (ftruncate(g_shm_fd, MAP_SIZE)) {

    PFATAL("setup_shm(): ftruncate() failed");

  }

  /* map the shared memory segment to the address space of the process */
  g_shm_base =
      mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, g_shm_fd, 0);
  if (g_shm_base == MAP_FAILED) {

    close(g_shm_fd);
    g_shm_fd = -1;
    PFATAL("mmap() failed");

  }

  atexit(remove_shm);

  /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on, perhaps? */

  if (!dumb_mode) setenv(SHM_ENV_VAR, g_shm_file_path, 1);

  trace_bits = g_shm_base;

  if (trace_bits == -1 || !trace_bits) PFATAL("mmap() failed");

#else
  u8 *shm_str;

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

  if (shm_id < 0) PFATAL("shmget() failed");

  if (cmplog_mode) {

    cmplog_shm_id = shmget(IPC_PRIVATE, sizeof(struct cmp_map),
                           IPC_CREAT | IPC_EXCL | 0600);

    if (cmplog_shm_id < 0) PFATAL("shmget() failed");

  }

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on, perhaps? */

  if (!dumb_mode) setenv(SHM_ENV_VAR, shm_str, 1);

  ck_free(shm_str);

  if (cmplog_mode) {

    shm_str = alloc_printf("%d", cmplog_shm_id);

    if (!dumb_mode) setenv(CMPLOG_SHM_ENV_VAR, shm_str, 1);

    ck_free(shm_str);

  }

  trace_bits = shmat(shm_id, NULL, 0);

  if (trace_bits == (void *)-1 || !trace_bits) PFATAL("shmat() failed");

  if (cmplog_mode) {

    cmp_map = shmat(cmplog_shm_id, NULL, 0);

    if (cmp_map == (void *)-1 || !cmp_map) PFATAL("shmat() failed");

  }

  #ifdef AF
    

    // Setup function activation bitmap
    funcbitmap_shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);
    if (funcbitmap_shm_id < 0) PFATAL("shmget() failed");

    __af_fnbitmap_ptr = (u32*) shmat(funcbitmap_shm_id, NULL, 0);

    shm_str = alloc_printf("%d", funcbitmap_shm_id);
    if (!dumb_mode) setenv(FUNCMAP_SHM_ENV_VAR, shm_str, 1);
    ck_free(shm_str);


    // // Initialize it with function activation bitmap
    // u8* funcbitmap_file = NULL;
    // funcbitmap_file = getenv(FNINDICES_VAR);
    // // Initialize the bitmap based on initfile 
    // // XXX: No init file will exist only in two possible scenarios:
    // // 1) User forgot to provide an init file
    // // 2) During target compilation, some intermediary binaries are created and executed (eg. conftest)
    // // 1 is erroneous while 2 is benign. However, assuming user sanity and 2 might prevent the compilation
    // // from erroring out incorrectly. So, in the case of no initfile being
    // // provided we activate the entire function bitmap. This is done under the implicit assumption that Scenario 2
    // // is the default which is being triggered.
    // // A more involved check to ensure that this is done only in the case of 2 and not 1 would be to check creation
    // // time of `/tmp/fn_indices.txt` and ensure that it is within an acceptable delta from the current unix time but
    // // we leave that since right now we are merely doing prototype testing under controlled conditions
    // if (! funcbitmap_file) {
    //     u32 mapped_size = MAP_SIZE / sizeof(u32);
    //     for (int x = 0; x < mapped_size; x++)
    //        __af_fnbitmap_ptr[x] |= 0xFFFFFFFF; 
    // }
    // else {
    //     FILE *fp;
    //     char *line = NULL;
    //     size_t len = 0;
    //     int func_bit;
    //     int bmp_idx = 0;
    //     ssize_t read;
    //     #ifdef LOG
    //       logfp = fopen("/tmp/log.txt", "a+");
    //       fprintf(logfp, "\nReading bitmap file"); 
    //       fclose(logfp);
    //     #endif
    //     fp = fopen(funcbitmap_file, "r");
    //     while ((read = getline(&line, &len, fp)) != -1) {
    //       func_bit = get_func_bit(line);
    //       #ifdef LOG
    //         logfp = fopen("/tmp/log.txt", "a+");
    //         fprintf(logfp, "\nFunc bit:%d", func_bit); 
    //         fclose(logfp);
    //       #endif
    //       if (func_bit) {
    //         #ifdef LOG
    //           logfp = fopen("/tmp/log.txt", "a+");
    //           fprintf(logfp, "\nSetting bit:%d", bmp_idx); 
    //           fclose(logfp);
    //         #endif
    //         set_bit(bmp_idx);
    //       }
    //       bmp_idx += 1;
    //     }
    //     fclose(fp);
    //     free(line);
    // }


    // Create calledge control structure 
    calledge_arr_ptr = (struct calledge_arr*)calloc(1, sizeof(struct calledge_arr));

    // Create references to SHM in the control structure. The SHM is maintained
    // as follows:
    // | NUMELEMENTS | LIMIT | <CALLEDGES.....|
    // References to each of these fields is maintained in the control structure `calledge_arr`
    calledge_shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

    if (calledge_shm_id < 0) PFATAL("shmget() failed");

    void *tmp_ptr = shmat(calledge_shm_id, NULL, 0);
    calledge_arr_ptr->numelements = (u32*) tmp_ptr;
    calledge_arr_ptr->limit = (u32*) tmp_ptr + 1;
    calledge_arr_ptr->base_ptr = (s64*) tmp_ptr + 2; 

    // Initialize calledge control structure 
    *(calledge_arr_ptr->numelements) = 0 ;
    *(calledge_arr_ptr->limit) = (MAP_SIZE - 8) / sizeof(s64) ;

    shm_str = alloc_printf("%d", calledge_shm_id);

    if (!dumb_mode) setenv(CALLEDGE_SHM_ENV_VAR, shm_str, 1);

    ck_free(shm_str);

    // Create counter for function trace length
    #ifdef TRACE_METRIC
      input_stat_ptr = (struct af_input_stats*)calloc(1, sizeof(struct af_input_stats));
      input_stat_shm_id = shmget(IPC_PRIVATE, sizeof(u64), IPC_CREAT | IPC_EXCL | 0600);
      if (input_stat_shm_id < 0) PFATAL("shmget() failed");
      void *tmp_stat_ptr = shmat(input_stat_shm_id, NULL, 0);
      input_stat_ptr->tracelength_ptr = (u64*) tmp_stat_ptr;

      shm_str = alloc_printf("%d", input_stat_shm_id);
      if (!dumb_mode) setenv(INPUTSTATS_ENV_VAR, shm_str, 1);
      ck_free(shm_str);
   #endif

 #endif //AF


#endif

}

