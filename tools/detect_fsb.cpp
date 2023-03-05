#include "branch_pred.h"
#include "libdft_api.h"
#include "pin.H"
#include "syscall_desc.h"
#include "syscall_hook.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

extern syscall_desc_t syscall_desc[SYSCALL_MAX];
extern ins_desc_t ins_desc[XED_ICLASS_LAST];

ADDRINT plt_printf = 0;

static void
check_string_taint(CONTEXT *ctxt, ADDRINT ip, ADDRINT target){
  
  if(target != plt_printf) return;

  ADDRINT rdiValue = PIN_GetContextReg(ctxt, REG_RDI);
  char buffer[1024] = {0,};

  PIN_SafeCopy(buffer, (VOID*)rdiValue, sizeof(buffer));
  fprintf(stderr, "[INFO] string may have been truncated\n");
  
  size_t size = 0;

  // Get the size of the string by finding the index of the null terminator
  for(size = 0 ; size < 1024; size++){
    if(buffer[size] == 0x0a) break;
  }

  ADDRINT end = rdiValue + size;
  uint8_t tag;

  for(ADDRINT addr = rdiValue; addr <= end; addr++){
    tag = tagmap_getb(addr);
    if(tag != 0){
      fprintf(stderr, "\n\n\n[WARNING] !!! ADDRESS %p IS TAINTED (tag=0x%02x), ABORTING !!!!!\n\n\n",
            (void *)addr,
            (unsigned int)tag);
      exit(1);
    }
  }
  
}

static void 
image_load(IMG img, VOID *v){
    if(IMG_IsMainExecutable(img)){

      for(SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)){

        if(SEC_Name(sec) == ".plt"){
          for(RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)){

            if(RTN_Name(rtn) == "printf@plt"){
                plt_printf = RTN_Address(rtn);
                break;
            }
          }
          break;
        }
      }

      if(plt_printf == 0){
        fprintf(stderr, "[ERROR] cannot retreive plt of printf()\n");
        exit(1);
      }
    }

}

static void
post_read_hook(THREADID tid, syscall_ctx_t *ctx){
  // read() was not successful; optimized branch
  if (unlikely((long)ctx->ret <= 0)) return;

  // only receive input data from STDIN(0)
  if(ctx->arg[SYSCALL_ARG0] != STDIN_FILENO) return ;

  // set the tag marking
  tagmap_setn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret, 0x01);
  fprintf(stderr, "[INFO] tainting bytes %p ~ %p (tainted byte : %lu)\n", 
          (void *)ctx->arg[SYSCALL_ARG1],
          (void *)(ctx->arg[SYSCALL_ARG1] + (size_t)ctx->ret),
          (size_t)ctx->ret - 1 );
  
}

static void
dta_instrument_call(INS ins){

  if(!INS_IsCall(ins)) return;

  INS_InsertCall(ins,
      IPOINT_BEFORE,
      (AFUNPTR)check_string_taint,
      IARG_CONTEXT ,  
      IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR,
      IARG_END);

}

int main(int argc, char **argv){
  /* initialize symbol processing */
  PIN_InitSymbols();

  /* initialize Pin; optimized branch */
  if (unlikely(PIN_Init(argc, argv)))
    /* Pin initialization failed */
    goto err;

  /* initialize the core tagging engine */
  if (unlikely(libdft_init() != 0))
    /* failed */
    goto err;

  IMG_AddInstrumentFunction(image_load, 0);
  syscall_set_post(&syscall_desc[__NR_read], post_read_hook);
  ins_set_post(&ins_desc[XED_ICLASS_CALL_NEAR], dta_instrument_call);
	

  /* start Pin */
  PIN_StartProgram();

  /* typically not reached; make the compiler happy */
  return EXIT_SUCCESS;

err: /* error handling */
  /* return */
  return EXIT_FAILURE;
}
