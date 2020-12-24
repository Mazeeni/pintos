#ifndef USERPROG_EXCEPTION_H
#define USERPROG_EXCEPTION_H

/* Page fault error code bits that describe the cause of the exception.  */
#define PF_P 0x1 /* 0: not-present page. 1: access rights violation. */
#define PF_W 0x2 /* 0: read, 1: write. */
#define PF_U 0x4 /* 0: kernel, 1: user process. */

/* Stack heuristic macros */
#define PUSH_BYTES 4
#define PUSHA_BYTES 32
#define STACK_MAX_SIZE 0x400000

#define STACK_ACCESS(fault_addr, esp)                                          \
  (is_kernel_vaddr(fault_addr + STACK_MAX_SIZE) &&                             \
   (esp <= fault_addr || fault_addr == esp - PUSH_BYTES ||                     \
    fault_addr == esp - PUSHA_BYTES))

void exception_init(void);
void exception_print_stats(void);

#endif /* userprog/exception.h */
