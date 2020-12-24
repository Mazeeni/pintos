#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "lib/user/syscall.h"
#include "threads/synch.h"
#include "threads/thread.h"

/* Takes into account pushes that are guaranteed to occur (in bytes)
   Calculation: (null sentinel + return address + argc + argv) = (4 + 4 + 4 + 4)
 */
#define MAX_WORD_ALIGN (3)
#define MINIMUM_STACK_SIZE (16 + MAX_WORD_ALIGN)

#define MIN_WAIT_TID (2)

/* Third-party process structure so processes can stay alive if needed when
   threads exit.
   Our booleans are stored as 1-bit bit fields to save space */
struct process {
  pid_t pid;       /* Process id (1-1 mapping to thread's tid). */
  int exit_status; /* Stores exit status for process to be used by parent. */
  int next_fd;     /* Integer of next available file descriptor. */

  bool parent_waiting : 1; /* Set if parent calls wait() on the child. */
  bool exited : 1;         /* Set if process has successfully exited. */
  bool exited_parent : 1;  /* Set if parent has successfully exited. */
  bool is_loaded : 1;      /* Set if user program has successfully loaded. */

  struct file *executable;       /* The user program file. */
  struct list fd_table;          /* File descriptor table. */
  struct list_elem process_elem; /* To store a process' children. */
  struct semaphore sema_wait;    /* Sema used by parent to either: wait for
                                    child program to finish loading or wait for
                                    child program to exit (if necessary). */
};

/* Created to be an auxiliary argument when passed into thread_create(). */
struct process_args {
  char **argv;             /* List of arguments to pass to new program. */
  int argc;                /* Number of arguments of new program. */
  struct process *process; /* Pointer to process that will be used by child. */
};

void initialise_file_lock(void);
void initialise_exit_lock(void);
void file_lock_acquire(void);
void file_lock_release(void);

tid_t process_execute(const char *file_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);

bool install_page(void *upage, void *kpage, bool writable);

#endif /* userprog/process.h */
