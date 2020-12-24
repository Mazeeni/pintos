#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "lib/kernel/list.h"
#include "lib/stdio.h"
#include "vm/page.h"
#include <debug.h>

/* Used by system calls to signify an error occurred. */
#define ERROR_CODE -1

/* Used to split large buffers when writing to console. */
#define MAX_PUTBUF_SIZE (256)

/* Default return value used by system calls. */
#define DEFAULT_RETURN (0)

/* Maximum number of characters for a file name (14 + 1 for sentinel). */
#define MAX_FILE_NAME (15)

/* Used to efficiently check pointers, for system calls only, when necessary. */
#define MAX_ARG_NUM (3)
enum arg_nums { NO_ARGS, ONE_ARG, TWO_ARGS, THREE_ARGS };

struct fd_entry *fd_table_lookup(int fd);

/* File descriptor entry for an opened file, stored in the
   file descriptor table. */
struct fd_entry {
  int fd;            /* Unique integer for file descriptor. */
  struct file *file; /* File opened by a process. */
  const char *file_name;
  struct list_elem fd_elem; /* To store entries in file descriptor table. */
};

void syscall_init(void);
void error_exit(void) NO_RETURN;

/* Typedef for all system calls, takes in array of dereferenced arguments and
   returns uint32_t (void system calls return 0).  */
typedef uint32_t(func_sys)(uint32_t *args);

/* SOME COMMENT*/
typedef bool(contains_func)(struct hash *spt, void *uaddr);

#endif /* userprog/syscall.h */
