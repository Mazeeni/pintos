#include "userprog/syscall.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/kernel/stdio.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <syscall-nr.h>

#ifdef VM
#include "vm/frame.h"
#include "vm/mmap.h"
#endif

static void syscall_handler(struct intr_frame *f);

/* System call functions. */
static uint32_t syscall_exit(uint32_t *args) NO_RETURN;
static uint32_t syscall_write(uint32_t *args);
static uint32_t syscall_exec(uint32_t *args);
static uint32_t syscall_wait(uint32_t *args);
static uint32_t syscall_halt(uint32_t *args UNUSED) NO_RETURN;
static uint32_t syscall_create(uint32_t *args);
static uint32_t syscall_remove(uint32_t *args);
static uint32_t syscall_open(uint32_t *args);
static uint32_t syscall_filesize(uint32_t *args);
static uint32_t syscall_read(uint32_t *args);
static uint32_t syscall_seek(uint32_t *args);
static uint32_t syscall_tell(uint32_t *args);
static uint32_t syscall_close(uint32_t *args);
static uint32_t syscall_mmap(uint32_t *args);
static uint32_t syscall_munmap(uint32_t *args);

/* Functions for memory checks. */
static void check_pointer(void *ptr, contains_func *contains);
static void check_arg_pointers(void *esp, uint32_t *args, int arg_num);
static bool check_string_pointers(const char *file_name, int limit);
static void check_buffer(char *buffer, unsigned size, contains_func *contains);

/* Function pointer array containing all system call function pointers. Used in
 * syscall_handler to call the needed system call function quickly in constant
 * time */
static func_sys *syscall_functions[] = {
    syscall_halt,   syscall_exit,   syscall_exec,  syscall_wait,
    syscall_create, syscall_remove, syscall_open,  syscall_filesize,
    syscall_read,   syscall_write,  syscall_seek,  syscall_tell,
    syscall_close,  syscall_mmap,   syscall_munmap};

/* Int array containing the number of arguments each system call
function takes, used to ensure pointer checks and dereferencing
only occurs for needed arguments. */
static enum arg_nums syscall_arg_nums[] = {
    NO_ARGS,  ONE_ARG, ONE_ARG, ONE_ARG,    TWO_ARGS,
    ONE_ARG,  ONE_ARG, ONE_ARG, THREE_ARGS, THREE_ARGS,
    TWO_ARGS, ONE_ARG, ONE_ARG, TWO_ARGS,   ONE_ARG};

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Used to call syscall_exit with exit status -1 from other functions
as syscall_exit takes a uint32_t* as input. Allows syscall_exit to
remain static so its only visible in syscall.c. */
void error_exit(void) {
  uint32_t error_args[] = {ERROR_CODE};
  syscall_exit(error_args);
}

/* Checks the validity of an address, if it is NULL, not a valid user
virtual address or does not exist in the current page directory then exit
with error code -1. */
static void check_pointer(void *ptr, contains_func *contains) {
  bool invalid_address = ptr == NULL || !is_user_vaddr(ptr);

#ifdef VM
  invalid_address |= !contains(&thread_current()->spt, pg_round_down(ptr));
#else
  invalid_address |= pagedir_get_page(thread_current()->pagedir, ptr) == NULL;
#endif

  if (invalid_address) {
    error_exit();
  }
}

/* Checks the address of the arguments, if address is valid then
argument is dereferenced and assigned to the arg array. If not
valid then it exits with error code -1 in check_pointer.
arg_num ensures only necessary number of arguments checked and
dereferenced. */
static void check_arg_pointers(void *esp, uint32_t *args, int arg_num) {
  for (int i = 0; i < arg_num; i++) {
    check_pointer(esp + i * sizeof(uintptr_t), spt_contains);
    args[i] = *(uint32_t *)(esp + i * sizeof(uintptr_t));
  }
}

/* Iterates byte by byte through a string, checking the validity of
each byte's pointer, if invalid then exit with error code -1 in
check_pointer. If all pointers valid then iterates until the string
ends when byte is equal to the null character returning true or if
limit is reached return false as string is too long. */
static bool check_string_pointers(const char *file_name, int limit) {
  for (int i = 0; i < limit; i++) {
    check_pointer((void *)file_name + i, spt_contains);
    if (file_name[i] == '\0') {
      return true;
    }
  }
  return false;
}

/* Iterates page by page checking the validity of the buffer, first
checks buffer and buffer+size (if necessary) to ensure whole buffer
is valid before being written/read. If buffer+size is on the same
page as buffer and check_pointer for buffer is valid then it returns
to prevent unnecessary additional checks. */
static void check_buffer(char *buffer, unsigned size, contains_func *contains) {
  check_pointer(buffer, contains);
  if (pg_ofs(buffer) >= size) {
    return;
  }

  check_pointer(buffer + size, contains);

  for (char *check_addr = buffer + PGSIZE; check_addr < buffer + size;
       check_addr += PGSIZE) {
    check_pointer(check_addr, contains);
  }
}

/* Checks the address of the stack pointer and exits with error code -1 if
invalid address or not a supported system call when dereferenced.
Calls check_arg_pointers to validate and dereference arguments.
Then uses function pointer array syscall_functions to call the necessary
system call function. eax register set to value returned by system call. */
static void syscall_handler(struct intr_frame *f) {
#ifdef VM
  check_pointer(f->esp, spt_contains);
#else
  check_pointer(f->esp, NULL);
#endif

  int syscall_number = *((int *)(f->esp));

  if (syscall_number < SYS_HALT || syscall_number > SYS_MUNMAP) {
    error_exit();
  }

  uint32_t args[MAX_ARG_NUM];
  check_arg_pointers(f->esp + sizeof(uintptr_t), args,
                     syscall_arg_nums[syscall_number]);

#ifdef VM
  thread_current()->esp = f->esp;
#endif

  f->eax = syscall_functions[syscall_number](args);
}

/* Terminates Pintos. */
static uint32_t syscall_halt(uint32_t *args UNUSED) {
  shutdown_power_off();
  NOT_REACHED();
}

/* Terminates current user program and sends its exit status to
the kernel. Success if error status = 0 otherwise an error occurred. */
static uint32_t syscall_exit(uint32_t *args) {
  int exit_code = args[0];
  struct thread *t = thread_current();

  printf("%s: exit(%d)\n", t->name, exit_code);
  t->process->exit_status = exit_code;

#ifdef VM
  free_mm_table(&t->mm_table);
#endif

  thread_exit();
  NOT_REACHED();
}

/* Runs executable from the command line returning its PID.
If cmd_line string invalid or executable unable to load then
returns PID_ERROR. Calls process_execute which does not return
until child processes have completed their attempt to load. */
static uint32_t syscall_exec(uint32_t *args) {
  const char *cmd_line = (char *)args[0];

  if (!check_string_pointers(cmd_line, PGSIZE)) {
    return PID_ERROR;
  };

  return process_execute(cmd_line);
}

/* Calls process_wait which waits for a child process with PID
and retrieves its exit status. */
static uint32_t syscall_wait(uint32_t *args) {
  int pid = args[0];

  return process_wait(pid);
}

/* Creates a new file of size 'initial_size' and name 'file_name'.
Calls check_string_pointers to check all pointers in file_name
is valid and its size is less than the MAX_FILE_NAME (14 + 1) characters.
file_lock used to synchronize calls to file/filesys functions. */
static uint32_t syscall_create(uint32_t *args) {
  const char *file_name = (const char *)args[0];
  unsigned initial_size = args[1];

  if (!check_string_pointers(file_name, MAX_FILE_NAME)) {
    return false;
  }

  file_lock_acquire();
  bool file_created = filesys_create(file_name, initial_size);
  file_lock_release();

  return file_created;
}

/* Removes a file with name 'file_name'. Calls check_string_pointers to
check all pointers in file_name is valid and its size is less than
the MAX_FILE_NAME (14 + 1) characters before removal.
file_lock used to synchronize calls to file/filesys functions. */
static uint32_t syscall_remove(uint32_t *args) {
  const char *file_name = (const char *)args[0];

  if (!check_string_pointers(file_name, MAX_FILE_NAME)) {
    return false;
  }

  file_lock_acquire();
  bool file_removed = filesys_remove(file_name);
  file_lock_release();

  return file_removed;
}

/* Opens a file with name 'file_name'. Calls check_string_pointers to
check all pointers in file_name are valid and its size is less than
the MAX_FILE_NAME (14 + 1) characters before attempting.
Adds the open file to file descriptor table of the current process
and assigns it a unique fd of 2 or greater and increments next_fd.
file_lock used to synchronize calls to file/filesys functions. */
static uint32_t syscall_open(uint32_t *args) {
  const char *file_name = (const char *)args[0];

  if (!check_string_pointers(file_name, MAX_FILE_NAME)) {
    return ERROR_CODE;
  }
  file_lock_acquire();
  struct file *file = filesys_open(file_name);
  file_lock_release();
  if (file == NULL) {
    return ERROR_CODE;
  }

  struct fd_entry *fd_entry = (struct fd_entry *)malloc(sizeof(*fd_entry));
  if (fd_entry == NULL) {
    file_lock_acquire();
    file_close(file);
    file_lock_release();
    return ERROR_CODE;
  }

  /* Add file and fd to file descriptor table of current process. */
  struct process *process = thread_current()->process;
  fd_entry->file = file;
  fd_entry->file_name = file_name;
  fd_entry->fd = (process->next_fd)++;
  list_push_back(&process->fd_table, &fd_entry->fd_elem);

  return fd_entry->fd;
}

/* Returns the length in bytes of the file open with file descriptor
fd. If fd is invalid returns 0.
file_lock used to synchronize calls to file/filesys functions. */
static uint32_t syscall_filesize(uint32_t *args) {
  int fd = args[0];

  struct fd_entry *fd_entry = fd_table_lookup(fd);
  if (fd_entry == NULL) {
    return DEFAULT_RETURN;
  }

  file_lock_acquire();
  int length = file_length(fd_entry->file);
  file_lock_release();

  return length;
}

/* Reads size bytes from the file relating to fd into buffer and returns
number of bytes actually read. If fd is 0 then reads from STDIN,
if fd is invalid or file cannot be read returns -1. check_buffer called
to ensure safe memory access for the buffer.
file_lock used to synchronize calls to file/filesys functions. */
static uint32_t syscall_read(uint32_t *args) {
  int fd = args[0];
  char *buffer = (char *)args[1];
  unsigned size = args[2];

  check_buffer(buffer, size, spt_contains_writable);

  if (fd == STDIN_FILENO) {
    for (unsigned i = 0; i < size; i++) {
      buffer[i] = input_getc();
    }
    return size;
  }

  struct fd_entry *fd_entry = fd_table_lookup(fd);
  if (fd_entry == NULL) {
    return ERROR_CODE;
  }

#ifdef VM
  pin_and_load_buff(buffer, size);
#endif

  file_lock_acquire();
  int bytes_read = file_read(fd_entry->file, buffer, size);
  file_lock_release();

#ifdef VM
  unpin_buffer(buffer, size);
#endif

  return bytes_read;
}

/* Writes size bytes from buffer into file relating to fd and returns
number of bytes actually written. If fd is 1 then writes to console,
if fd is 0 or invalid returns 0 as no bytes can be written.
check_buffer called to ensure safe memory access for the buffer.
file_lock used to synchronize calls to file/filesys functions. */
static uint32_t syscall_write(uint32_t *args) {
  int fd = args[0];
  const char *buffer = (const char *)args[1];
  unsigned size = args[2];

  if (fd == STDIN_FILENO) {
    return DEFAULT_RETURN;
  }
  check_buffer((char *)buffer, size, spt_contains);

  /* Breaks up large buffers into MAX_PUTBUF_SIZE(256) bytes
      segments when writing to console. */
  if (fd == STDOUT_FILENO) {
    char *substring;
    int bytes_written = 0;

    for (substring = (char *)buffer;
         substring + MAX_PUTBUF_SIZE < buffer + size;
         substring += MAX_PUTBUF_SIZE) {

      putbuf(substring, MAX_PUTBUF_SIZE);
      bytes_written += MAX_PUTBUF_SIZE;
    }
    putbuf(substring, size - bytes_written);

    return size;
  }

  struct fd_entry *fd_entry = fd_table_lookup(fd);
  if (fd_entry == NULL) {
    return DEFAULT_RETURN;
  }

#ifdef VM
  pin_and_load_buff(buffer, size);
#endif

  file_lock_acquire();
  int bytes_written = file_write(fd_entry->file, buffer, size);
  file_lock_release();

#ifdef VM
  unpin_buffer(buffer, size);
#endif

  return bytes_written;
}

/* Changes the next byte to be read/written to position bytes from
beginning of the file. If fd is invalid do nothing.
file_lock used to synchronize calls to file/filesys functions. */
static uint32_t syscall_seek(uint32_t *args) {
  int fd = args[0];
  unsigned position = args[1];

  struct fd_entry *fd_entry = fd_table_lookup(fd);

  if (fd_entry == NULL) {
    return DEFAULT_RETURN;
  }

  file_lock_acquire();
  file_seek(fd_entry->file, position);
  file_lock_release();

  return DEFAULT_RETURN;
}

/* Returns position of next byte to be read/written from beginning of
the file. If fd is invalid call error_exit as returning 0 would indicate
the start of the file, but file does not exist.
file_lock used to synchronize calls to file/filesys functions. */
static uint32_t syscall_tell(uint32_t *args) {
  int fd = args[0];

  struct fd_entry *fd_entry = fd_table_lookup(fd);
  if (fd_entry == NULL) {
    error_exit();
  }

  file_lock_acquire();
  int next_byte = file_tell(fd_entry->file);
  file_lock_release();

  return next_byte;
}

/* If fd valid closes file, removes fd_entry from the file descriptor
table of the current process and frees fd_entry. If fd not found
in the file descriptor table do nothing and return default.
file_lock used to synchronize calls to file/filesys functions. */
static uint32_t syscall_close(uint32_t *args) {
  int fd = args[0];

  struct fd_entry *fd_entry = fd_table_lookup(fd);
  if (fd_entry == NULL) {
    return DEFAULT_RETURN;
  }

  file_lock_acquire();
  file_close(fd_entry->file);
  file_lock_release();

  list_remove(&fd_entry->fd_elem);
  free(fd_entry);

  return DEFAULT_RETURN;
}

/* Iterates through the file descriptor table of the current process.
If the fd is found in the table then the corresponding fd_entry is
returned. If not found, returns NULL. */
struct fd_entry *fd_table_lookup(int fd) {
  struct list_elem *e;
  struct list *fd_table = &thread_current()->process->fd_table;

  for (e = list_begin(fd_table); e != list_end(fd_table); e = list_next(e)) {
    struct fd_entry *cur_file = list_entry(e, struct fd_entry, fd_elem);
    if (cur_file->fd == fd) {
      return cur_file;
    }
  }
  return NULL;
}

#ifdef VM

static uint32_t syscall_mmap(uint32_t *args) {
  int fd = args[0];
  void *addr = (void *)args[1];

  file_lock_acquire();
  mapid_t map_id = mmap(fd, addr);
  file_lock_release();

  return map_id;
}

static uint32_t syscall_munmap(uint32_t *args) {
  mapid_t mapping = args[0];

  munmap(mapping);

  return DEFAULT_RETURN;
}

#endif
