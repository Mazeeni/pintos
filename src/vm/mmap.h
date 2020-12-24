#ifndef VM_MMAP_H
#define VM_MMAP_H
#include "lib/kernel/list.h"
#include "lib/stdio.h"
#include "lib/user/syscall.h"
#include <debug.h>

/* An entry for the memory mapped files table. */
struct mm_entry {
  int map_id;               /* Unique id for each map entry. */
  struct file *file;        /* Associated file. */
  void *uaddr;              /* Load virtual user address. */
  struct list_elem mm_elem; /* List element for the table. */
};

/* Mapping checks */
#define IS_CONSOLE_FD(fd) (fd == STDIN_FILENO || fd == STDOUT_FILENO)
#define IS_INVALID_ADDR(addr) (addr == NULL || is_kernel_vaddr(addr))

void free_mm_table(struct list *mm_table);
mapid_t mmap(int fd, void *addr);
void munmap(mapid_t mapping);

#endif /* vm/mmap.h */