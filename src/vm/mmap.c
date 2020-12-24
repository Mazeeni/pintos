#include "vm/mmap.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "vm/frame.h"

static void unmapping(struct mm_entry *entry);
static struct mm_entry *mm_table_lookup(int mapping);

/* Iterates through the memory mapped file table, unmapping and freeing each
 * entry. */
void free_mm_table(struct list *mm_table) {
  file_lock_acquire();
  while (!list_empty(mm_table)) {
    struct mm_entry *entry =
        list_entry(list_pop_front(mm_table), struct mm_entry, mm_elem);
    unmapping(entry);
    free(entry);
  }
  file_lock_release();
}

/* Added supplemental page table entries for file identified by 'fd' starting at
 * user virtual address 'uaddr'. */
mapid_t mmap(int fd, void *addr) {
  /* Check if fd is not for consoles and addr is valid. */
  if (IS_CONSOLE_FD(fd) || IS_INVALID_ADDR(addr) || pg_ofs(addr)) {
    return MAP_FAILED;
  }

  /* Check current thread has a file opened with specified fd. */
  struct fd_entry *fd_entry = fd_table_lookup(fd);
  if (fd_entry == NULL) {
    return MAP_FAILED;
  }

  /* Reopen the file to not interfere with system calls.  */
  struct file *file = file_reopen(fd_entry->file);
  if (file == NULL) {
    return MAP_FAILED;
  }

  size_t size = file_length(file);
  if (size == 0) {
    file_close(file);
    return MAP_FAILED;
  }

  /* Check if file can be loaded into user memory at specified addr.  */
  struct thread *t = thread_current();

  for (uintptr_t offset = 0; offset < size; offset += PGSIZE) {
    if (spt_contains(&t->spt, addr + offset)) {
      file_close(file);
      return MAP_FAILED;
    }
  }

  /* Add entries to spt for current thread.  */
  bool writable = true;
  uintptr_t offset = 0;

  for (size_t i = 0; i < size / PGSIZE; i++) {
    spt_add_file_page(file, fd_entry->file_name, offset, addr + offset, PGSIZE,
                      INITIAL, writable, MMAP);
    offset += PGSIZE;
  }

  uint32_t remaining = size % PGSIZE;
  if (remaining != 0) {
    spt_add_file_page(file, fd_entry->file_name, offset, addr + offset,
                      remaining, PGSIZE - remaining, writable, MMAP);
  }

  /* Add entry to the current threads mm_list.  */
  struct mm_entry *new_entry = malloc(sizeof(*new_entry));
  if (new_entry == NULL) {
    file_close(file);
    return MAP_FAILED;
  }

  new_entry->file = file;
  new_entry->uaddr = addr;
  new_entry->map_id = t->next_mapping++;

  list_push_back(&t->mm_table, &new_entry->mm_elem);

  return new_entry->map_id;
}

/* Unmap supplemental page table entry 'entry'. It goes through all the pages
 * for the mapped file and writes the page back to the file if it has been
 * written to. */
static void unmapping(struct mm_entry *entry) {
  struct file *file = entry->file;
  size_t size = file_length(file);
  uint32_t *pd = thread_current()->pagedir;

  for (void *cur_page = entry->uaddr; cur_page < entry->uaddr + size;
       cur_page += PGSIZE) {
    struct spt_entry *spt_entry =
        spt_get_entry(&thread_current()->spt, cur_page);

    /* Only write page back to file is changed. */
    if (frame_is_dirty(spt_entry->kaddr)) {
      file_write_at(file, cur_page, PGSIZE, spt_entry->spt_file.ofs);
    }

    spt_remove(cur_page, pd);
  }
  file_close(file);
}

/* Function that will look up the memory map entry in the table using the
 * integer identifier for it. */
static struct mm_entry *mm_table_lookup(int mapping) {
  struct list_elem *e;
  struct list *mm_table = &thread_current()->mm_table;

  for (e = list_begin(mm_table); e != list_end(mm_table); e = list_next(e)) {
    struct mm_entry *cur = list_entry(e, struct mm_entry, mm_elem);
    if (cur->map_id == mapping) {
      return cur;
    }
  }
  return DEFAULT_RETURN;
}

/* Looks up the mm_entry in the mappings table and then calls the function
 * 'munmapping' with that entry. It acquires the file lock during this call and
 * removes the entry from the table. */
void munmap(mapid_t mapping) {

  struct mm_entry *entry = mm_table_lookup(mapping);

  if (entry == NULL) {
    return;
  }

  file_lock_acquire();
  unmapping(entry);
  file_lock_release();

  list_remove(&entry->mm_elem);
  free(entry);
}
