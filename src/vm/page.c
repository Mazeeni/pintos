#include "vm/page.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>

static void spt_free(struct hash_elem *e, void *aux);

/* Mallocs and initialises a new spt_entry. Returns NULL if unsuccessful. */
static struct spt_entry *spt_add_page(void *uaddr, void *kaddr,
                                      enum page_status status, bool writable,
                                      unsigned hashed_name, off_t ofs,
                                      struct file *file, size_t read_bytes,
                                      size_t zero_bytes) {
  struct spt_entry *new_entry = (struct spt_entry *)malloc(sizeof(*new_entry));
  if (new_entry == NULL) {
    return NULL;
  }
  new_entry->uaddr = uaddr;
  new_entry->kaddr = kaddr;
  new_entry->status = status;
  new_entry->writable = writable;

  new_entry->spt_file.file = file;
  new_entry->spt_file.hashed_name = hashed_name;
  new_entry->spt_file.ofs = ofs;
  new_entry->spt_file.read_bytes = read_bytes;
  new_entry->spt_file.zero_bytes = zero_bytes;

  return new_entry;
}

/* Inserts a new page into the spt_table. Must be an EXECUTABLE or MMAP page. */
bool spt_add_file_page(struct file *file, const char *file_name, off_t ofs,
                       uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes,
                       bool writable, enum page_status status) {
  ASSERT(status == EXECUTABLE || status == MMAP);

  struct spt_entry *new_entry =
      spt_add_page(upage, NULL, status, writable, hash_string(file_name), ofs,
                   file, read_bytes, zero_bytes);
  if (new_entry == NULL) {
    return false;
  }

  struct hash_elem *replace =
      hash_replace(&thread_current()->spt, &new_entry->helem);

  if (replace != NULL) {
    free(hash_entry(replace, struct spt_entry, helem));
  }

  return true;
}

/* Inserts a new page in the spt of type ZERO. */
bool spt_add_zero_page(struct hash *spt, void *uaddr) {
  struct spt_entry *new_entry = spt_add_page(uaddr, NULL, ZERO, true, INITIAL,
                                             INITIAL, NULL, INITIAL, INITIAL);
  if (new_entry == NULL) {
    return false;
  }

  if (hash_insert(spt, &new_entry->helem) != NULL) {
    PANIC("Duplicate entry to spt_table!");
  }
  return true;
}

/* Inserts a new spt_entry of type STACK. */
bool spt_add_stack_page(void *kaddr, uint8_t *upage) {
  struct spt_entry *new_entry = spt_add_page(upage, kaddr, ZERO, true, INITIAL,
                                             INITIAL, NULL, INITIAL, INITIAL);
  if (new_entry == NULL) {
    return false;
  }

  hash_insert(&thread_current()->spt, &new_entry->helem);
  return true;
}

/* Finds an entry in the spt_table with the specified uaddr. Returns null if not
 * found. */
struct hash_elem *spt_find_entry(struct hash *spt, void *uaddr) {
  struct spt_entry mock_entry;
  mock_entry.uaddr = uaddr;
  return hash_find(spt, &mock_entry.helem);
}

/* Determines if there is a entry in the spt_table with the given uaddr. */
bool spt_contains(struct hash *spt, void *uaddr) {
  return spt_find_entry(spt, uaddr) != NULL;
}

/* Determines if there is a entry in the spt_table with the given uaddr that is
 * writable. */
bool spt_contains_writable(struct hash *spt, void *uaddr) {
  struct spt_entry *entry = spt_get_entry(spt, uaddr);
  if (entry == NULL) {
    return false;
  }
  return entry->writable;
}

/* Finds the spt page with the specified uaddr. Returns NULL if not found. */
struct spt_entry *spt_get_entry(struct hash *spt, void *uaddr) {
  struct hash_elem *helem = spt_find_entry(spt, uaddr);
  if (helem != NULL) {
    return hash_entry(helem, struct spt_entry, helem);
  }
  return NULL;
}

/* Loads the contents of the spt page at uaddr. */
bool spt_load_page(struct spt_entry *spt_entry) {

  if (spt_entry == NULL) {
    return false;
  }

  if (spt_entry->status == FRAME) {
    return true;
  }

  /* Check if file page has already been loaded into memory. */
  if (spt_entry->status == EXECUTABLE || spt_entry->status == MMAP) {

    /* Try to find a frame with the same file name and offset. */
    struct frame_entry *frame = frame_find_page(spt_entry->spt_file.hashed_name,
                                                spt_entry->spt_file.ofs);

    /* Point to the frame if found and insert into the pairs list. */
    if (frame != NULL) {
      void *kaddr = frame->kaddr;
      spt_entry->kaddr = kaddr;

      frame_add_pair(frame, spt_entry, thread_current()->pagedir);
      if (!install_page(spt_entry->uaddr, kaddr, spt_entry->writable)) {
        frame_free(frame);
        return false;
      }

      frame->pinned = false;
      return true;
    }
  }

  /* Get an available frame and load in the required data. */
  struct frame_entry *frame = frame_allocate(
      PAL_USER, spt_entry->spt_file.hashed_name, spt_entry->spt_file.ofs);
  void *kpage = frame->kaddr;
  if (kpage == NULL) {
    return false;
  }

  size_t read_bytes;
  switch (spt_entry->status) {
  /* Set an all zero page */
  case ZERO:
    memset(kpage, ZERO, PGSIZE);
    break;

  /* Read file contents from specified file and offset. */
  case MMAP:
  case EXECUTABLE:
    read_bytes = spt_entry->spt_file.read_bytes;

    file_seek(spt_entry->spt_file.file, spt_entry->spt_file.ofs);
    if (file_read(spt_entry->spt_file.file, kpage, read_bytes) !=
        (int)read_bytes) {
      spt_remove(spt_entry->uaddr, thread_current()->pagedir);
      return false;
    }

    memset(kpage + read_bytes, ZERO, spt_entry->spt_file.zero_bytes);
    break;

  /* Already loaded so can break */
  case FRAME:
    break;

  /* Load contents from swap space back into memory. */
  case SWAP:
    swap_get(spt_entry->swap_index, kpage);
    spt_entry->status = FRAME;
    break;
  }

  /* Add pair_entry to frames pairs. */
  spt_entry->kaddr = kpage;
  struct thread *cur = thread_current();
  frame_add_pair(frame, spt_entry, thread_current()->pagedir);

  /* Add page to pd and reset reference/dirty bits. */
  if (!install_page(spt_entry->uaddr, kpage, spt_entry->writable)) {
    frame_free(frame);
    return false;
  }

  /* Reset accessed and dirty bits and unpin page */
  pagedir_set_accessed(cur->pagedir, spt_entry->uaddr, false);
  pagedir_set_dirty(cur->pagedir, spt_entry->uaddr, false);
  frame->pinned = false;

  return true;
}

/* Removes entry from spt_table with the specified uaddr. */
void spt_remove(uint8_t *addr, uint32_t *pd) {
  struct spt_entry mock_spt;
  mock_spt.uaddr = addr;

  struct hash_elem *spt_elem =
      hash_delete(&thread_current()->spt, &mock_spt.helem);
  if (spt_elem == NULL) {
    PANIC("Freeing Non-Allocated Memory!");
  }

  spt_free(spt_elem, pd);
}

/* Frees a spt_entry. If it is the only refernce to a frame, then that is freed.
   If the type is SWAP, the swap entry is freed.  */
static void spt_free(struct hash_elem *e, void *aux) {
  struct spt_entry *spt_entry = hash_entry(e, struct spt_entry, helem);

  void *kaddr = spt_entry->kaddr;
  if (kaddr != NULL) {
    struct frame_entry *frame = frame_get_entry(kaddr);
    frame_free_pair(spt_entry, frame);
    /* Free frame if not sharing.  */
    if (list_empty(&frame->spt_pd_pairs)) {
      frame_free(frame);
    }
    /* Free swap entry.  */
  } else if (spt_entry->status == SWAP) {
    swap_free(spt_entry->swap_index);
  }

  pagedir_clear_page(aux, spt_entry->uaddr);

  free(spt_entry);
}

/* Destroys the spt table.  */
void spt_free_table(void) {
  enum intr_level old_level = intr_disable();
  hash_destroy(&thread_current()->spt, spt_free);
  intr_set_level(old_level);
}

/* Hash function for the spt table. Hashes on the uaddr.  */
unsigned page_hash(const struct hash_elem *e, void *aux UNUSED) {
  const struct spt_entry *page = hash_entry(e, struct spt_entry, helem);
  return hash_bytes(&page->uaddr, sizeof(page->uaddr));
}

/* Compares spt entries by their uaddr.  */
bool page_hash_less(const struct hash_elem *a, const struct hash_elem *b,
                    void *aux UNUSED) {
  const struct spt_entry *page_a = hash_entry(a, struct spt_entry, helem);
  const struct spt_entry *page_b = hash_entry(b, struct spt_entry, helem);

  return page_a->uaddr < page_b->uaddr;
}