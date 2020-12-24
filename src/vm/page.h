#ifndef VM_PAGE_H
#define VM_PAGE_H
#include "filesys/file.h"
#include "filesys/off_t.h"
#include <hash.h>

/* Types of spt entries.  */
enum page_status { ZERO, EXECUTABLE, FRAME, SWAP, MMAP };
#define INITIAL (0) /* Setting members when creating a new spt entry */

/* Stores metadata for a file page. Member of spt_entry.  */
struct spt_file {
  struct file *file;    /* Associated file.  */
  unsigned hashed_name; /* hashed name of file.  */
  off_t ofs;            /* offset into the file.  */
  size_t read_bytes;    /* No. of bytes to read.  */
  size_t zero_bytes;    /* No. of bytes zeroed after.  */
};

/* Stores information on lazily loaded page. */
struct spt_entry {

  void *uaddr;       /* virtual user address. */
  void *kaddr;       /* virtual kernal address. NULL if not loaded.  */
  size_t swap_index; /* Identifier for swap slot. Used for eviction.  */

  enum page_status status; /* Type of page.  */
  struct hash_elem helem;  /* Used for spt_table.  */

  bool writable : 1;        /* Can page be written over.  */
  struct spt_file spt_file; /* metadata on associated file.  */
};

unsigned page_hash(const struct hash_elem *e, void *aux);
bool page_hash_less(const struct hash_elem *a, const struct hash_elem *b,
                    void *aux);
bool spt_add_file_page(struct file *file, const char *file_name, off_t ofs,
                       uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes,
                       bool writable, enum page_status status);
bool spt_contains(struct hash *spt, void *uaddr);
bool spt_contains_writable(struct hash *spt, void *uaddr);
struct hash_elem *spt_find_entry(struct hash *spt, void *uaddr);
struct spt_entry *spt_get_entry(struct hash *spt, void *uaddr);
bool spt_add_stack_page(void *kaddr, uint8_t *upage);
bool spt_add_zero_page(struct hash *spt, void *uaddr);
bool spt_load_page(struct spt_entry *spt_entry);
void spt_remove(uint8_t *addr, uint32_t *pd);
void spt_free_table(void);

#endif /* vm/page.h */