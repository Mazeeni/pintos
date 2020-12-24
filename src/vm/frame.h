#ifndef VM_FRAME_H
#define VM_FRAME_H
#include "filesys/off_t.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include <hash.h>

/* Returned if frame_entry not returned in lookup. */
#define FAILURE NULL

/* Pair entry which stores the spt_entry and pointer to the page table of the
 * associated thread. Used in the management of sharing frames. */
struct spt_pd_pair {
  struct spt_entry *spt_entry;
  uint32_t *pd;
  struct list_elem pair_elem; /* The list element for the list of spt_entry's
                                 in a particular frame entry from the frame
                                 table. */
};

/* An entry for the frame table. */
struct frame_entry {
  void *kaddr; /* Associate kernel address (null if non-existent). */
  struct list spt_pd_pairs; /* List of spt_entry pd pairs, which are used to
                               monitor all process spt's that are sharing the
                               frame. */
  struct lock shared_lock;  /* Lock used to synchronise accesses to shared
                               frame data. */
  unsigned hashed_name;     /* The hashed name of the file
                               (null if non-existent).   */
  off_t offset; /* The offset in the file the frame corresponds to. */
  bool pinned;  /* Set to true when frame should not be evicted. */
  struct hash_elem frame_elem; /* hash_elem used for keeping a hash table of
                                     frame_entry's in frame table. */

  struct list_elem eviction_elem; /* Element for list used by eviction
                                     algorithm. */
};

void frame_init(void);
void frame_lock_acquire(void);
void frame_lock_release(void);

struct frame_entry *frame_allocate(enum palloc_flags flags,
                                   unsigned hashed_name, off_t offset);
struct spt_pd_pair *frame_find_pair(struct spt_entry *spt_entry,
                                    struct frame_entry *frame);
void frame_free(struct frame_entry *frame);
struct frame_entry *frame_get_entry(void *addr);
struct frame_entry *frame_find_page(unsigned hashed_name, off_t offset);
void frame_add_pair(struct frame_entry *frame, struct spt_entry *spt_entry,
                    uint32_t *pd);
void frame_free_pair(struct spt_entry *spt_entry, struct frame_entry *frame);
void frame_free_all_pairs(struct frame_entry *frame);
void frame_free_table(void);
void pin_and_load_buff(const void *uaddr, size_t size);
void unpin_buffer(const void *uaddr, unsigned size);
bool frame_is_dirty(void *kaddr);

#endif /* vm/frame.h */