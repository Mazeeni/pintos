#include "vm/frame.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/page.h"
#include "vm/swap.h"
#include <debug.h>

/* Table and list containing all the frames currently allocated.
  The list is sorted by time the frame was allocated (used in eviction). */
static struct hash frame_table;
static struct list frame_list;

/* Re-entrant lock for synchronising frame table accesses. */
static struct re_lock frame_lock;

/* Allocates and inserts frame_entry into frame_table. */
static struct frame_entry *frame_add_entry(void *kaddr, unsigned hashed_name,
                                           size_t offset);

/* Functions for eviction algorithm. */
static struct frame_entry *get_victim(void);
static struct list_elem *frame_next(struct list_elem *e);
static bool frame_is_accessed(struct frame_entry *frame);

/* Evicts all pages loaded on the victim frame. */
static void evict_page(struct frame_entry *victim);

/* Hashing functions for frame. */
static unsigned frame_hash(const struct hash_elem *e, void *aux);
static bool frame_hash_less(const struct hash_elem *a,
                            const struct hash_elem *b, void *aux UNUSED);

/* Initialise resources for frame. */
void frame_init(void) {
  hash_init(&frame_table, frame_hash, frame_hash_less, NULL);
  reentrant_lock_init(&frame_lock);
  list_init(&frame_list);
}

/* To synchronise access to frame_table. */
void frame_lock_acquire(void) { reentrant_lock_acquire(&frame_lock); }
void frame_lock_release(void) { reentrant_lock_release(&frame_lock); }

/* Returns a frame that's not in use. A frame will be evicted if necessary to
 * create space. */
struct frame_entry *frame_allocate(enum palloc_flags flags,
                                   unsigned hashed_name, off_t offset) {
  frame_lock_acquire();
  void *addr = palloc_get_page(PAL_USER | flags);

  /* Evict a frame if fail to palloc a page. */
  if (addr == NULL) {
    struct frame_entry *victim = get_victim();

    evict_page(victim);

    frame_free(victim);
    addr = palloc_get_page(PAL_USER | flags);

    /* Additional check for safety but should not occur as page was evicted */
    if (addr == NULL) {
      PANIC("Memory could not be allocated even after eviction!");
    }
  }

  /* Add new frame into frame table. */
  struct frame_entry *frame = frame_add_entry(addr, hashed_name, offset);
  frame_lock_release();
  return frame;
}

/* Allocates and inserts frame_entry into frame_table. */
static struct frame_entry *frame_add_entry(void *kaddr, unsigned hashed_name,
                                           size_t offset) {
  struct frame_entry *new_frame = malloc(sizeof(*new_frame));
  if (new_frame == NULL) {
    PANIC("Unable to allocate memory for new frame_entry.");
  }

  new_frame->kaddr = kaddr;
  new_frame->hashed_name = hashed_name;
  new_frame->offset = offset;
  new_frame->pinned = true;

  list_init(&new_frame->spt_pd_pairs);
  lock_init(&new_frame->shared_lock);

  hash_insert(&frame_table, &new_frame->frame_elem);
  list_push_back(&frame_list, &new_frame->eviction_elem);

  return new_frame;
}

/* Evicts a given frame, writing to swap space or filesystem if necessary. */
static void evict_page(struct frame_entry *victim) {
  struct list *pairs = &victim->spt_pd_pairs;

  lock_acquire(&victim->shared_lock);
  struct spt_pd_pair *pair =
      list_entry(list_pop_front(pairs), struct spt_pd_pair, pair_elem);

  struct spt_entry *spt_entry = pair->spt_entry;

  /* If the frame is from a mmap, is writable and is dirty, then write back to
   * original file. Otherwise, write to swap. */
  if (spt_entry->status == MMAP && spt_entry->writable &&
      frame_is_dirty(victim->kaddr)) {
    file_lock_acquire();
    file_write_at(spt_entry->spt_file.file, victim->kaddr,
                  spt_entry->spt_file.read_bytes, spt_entry->spt_file.ofs);
    file_lock_release();
  } else {
    spt_entry->swap_index = swap_put(victim->kaddr);
    spt_entry->status = SWAP;
  }

  /* Free and unmap all pairs on the frame. */
  spt_entry->kaddr = NULL;
  pagedir_clear_page(pair->pd, spt_entry->uaddr);
  free(pair);

  frame_free_all_pairs(victim);
  lock_release(&victim->shared_lock);
}

/* Our eviction algorithm uses Second Chance algorithm with a list
of frames which will be in order of time inserted */
static struct frame_entry *get_victim(void) {
  frame_lock_acquire();
  for (struct list_elem *e = list_begin(&frame_list);; e = frame_next(e)) {
    struct frame_entry *frame =
        list_entry(e, struct frame_entry, eviction_elem);

    if (!frame_is_accessed(frame) && !frame->pinned) {
      frame_lock_release();
      return frame;
    }
  }
}

/* To make second chance list cyclic */
static struct list_elem *frame_next(struct list_elem *e) {
  if (list_next(e) == list_end(&frame_list)) {
    return list_begin(&frame_list);
  }
  return list_next(e);
}

/* Checks if the frame has been accessed by any of its associated
   uaddrs.  Also resets their accessed bits.  */
static bool frame_is_accessed(struct frame_entry *frame) {
  struct list *pairs = &frame->spt_pd_pairs;
  bool accessed = false;
  lock_acquire(&frame->shared_lock);

  for (struct list_elem *e = list_begin(pairs); e != list_end(pairs);
       e = list_next(e)) {
    struct spt_pd_pair *pair = list_entry(e, struct spt_pd_pair, pair_elem);
    accessed |= pagedir_is_accessed(pair->pd, pair->spt_entry->uaddr);
    pagedir_set_accessed(pair->pd, pair->spt_entry->uaddr, false);
  }
  lock_release(&frame->shared_lock);

  return accessed;
}

/* Checks if the frame has been accessed by any of its associated
   uaddrs. */
bool frame_is_dirty(void *kaddr) {

  /* Acquire frame lock here and releasing frame lock after acquiring the shared
   * lock because it is possible for the condition (frame == NULL) to change
   * between the check and actually acquiring the shared lock (trying to
   * reference a null-type errors). */
  frame_lock_acquire();
  struct frame_entry *frame = frame_get_entry(kaddr);
  if (frame == NULL) {
    return false;
  }

  lock_acquire(&frame->shared_lock);
  frame_lock_release();
  struct list *pairs = &frame->spt_pd_pairs;
  bool dirty = false;

  for (struct list_elem *e = list_begin(pairs); e != list_end(pairs);
       e = list_next(e)) {
    struct spt_pd_pair *pair = list_entry(e, struct spt_pd_pair, pair_elem);
    dirty |= pagedir_is_dirty(pair->pd, pair->spt_entry->uaddr);
  }

  lock_release(&frame->shared_lock);

  return dirty;
}

/* Frees a frame and removes all of its references.  */
void frame_free(struct frame_entry *frame) {
  frame_lock_acquire();
  struct hash_elem *frame_elem = hash_delete(&frame_table, &frame->frame_elem);
  list_remove(&frame->eviction_elem);

  if (frame_elem == NULL) {
    PANIC("Freeing non-allocated memory!");
  }

  palloc_free_page(frame->kaddr);
  frame_lock_release();

  free(frame);
}

/*  Searches the frames pairs list for an entry with the specified spt_entry.
 */
struct spt_pd_pair *frame_find_pair(struct spt_entry *spt_entry,
                                    struct frame_entry *frame) {

  struct list_elem *e;
  struct list *pairs = &frame->spt_pd_pairs;

  for (e = list_begin(pairs); e != list_end(pairs); e = list_next(e)) {
    struct spt_pd_pair *pair = list_entry(e, struct spt_pd_pair, pair_elem);
    if (pair->spt_entry == spt_entry) {
      return pair;
    }
  }
  return NULL;
}

/* Frees a pair entry with the specified spt_entry.  */
void frame_free_pair(struct spt_entry *spt_entry, struct frame_entry *frame) {
  lock_acquire(&frame->shared_lock);

  struct spt_pd_pair *pair = frame_find_pair(spt_entry, frame);
  if (pair != NULL) {
    list_remove(&pair->pair_elem);
    free(pair);
  }
  lock_release(&frame->shared_lock);
}

/* Frees all pairs on a frame. */
void frame_free_all_pairs(struct frame_entry *frame) {
  struct list *pairs = &frame->spt_pd_pairs;
  while (!list_empty(pairs)) {
    struct list_elem *e = list_pop_front(pairs);
    struct spt_pd_pair *pair = list_entry(e, struct spt_pd_pair, pair_elem);
    struct spt_entry *spt_entry = pair->spt_entry;

    spt_entry->kaddr = NULL;
    pagedir_clear_page(pair->pd, spt_entry->uaddr);
    free(pair);
  }
}

/* Inserts a new pair into the frames pairs list.  */
void frame_add_pair(struct frame_entry *frame, struct spt_entry *spt_entry,
                    uint32_t *pd) {
  struct spt_pd_pair *pair = malloc(sizeof(*pair));
  if (pair == NULL) {
    PANIC("Memory could not be allocated for spt_pd_pair.");
  }
  pair->spt_entry = spt_entry;
  pair->pd = pd;
  lock_acquire(&frame->shared_lock);
  list_push_back(&frame->spt_pd_pairs, &pair->pair_elem);
  lock_release(&frame->shared_lock);
}

/* Returns the frame_entry for addr from the frame table. */
struct frame_entry *frame_get_entry(void *addr) {
  frame_lock_acquire();
  struct frame_entry mock_frame;
  mock_frame.kaddr = addr;

  struct hash_elem *elem = hash_find(&frame_table, &mock_frame.frame_elem);
  frame_lock_release();

  if (elem != NULL) {
    return hash_entry(elem, struct frame_entry, frame_elem);
  }
  return NULL;
}

/* Iterates through the frames to find an entry with the specified hash_named
 * and offset.  */
struct frame_entry *frame_find_page(unsigned hashed_name, off_t offset) {
  frame_lock_acquire();
  struct hash_iterator i;

  hash_first(&i, &frame_table);
  while (hash_next(&i)) {
    struct frame_entry *f =
        hash_entry(hash_cur(&i), struct frame_entry, frame_elem);
    if (f->hashed_name == hashed_name && f->offset == offset) {
      frame_lock_release();
      return f;
    }
  }
  frame_lock_release();
  return FAILURE;
}

/* Allocate 'size' space for the user virtual addresses starting at the
 * beginning of the page containing 'uaddr'. Sets the frame_entry's 'pinned'
 * status to true. This is done to make sure that the none of the pages are
 * evicted until it is fully loaded. */
void pin_and_load_buff(const void *uaddr, size_t size) {
  struct hash *spt = &thread_current()->spt;

  for (void *upage = pg_round_down(uaddr); upage < uaddr + size;
       upage += PGSIZE) {
    struct spt_entry *spt_entry = spt_get_entry(spt, upage);
    if (spt_entry->kaddr == NULL) {
      spt_load_page(spt_entry);
    }

    frame_get_entry(spt_entry->kaddr)->pinned = true;
  }
}

/* For all the memory starting at the page containing 'uaddr', unpin the
 * pages. */
void unpin_buffer(const void *uaddr, unsigned size) {
  for (void *upage = pg_round_down(uaddr); upage < uaddr + size;
       upage += PGSIZE) {

    struct spt_entry *spt_entry = spt_get_entry(&thread_current()->spt, upage);
    struct frame_entry *frame = frame_get_entry(spt_entry->kaddr);
    frame->pinned = false;
  }
}

/* Function called with hash_destroy to free all frame resources. */
static void frame_free_exit(struct hash_elem *e, void *aux UNUSED) {
  struct frame_entry *frame = hash_entry(e, struct frame_entry, frame_elem);
  frame_free_all_pairs(frame);
  frame_free(frame);
}

/* Free the entire frame_table. */
void frame_free_table(void) { hash_destroy(&frame_table, frame_free_exit); }

/* Hash function for the frame table. Hashes the kaddr.  */
static unsigned frame_hash(const struct hash_elem *e, void *aux UNUSED) {
  const struct frame_entry *frame =
      hash_entry(e, struct frame_entry, frame_elem);
  return hash_bytes(&frame->kaddr, sizeof(frame->kaddr));
}

/* Compares two frames by their kaddr.  */
static bool frame_hash_less(const struct hash_elem *a,
                            const struct hash_elem *b, void *aux UNUSED) {
  const struct frame_entry *frame_a =
      hash_entry(a, struct frame_entry, frame_elem);
  const struct frame_entry *frame_b =
      hash_entry(b, struct frame_entry, frame_elem);

  return frame_a->kaddr < frame_b->kaddr;
}