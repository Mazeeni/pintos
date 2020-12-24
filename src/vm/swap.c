#include "vm/swap.h"
#include "threads/synch.h"
#include "userprog/syscall.h"
#include <bitmap.h>
#include <stdio.h>

/* Block device for swapping */
static struct block *block_swap;

/* Bitmap to keep track of which swap slots are in use */
static struct bitmap *swap_map;

/* Lock for synchronising any accesses to swap. */
static struct lock swap_lock;

/* Initialises our block device and bitmap for use in swapping. */
void swap_init() {
  lock_init(&swap_lock);
  block_swap = block_get_role(BLOCK_SWAP);
  if (block_swap == NULL) {
    PANIC("Block device for swapping could not be obtained!");
  }

  swap_map = bitmap_create(block_size(block_swap) / SECTORS_PER_PAGE);
  if (!swap_map) {
    PANIC("Memory for bitmap could not be allocated!");
  }
}

/* Write into the swap slots */
size_t swap_put(void *addr) {

  lock_acquire(&swap_lock);

  block_sector_t swap_index = bitmap_scan_and_flip(swap_map, 0, 1, false);

  lock_release(&swap_lock);

  if (swap_index == BITMAP_ERROR) {
    error_exit();
  }
  for (int i = 0; i < SECTORS_PER_PAGE; i++) {
    block_write(block_swap, swap_index * SECTORS_PER_PAGE + i,
                addr + i * BLOCK_SECTOR_SIZE);
  }

  return swap_index;
}

/* Extract from a swap slot and free that slot */
void swap_get(block_sector_t swap_index, void *addr) {

  lock_acquire(&swap_lock);

  if (!(bitmap_test(swap_map, swap_index) &&
        swap_index < bitmap_size(swap_map))) {
    PANIC("Swap index provided is invalid!");
  }

  lock_release(&swap_lock);

  for (int i = 0; i < SECTORS_PER_PAGE; i++) {
    block_read(block_swap, swap_index * SECTORS_PER_PAGE + i,
               addr + i * BLOCK_SECTOR_SIZE);
  }
  swap_free(swap_index);
}

/* Set bit to false to indicate swap_index is no longer in use */
void swap_free(block_sector_t swap_index) {
  bitmap_set(swap_map, swap_index, false);
}

/* To destroy the swap_map on shutdown */
void swap_destroy(void) { bitmap_destroy(swap_map); }