#ifndef SWAP_H
#define SWAP_H
#include "devices/block.h"
#include "threads/vaddr.h"

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

void swap_init(void);
size_t swap_put(void *addr);
void swap_get(block_sector_t swap_index, void *addr);
void swap_free(block_sector_t swap_index);
void swap_destroy(void);
#endif