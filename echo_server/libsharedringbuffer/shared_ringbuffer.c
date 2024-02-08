/*
 * Copyright 2022, UNSW
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "shared_ringbuffer.h"

void ring_init(ring_handle_t *ring, ring_buffer_t *free, ring_buffer_t *used, uint32_t free_size, uint32_t used_size)
{
    ring->free_ring = free;
    ring->used_ring = used;
    ring->free_ring->size = free_size;
    ring->used_ring->size = used_size;
}