#include "cache.h"
#include "shared_ringbuffer.h"
#include "util.h"

/* Notification channels - ensure these align with .system file! */
#define ARP 0
#define CLIENT0 1
#define CLIENT1 2
#define DRIVER 3

/* CDTODO: Extract from system later */
#define NUM_CLIENTS 3

/* Ring buffer regions */
uintptr_t tx_free_drv;
uintptr_t tx_used_drv;
uintptr_t tx_free_cli0;
uintptr_t tx_used_cli0;
uintptr_t tx_free_cli1;
uintptr_t tx_used_cli1;
uintptr_t tx_free_arp;
uintptr_t tx_used_arp;

/* Buffer data regions */
uintptr_t buffer_data_region_arp_vaddr;
uintptr_t buffer_data_region_cli0_vaddr;
uintptr_t buffer_data_region_cli1_vaddr;
uintptr_t buffer_region_vaddrs[NUM_CLIENTS];

uintptr_t buffer_data_region_arp_paddr;
uintptr_t buffer_data_region_cli0_paddr;
uintptr_t buffer_data_region_cli1_paddr;
uintptr_t buffer_region_paddrs[NUM_CLIENTS];

uintptr_t uart_base;

typedef struct state {
    ring_handle_t tx_ring_drv;
    ring_handle_t tx_ring_clients[NUM_CLIENTS];
    uint client_priority_order[NUM_CLIENTS];
} state_t;

state_t state;

int extract_offset(uintptr_t phys, uintptr_t *offset) {
    for (int client = 0; client < NUM_CLIENTS; client++) {
        if (phys >= buffer_region_paddrs[client] && phys < buffer_region_paddrs[client] + NUM_BUFFERS * BUF_SIZE) {
            *offset = phys - *offset;
            return client;
        }
    }
    return -1;
}

void tx_provide(void)
{
    bool enqueued = false;
    for (int i = 0; i < NUM_CLIENTS; i++) {
        int client = state.client_priority_order[i];
        bool reprocess = true;
        while (reprocess) {
            while (!ring_empty(state.tx_ring_clients[client].used_ring) && !ring_full(state.tx_ring_drv.used_ring)) {
                buff_desc_t buffer;
                int err __attribute__((unused)) = dequeue_used(&state.tx_ring_clients[client], &buffer);
                assert(!err);

                if (buffer.offset % BUF_SIZE || buffer.offset >= BUF_SIZE * NUM_BUFFERS) {
                    printf("MUX_TX|LOG: Client %d provided offset %X which is not buffer aligned or outside of buffer region\n", client, buffer.offset);
                    /* CDTODO: How do we gaurantee that this operation will succeed? And should we signal the client? */
                    err = enqueue_free(&state.tx_ring_clients[client], buffer);
                    assert(!err);
                    continue;
                }

                cleanCache(buffer.offset + buffer_region_vaddrs[client], buffer.offset + buffer_region_vaddrs[client] + buffer.len);

                buffer.phys = buffer.offset + buffer_region_paddrs[client];
                err = enqueue_used(&state.tx_ring_drv, buffer);
                assert(!err);
                enqueued = true;
            }

            request_signal(state.tx_ring_clients[client].used_ring);
            reprocess = false;

            if (!ring_empty(state.tx_ring_clients[client].used_ring) && !ring_full(state.tx_ring_drv.used_ring)) {
                cancel_signal(state.tx_ring_clients[client].used_ring);
                reprocess = true;
            }
        }
    }

    if (enqueued && require_signal(state.tx_ring_drv.used_ring)) {
        cancel_signal(state.tx_ring_drv.used_ring);
        sel4cp_notify_delayed(DRIVER);
    }
}

void tx_return(void)
{
    bool reprocess = true;
    bool notify_clients[NUM_CLIENTS] = {false};
    while (reprocess) {
        while (!ring_empty(state.tx_ring_drv.free_ring)) {
            buff_desc_t buffer;
            int err __attribute__((unused)) = dequeue_free(&state.tx_ring_drv, &buffer);
            assert(!err);

            int client = extract_offset(buffer.phys, &buffer.offset);
            assert(client >= 0);

            /* CDTODO: How do we gaurantee that this operation will succeed? */
            err = enqueue_free(&state.tx_ring_clients[client], buffer);
            assert(!err);
            notify_clients[client];
        }

        request_signal(state.tx_ring_drv.free_ring);
        reprocess = false;

        if (!ring_empty(state.tx_ring_drv.free_ring)) {
            cancel_signal(state.tx_ring_drv.free_ring);
            reprocess = true;
        }
    }

    for (int client = 0; client < NUM_CLIENTS; client++) {
        if (notify_clients[client] && require_signal(state.tx_ring_clients[client].free_ring)) {
            cancel_signal(state.tx_ring_clients[client].free_ring);
            sel4cp_notify(client);
        }
    }
}

void notified(sel4cp_channel ch)
{
    tx_return();
    tx_provide();
}

void init(void)
{
    ring_init(&state.tx_ring_drv, (ring_buffer_t *)tx_free_drv, (ring_buffer_t *)tx_used_drv, NUM_BUFFERS, NUM_BUFFERS);
    ring_init(&state.tx_ring_clients[0], (ring_buffer_t *)tx_free_arp, (ring_buffer_t *)tx_used_arp, NUM_BUFFERS, NUM_BUFFERS);
    ring_init(&state.tx_ring_clients[1], (ring_buffer_t *)tx_free_cli0, (ring_buffer_t *)tx_used_cli0, NUM_BUFFERS, NUM_BUFFERS);
    ring_init(&state.tx_ring_clients[2], (ring_buffer_t *)tx_free_cli1, (ring_buffer_t *)tx_used_cli1, NUM_BUFFERS, NUM_BUFFERS);

    buffer_region_vaddrs[0] = buffer_data_region_arp_vaddr;
    buffer_region_vaddrs[1] = buffer_data_region_cli0_vaddr;
    buffer_region_vaddrs[2] = buffer_data_region_cli1_vaddr;

    buffer_region_paddrs[0] = buffer_data_region_arp_paddr;
    buffer_region_paddrs[1] = buffer_data_region_cli0_paddr;
    buffer_region_paddrs[2] = buffer_data_region_cli1_paddr;

    state.client_priority_order[0] = CLIENT1;
    state.client_priority_order[1] = ARP;
    state.client_priority_order[2] = CLIENT0;
    
    tx_provide();
}