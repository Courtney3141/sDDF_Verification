#include "shared_ringbuffer.h"
#include "util.h"

/* Notification channels - ensure these align with .system file! */
#define CLIENT0 0
#define CLIENT1 1
#define ARP 2
#define DRIVER 3

/* CDTODO: Remove later or figure out a standardised way of configuring this */
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

/* CDTODO: Why is this here? */
uintptr_t uart_base;

typedef struct state {
    ring_handle_t tx_ring_drv;
    ring_handle_t tx_ring_clients[NUM_CLIENTS];
} state_t;

state_t state;

void tx_provide(void)
{
    bool enqueued;
    for (int client = 0; client < NUM_CLIENTS; client++) {
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

                buffer.dma_region_id = client;
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
        microkit_notify_delayed(DRIVER);
    }
}

/* CDTODO: Benchmark this and ensure it's not faster than original */
void tx_provide_alternate(void)
{
    bool reprocess = true;
    bool enqueued;
    while (reprocess) {
        for (int client = 0; client < NUM_CLIENTS; client++) {
            while (!ring_empty(state.tx_ring_clients[client].used_ring) && !ring_full(state.tx_ring_drv.used_ring)) {
                buff_desc_t buffer;
                int err __attribute__((unused)) = dequeue_used(&state.tx_ring_clients[client], &buffer);
                assert(!err);

                buffer.dma_region_id = client;
                err = enqueue_used(&state.tx_ring_drv, buffer);
                assert(!err);
                enqueued = true;
            }
        }

        for (int client = 0; client < NUM_CLIENTS; client++) request_signal(state.tx_ring_clients[client].used_ring);
        reprocess = false;

        bool clients_empty = true;
        for (int client = 0; client < NUM_CLIENTS; client++) clients_empty &= ring_empty(state.tx_ring_clients[client].used_ring);

        if (!clients_empty && !ring_full(state.tx_ring_drv.used_ring)) {
            for (int client = 0; client < NUM_CLIENTS; client++) cancel_signal(state.tx_ring_clients[client].used_ring);
            reprocess = true;
        }
    }

    if (enqueued && require_signal(state.tx_ring_drv.used_ring)) {
        cancel_signal(state.tx_ring_drv.used_ring);
        microkit_notify_delayed(DRIVER);
    }
}

void tx_return(void)
{
    bool reprocess = true;
    bool notify_clients[NUM_CLIENTS];
    while (reprocess) {
        while (!ring_empty(state.tx_ring_drv.free_ring)) {
            buff_desc_t buffer;
            int err __attribute__((unused)) = dequeue_free(&state.tx_ring_drv, &buffer);
            assert(!err);

            /* CDTODO: How do we gaurantee that this operation will succeed? */
            err = enqueue_free(&state.tx_ring_clients[buffer.dma_region_id], buffer);
            assert(!err);
            notify_clients[buffer.dma_region_id] = true;
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
            microkit_notify(client);
        }
    }
}

void notified(microkit_channel ch)
{
    tx_return();
    tx_provide();
}

void init(void)
{
    ring_init(&state.tx_ring_drv, (ring_buffer_t *)tx_free_drv, (ring_buffer_t *)tx_used_drv, NUM_BUFFERS, NUM_BUFFERS);
    ring_init(&state.tx_ring_clients[0], (ring_buffer_t *)tx_free_cli0, (ring_buffer_t *)tx_used_cli0, NUM_BUFFERS, NUM_BUFFERS);
    ring_init(&state.tx_ring_clients[1], (ring_buffer_t *)tx_free_cli1, (ring_buffer_t *)tx_used_cli1, NUM_BUFFERS, NUM_BUFFERS);
    ring_init(&state.tx_ring_clients[2], (ring_buffer_t *)tx_free_arp, (ring_buffer_t *)tx_used_arp, NUM_BUFFERS, NUM_BUFFERS);

    tx_provide();
}