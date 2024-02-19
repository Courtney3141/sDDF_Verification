#include <math.h>

#include "cache.h"
#include "shared_ringbuffer.h"
#include "util.h"

/* Notification and ppc channels - ensure these align with .system file! */
#define ARP 0
#define CLIENT0 1
#define CLIENT1 2
#define DRIVER 3
#define TIMER_CH 4

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

/* Timing configuration */
#define TIME_WINDOW 10000ULL // 10 milliseconds
#define GET_TIME 0
#define SET_TIMEOUT 1

typedef struct client_usage {
    uint64_t last_time;
    uint64_t curr_bandwidth;
    uint64_t max_bandwidth;
    bool pending_timeout;
} client_usage_t;

typedef struct state {
    ring_handle_t tx_ring_drv;
    ring_handle_t tx_ring_clients[NUM_CLIENTS];
    client_usage_t client_usage[NUM_CLIENTS];
} state_t;

state_t state;

int extract_offset(uintptr_t phys, uintptr_t *offset) {
    for (int client = 0; client < NUM_CLIENTS; client++) {
        if (phys >= buffer_region_paddrs[client] && phys < buffer_region_paddrs[client] + NUM_BUFFERS * BUF_SIZE) {
            *offset = phys - buffer_region_paddrs[client];
            return client;
        }
    }
    return -1;
}

static uint64_t get_time(void)
{
    /* This should be done using read only memory like with idle.c and utilization_socket.c */
    microkit_ppcall(TIMER_CH, microkit_msginfo_new(GET_TIME, 0));
    uint64_t time_now = seL4_GetMR(0);
    return time_now;
}

static void set_timeout(uint64_t timeout)
{
    microkit_mr_set(0, timeout);
    microkit_ppcall(TIMER_CH, microkit_msginfo_new(SET_TIMEOUT, 1));
}

void tx_provide(void)
{
    bool enqueued = false;
    bool notify_driver = false;
    uint64_t curr_time = get_time();
    for (int client = 0; client < NUM_CLIENTS; client++) {
        if (curr_time - state.client_usage[client].last_time >= TIME_WINDOW) {
            state.client_usage[client].curr_bandwidth = 0;
            state.client_usage[client].last_time = curr_time;
        }

        while (!ring_empty(state.tx_ring_clients[client].used_ring) && !ring_full(state.tx_ring_drv.used_ring)
                && (state.client_usage[client].curr_bandwidth < state.client_usage[client].max_bandwidth)) {
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

            state.client_usage[client].curr_bandwidth += (buffer.len * 8);
        }

        if (!ring_empty(state.tx_ring_clients[client].used_ring) && !state.client_usage[client].pending_timeout) {
            set_timeout(TIME_WINDOW - (curr_time - state.client_usage[client].last_time));
            state.client_usage[client].pending_timeout = true;
            cancel_signal(state.tx_ring_clients[client].used_ring);
        } else {
            request_signal(state.tx_ring_clients[client].used_ring);
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
            microkit_notify(client);
        }
    }
}

void notified(microkit_channel ch)
{
    if (ch == TIMER_CH) {
        /* We always assume that timeout is for client 1... */
        state.client_usage[CLIENT_1].pending_timeout = false;
        request_signal(state.tx_ring_clients[CLIENT_1].used_ring);
    }
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

    state.client_usage[0].max_bandwidth = 100000000;
    state.client_usage[1].max_bandwidth = 1000000;
    state.client_usage[2].max_bandwidth = 100000000;
    
    tx_provide();
}