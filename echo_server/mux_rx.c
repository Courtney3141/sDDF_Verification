#include <sel4cp.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "lwip/ip_addr.h"
#include "netif/etharp.h"
#include "shared_ringbuffer.h"
#include "util.h"

/* Notification and PPC channels - ensure these align with .system file! */
#define DRIVER_CH 3

/* CDTODO: Extract from system later */
#define NUM_CLIENTS 3
#define ETHER_MTU 1500

/* Ring buffer regions */
uintptr_t rx_free_drv;
uintptr_t rx_used_drv;
uintptr_t rx_free_cli0;
uintptr_t rx_used_cli0;
uintptr_t rx_free_cli1;
uintptr_t rx_used_cli1;
uintptr_t rx_free_arp;
uintptr_t rx_used_arp;

/* Buffer data regions */
uintptr_t buffer_data_vaddr;
uintptr_t buffer_data_paddr;

uintptr_t uart_base;

typedef struct state {
    ring_handle_t rx_ring_drv;
    ring_handle_t rx_ring_clients[NUM_CLIENTS];
    uint8_t mac_addrs[NUM_CLIENTS][6];
} state_t;

state_t state;

/* Boolean to indicate whether a packet has been enqueued into the driver's free ring during notification handling */
static bool notify_drv;

/* Return the client ID if the Mac address is a match. */
int get_client(struct eth_hdr * buffer)
{
        for (int client = 0; client < NUM_CLIENTS; client++) {
        bool match = true;
        for (int i = 0; (i < 6) && match; i++) if (buffer->dest.addr[i] != state.mac_addrs[client][i]) match = false;
        if (match) return client;
    }

    return -1;
}

void rx_return(void)
{
    bool reprocess = true;
    bool notify_clients[NUM_CLIENTS] = {false};
    while (reprocess) {
        while (!ring_empty(state.rx_ring_drv.used_ring)) {
            buff_desc_t buffer;
            int err __attribute__((unused)) = dequeue_used(&state.rx_ring_drv, &buffer);
            assert(!err);

            buffer.offset = buffer.phys - buffer_data_paddr;
            err = seL4_ARM_VSpace_Invalidate_Data(3, buffer.offset + buffer_data_vaddr, buffer.offset + buffer_data_vaddr + buffer.len);
            if (err) printf("MUX_RX|ERROR: ARM Vspace invalidate failed with err %d\n", err);
            assert(!err);

            int client = get_client((struct eth_hdr *) (buffer.offset + buffer_data_vaddr));
            if (client >= 0 && !ring_full(state.rx_ring_clients[client].used_ring)) {
                err = enqueue_used(&state.rx_ring_clients[client], buffer);
                assert(!err);
                notify_clients[client] = true;
            } else {
                buffer.phys = buffer.offset + buffer_data_paddr;
                err = enqueue_free(&state.rx_ring_drv, buffer);
                assert(!err);
                notify_drv = true;
            }
        }

        request_signal(state.rx_ring_drv.used_ring);
        reprocess = false;

        if (!ring_empty(state.rx_ring_drv.used_ring)) {
            cancel_signal(state.rx_ring_drv.used_ring);
            reprocess = true;
        }
    }

    for (int client = 0; client < NUM_CLIENTS; client++) {
        if (notify_clients[client] && require_signal(state.rx_ring_clients[client].used_ring)) {
            cancel_signal(state.rx_ring_clients[client].used_ring);
                        sel4cp_notify(client);
        }
    }    
}

void rx_provide(void)
{
    for (int client = 0; client < NUM_CLIENTS; client++) {
        bool reprocess = true;
        while (reprocess) {
            while (!ring_empty(state.rx_ring_clients[client].free_ring) && !ring_full(state.rx_ring_drv.free_ring)) {
                buff_desc_t buffer;
                int err __attribute__((unused)) = dequeue_free(&state.rx_ring_clients[client], &buffer);
                assert(!err);
                buffer.phys = buffer.offset + buffer_data_paddr;

                err = enqueue_free(&state.rx_ring_drv, buffer);
                assert(!err);
                notify_drv = true;
            }

            request_signal(state.rx_ring_clients[client].free_ring);
            reprocess = false;

            if (!ring_empty(state.rx_ring_clients[client].free_ring) && !ring_full(state.rx_ring_drv.free_ring)) {
                cancel_signal(state.rx_ring_clients[client].free_ring);
                reprocess = true;
            }
        }
    }

    if (notify_drv && require_signal(state.rx_ring_drv.free_ring)) {
        cancel_signal(state.rx_ring_drv.free_ring);
        sel4cp_notify_delayed(DRIVER_CH);
    }
}

void notified(sel4cp_channel ch)
{
    rx_return();
    rx_provide();
}

void init(void)
{
    /* CDTODO: Extract from system later */
    state.mac_addrs[0][0] = 0xff;
    state.mac_addrs[0][1] = 0xff;
    state.mac_addrs[0][2] = 0xff;
    state.mac_addrs[0][3] = 0xff;
    state.mac_addrs[0][4] = 0xff;
    state.mac_addrs[0][5] = 0xff;

    state.mac_addrs[1][0] = 0x52;
    state.mac_addrs[1][1] = 0x54;
    state.mac_addrs[1][2] = 0x1;
    state.mac_addrs[1][3] = 0;
    state.mac_addrs[1][4] = 0;
    state.mac_addrs[1][5] = 0;

    state.mac_addrs[2][0] = 0x52;
    state.mac_addrs[2][1] = 0x54;
    state.mac_addrs[2][2] = 0x1;
    state.mac_addrs[2][3] = 0;
    state.mac_addrs[2][4] = 0;
    state.mac_addrs[2][5] = 0x1;

    ring_init(&state.rx_ring_drv, (ring_buffer_t *)rx_free_drv, (ring_buffer_t *)rx_used_drv, NUM_BUFFERS, NUM_BUFFERS);
    ring_init(&state.rx_ring_clients[0], (ring_buffer_t *)rx_free_arp, (ring_buffer_t *)rx_used_arp, NUM_BUFFERS, NUM_BUFFERS);
    ring_init(&state.rx_ring_clients[1], (ring_buffer_t *)rx_free_cli0, (ring_buffer_t *)rx_used_cli0, NUM_BUFFERS, NUM_BUFFERS);
    ring_init(&state.rx_ring_clients[2], (ring_buffer_t *)rx_free_cli1, (ring_buffer_t *)rx_used_cli1, NUM_BUFFERS, NUM_BUFFERS);

    buffers_init((ring_buffer_t *)rx_free_drv, buffer_data_paddr, NUM_BUFFERS, BUF_SIZE);

    if (require_signal(state.rx_ring_drv.free_ring)) {
        cancel_signal(state.rx_ring_drv.free_ring);
        sel4cp_notify_delayed(DRIVER_CH);
    }
}