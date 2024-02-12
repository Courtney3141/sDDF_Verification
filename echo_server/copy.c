#include <stdbool.h>
#include <string.h>

#include "shared_ringbuffer.h"
#include "util.h"

/* Notification and PPC channels - ensure these align with .system file! */
#define MUX_RX_CH 0
#define CLIENT_CH 1

/* Ring handles */
ring_handle_t rx_ring_mux;
ring_handle_t rx_ring_cli;

/* Ring buffer regions */
uintptr_t rx_free_mux;
uintptr_t rx_used_mux;
uintptr_t rx_free_cli;
uintptr_t rx_used_cli;

/* Buffer data regions */
uintptr_t mux_buffer_data_region;
uintptr_t cli_buffer_data_region;

uintptr_t uart_base;

void rx_return(void)
{
    bool enqueued = false;
    bool reprocess = true;

    while (reprocess) {
        while (!ring_empty(rx_ring_mux.used_ring) && !ring_empty(rx_ring_cli.free_ring) &&
                !ring_full(rx_ring_mux.free_ring) && !ring_full(rx_ring_cli.used_ring)) {
            buff_desc_t cli_buffer, mux_buffer;
            int err __attribute__((unused)) = dequeue_free(&rx_ring_cli, &cli_buffer);
            assert(!err);

            if (cli_buffer.offset % BUF_SIZE || cli_buffer.offset >= BUF_SIZE * NUM_BUFFERS) {
                printf("COPY|LOG: Client provided offset %X which is not buffer aligned or outside of buffer region\n", cli_buffer.offset);
                err = enqueue_free(&rx_ring_cli, cli_buffer);
                assert(!err);
                continue;
            }

            err = dequeue_used(&rx_ring_mux, &mux_buffer);
            assert(!err);

            uintptr_t cli_addr = cli_buffer_data_region + cli_buffer.offset;
            uintptr_t mux_addr = mux_buffer_data_region + mux_buffer.offset;

            memcpy((void *)cli_addr, (void *)mux_addr, mux_buffer.len);
            cli_buffer.len = mux_buffer.len;
            mux_buffer.len = 0;
            
            err = enqueue_used(&rx_ring_cli, cli_buffer);
            assert(!err);

            err = enqueue_free(&rx_ring_mux, mux_buffer);
            assert(!err);

            enqueued = true;
        }
        
        request_signal(rx_ring_mux.used_ring);

        /* Only request signal from client if incoming packets from multiplexer are awaiting free buffers */
        if (!ring_empty(rx_ring_mux.used_ring)) request_signal(rx_ring_cli.free_ring);
        else cancel_signal(rx_ring_cli.free_ring);

        reprocess = false;
        
        if (!ring_empty(rx_ring_mux.used_ring) && !ring_empty(rx_ring_cli.free_ring) &&
            !ring_full(rx_ring_mux.free_ring) && !ring_full(rx_ring_cli.used_ring)) {
            cancel_signal(rx_ring_mux.used_ring);
            cancel_signal(rx_ring_cli.free_ring);
            reprocess = true;
        }
    }

    if (enqueued && require_signal(rx_ring_cli.used_ring)) {
        cancel_signal(rx_ring_cli.used_ring);
        sel4cp_notify(CLIENT_CH);
    }

    if (enqueued && require_signal(rx_ring_mux.free_ring)) {
        cancel_signal(rx_ring_mux.free_ring);
        sel4cp_notify_delayed(MUX_RX_CH);
    }
}

void notified(sel4cp_channel ch)
{
    rx_return();
}

void init(void)
{
    ring_init(&rx_ring_mux, (ring_buffer_t *)rx_free_mux, (ring_buffer_t *)rx_used_mux, NUM_BUFFERS, NUM_BUFFERS);
    ring_init(&rx_ring_cli, (ring_buffer_t *)rx_free_cli, (ring_buffer_t *)rx_used_cli, NUM_BUFFERS, NUM_BUFFERS);

    buffers_init(rx_ring_cli.free_ring, 0, NUM_BUFFERS, BUF_SIZE);
}