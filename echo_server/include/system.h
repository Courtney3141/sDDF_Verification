#pragma once

#include <string.h>

#include "echo.h"
#include "networkutil.h"
#include "shared_ringbuffer.h"
#include "util.h"

#define NUM_CLIENTS 3
#define DATA_REGION_SIZE 0x200000

#define MAC_ADDR_ARP 0xFFFFFFFFFFFF
#define MAC_ADDR_CLI0 0x525401000000
#define MAC_ADDR_CLI1 0x525401000001

#define TX_RING_SIZE_ARP 512
#define TX_RING_SIZE_CLI0 512
#define TX_RING_SIZE_CLI1 512
#define TX_RING_SIZE_DRIV (TX_RING_SIZE_ARP + TX_RING_SIZE_CLI0 + TX_RING_SIZE_CLI1)

#define RX_RING_SIZE_ARP RX_RING_SIZE_DRIV
#define RX_RING_SIZE_CLI0 512
#define RX_RING_SIZE_CLI1 512
#define RX_RING_SIZE_COPY0 RX_RING_SIZE_DRIV
#define RX_RING_SIZE_COPY1 RX_RING_SIZE_DRIV
#define RX_RING_SIZE_DRIV 512

_Static_assert(MAX_BUFFS >= TX_RING_SIZE_DRIV, "Shared ring buffer capacity must be >= largest TX ring.");
_Static_assert(MAX_BUFFS >= MAX(RX_RING_SIZE_DRIV, MAX(RX_RING_SIZE_CLI0, RX_RING_SIZE_CLI1)), "Shared ring buffer capacity must be >=  largest RX ring.");
_Static_assert(TX_RING_SIZE_DRIV >= TX_RING_SIZE_ARP + TX_RING_SIZE_CLI0 + TX_RING_SIZE_CLI1, "Driver TX ring buffer must have capacity to fit all of client's TX buffers.");
_Static_assert(RX_RING_SIZE_ARP >= RX_RING_SIZE_DRIV, "Arp ring buffers must have capacity to fit all rx buffers.");
_Static_assert(RX_RING_SIZE_COPY0 >= RX_RING_SIZE_DRIV, "Copy0 ring buffers must have capacity to fit all RX buffers.");
_Static_assert(RX_RING_SIZE_COPY1 >= RX_RING_SIZE_DRIV, "Copy1 ring buffers must have capacity to fit all RX buffers.");
_Static_assert(sizeof(ring_buffer_t) <= DATA_REGION_SIZE, "Ring buffer must fit into a single data region.");

static void mac_addr_init_sys(char *pd_name, uint8_t *macs)
{
    if (!strcmp(pd_name, "client0")) {
        set_mac_addr(macs, MAC_ADDR_CLI0);
    } else if (!strcmp(pd_name, "client1")) {
        set_mac_addr(macs, MAC_ADDR_CLI1);
    } else if (!strcmp(pd_name, "arp")) {
        set_mac_addr(macs, MAC_ADDR_CLI0);
        set_mac_addr(&macs[ETH_HWADDR_LEN], MAC_ADDR_CLI1);
    } else if (!strcmp(pd_name, "mux_rx")) {
        set_mac_addr(macs, MAC_ADDR_ARP);
        set_mac_addr(&macs[ETH_HWADDR_LEN], MAC_ADDR_CLI0);
        set_mac_addr(&macs[2*ETH_HWADDR_LEN], MAC_ADDR_CLI1);
    }
}

static void cli_ring_init_sys(char *pd_name, ring_handle_t *rx_ring, uintptr_t rx_free, uintptr_t rx_used,
                                ring_handle_t *tx_ring, uintptr_t tx_free, uintptr_t tx_used)
{
    if (!strcmp(pd_name, "client0")) {
        ring_init(rx_ring, (ring_buffer_t *) rx_free, (ring_buffer_t *) rx_used, RX_RING_SIZE_CLI0);
        ring_init(tx_ring, (ring_buffer_t *) tx_free, (ring_buffer_t *) tx_used, TX_RING_SIZE_CLI0);
    } else if (!strcmp(pd_name, "client1")) {
        ring_init(rx_ring, (ring_buffer_t *) rx_free, (ring_buffer_t *) rx_used, RX_RING_SIZE_CLI1);
        ring_init(tx_ring, (ring_buffer_t *) tx_free, (ring_buffer_t *) tx_used, TX_RING_SIZE_CLI1);
    }
}

static void copy_ring_init_sys(char *pd_name, ring_handle_t *cli_ring, uintptr_t cli_free, uintptr_t cli_used,
                                ring_handle_t *mux_ring, uintptr_t mux_free, uintptr_t mux_used)
{
    if (!strcmp(pd_name, "copy0")) {
        ring_init(cli_ring, (ring_buffer_t *) cli_free, (ring_buffer_t *) cli_used, RX_RING_SIZE_CLI0);
        ring_init(mux_ring, (ring_buffer_t *) mux_free, (ring_buffer_t *) mux_used, RX_RING_SIZE_COPY0);
    } else if (!strcmp(pd_name, "copy1")) {
        ring_init(cli_ring, (ring_buffer_t *) cli_free, (ring_buffer_t *) cli_used, RX_RING_SIZE_CLI1);
        ring_init(mux_ring, (ring_buffer_t *) mux_free, (ring_buffer_t *) mux_used, RX_RING_SIZE_COPY1);
    }
}

static void mux_ring_init_sys(char *pd_name, ring_handle_t *cli_ring, uintptr_t cli_free, uintptr_t cli_used)
{
    if (!strcmp(pd_name, "mux_rx")) {
        ring_init(cli_ring, (ring_buffer_t *) cli_free, (ring_buffer_t *) cli_used, RX_RING_SIZE_ARP);
        ring_init(&cli_ring[1], (ring_buffer_t *) (cli_free + 2 * DATA_REGION_SIZE), (ring_buffer_t *) (cli_used + 2 * DATA_REGION_SIZE), RX_RING_SIZE_CLI0);
        ring_init(&cli_ring[2], (ring_buffer_t *) (cli_free + 4 * DATA_REGION_SIZE), (ring_buffer_t *) (cli_used + 4 * DATA_REGION_SIZE), RX_RING_SIZE_CLI1);
    } else if (!strcmp(pd_name, "mux_tx")) {
        ring_init(cli_ring, (ring_buffer_t *) cli_free, (ring_buffer_t *) cli_used, TX_RING_SIZE_ARP);
        ring_init(&cli_ring[1], (ring_buffer_t *) (cli_free + 2 * DATA_REGION_SIZE), (ring_buffer_t *) (cli_used + 2 * DATA_REGION_SIZE), TX_RING_SIZE_CLI0);
        ring_init(&cli_ring[2], (ring_buffer_t *) (cli_free + 4 * DATA_REGION_SIZE), (ring_buffer_t *) (cli_used + 4 * DATA_REGION_SIZE), TX_RING_SIZE_CLI1);
    }
}

static void mem_region_init_sys(char *pd_name, uintptr_t *mem_regions, uintptr_t start_region) {
    if (!strcmp(pd_name, "mux_tx")) {
        mem_regions[0] = start_region;
        mem_regions[1] = start_region + DATA_REGION_SIZE;
        mem_regions[2] = start_region + DATA_REGION_SIZE * 2;
    }
}