/*
 * Copyright 2022, UNSW
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sel4cp.h>

#include "lwip/dhcp.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/snmp.h"
#include "lwip/stats.h"
#include "lwip/sys.h"
#include "netif/etharp.h"

#include "cache.h"
#include "echo.h"
#include "sel4bench.h"
#include "shared_ringbuffer.h"
#include "timer.h"
#include "util.h"

/* Notification and PPC channels - ensure these align with .system file! */
#define TIMER  1
#define RX_CH  2
#define TX_CH  3
#define ARP    7

/* Ring buffer regions */
uintptr_t rx_free;
uintptr_t rx_used;
uintptr_t tx_free;
uintptr_t tx_used;

/* Buffer data regions */
uintptr_t rx_buffer_data_region;
uintptr_t tx_buffer_data_region;

/* CDTODO: Why is this here? */
uintptr_t uart_base;

/* CDTODO: Booleans to indicate whether packets have been enqueued during notification handling */
static bool notify_tx;
static bool notify_rx;

/* Initialise an array to hold lwip pbuffs */
LWIP_MEMPOOL_DECLARE(
    RX_POOL,
    NUM_BUFFERS * 2,
    sizeof(struct pbuf_custom),
    "Zero-copy RX pool"
);

typedef struct state {
    struct netif netif;
    /* mac address for this client */
    uint8_t mac[6];

    /* Ring handles */
    ring_handle_t rx_ring;
    ring_handle_t tx_ring;

    /* pbufs waiting to be copied to shared buffers and passed to multiplexer */
    struct pbuf *head;
    struct pbuf *tail;
} state_t;

/* Keep track of MAC, ring buffers and pbuf queue to be transmitted */
state_t state;

/**
 * Free a pbuf. This also returns the underlying buffer to the receive free ring.
 * 
 * @param p pbuf to free.
 */
static void interface_free_buffer(struct pbuf *p)
{
    SYS_ARCH_DECL_PROTECT(old_level);
    struct pbuf_custom *custom_pbuf = (struct pbuf_custom *)p;
    SYS_ARCH_PROTECT(old_level);
    buff_desc_t buffer = {(uintptr_t) (custom_pbuf->pbuf.payload - rx_buffer_data_region), 0, 0, NULL};
    /* CDTODO: No obvious way to ensure that the free ring is not full before this function is called... */
    int err __attribute__((unused)) = enqueue_free(&(state.rx_ring), buffer);
    assert(!err);
    notify_rx = true;
    LWIP_MEMPOOL_FREE(RX_POOL, custom_pbuf);
    SYS_ARCH_UNPROTECT(old_level);
}

/**
 * Create a pbuf structure to pass to the network interface.
 *
 * @param state client state data.
 * @param buffer shared buffer containing the data.
 * @param length length of data.
 *
 * @return the newly created pbuf. Can be cast to pbuf_custom.
 */
static struct pbuf *create_interface_buffer(uintptr_t buffer, size_t length)
{
    struct pbuf_custom *custom_pbuf = (struct pbuf_custom *) LWIP_MEMPOOL_ALLOC(RX_POOL);
    custom_pbuf->custom_free_function = interface_free_buffer;

    return pbuf_alloced_custom(
        PBUF_RAW,
        length,
        PBUF_REF,
        custom_pbuf,
        (void *)buffer,
        BUF_SIZE
    );
}

/**
 * Stores a pbuf to be transmitted upon available transmit buffers.
 * 
 * @param p pbuf to be stored.
 */
void enqueue_pbufs(struct pbuf *p)
{
    /* Indicate to the multiplexer that we require transmit free buffers */
    request_signal(state.tx_ring.free_ring);

    if (state.head == NULL) {
        state.head = p;
    } else {
        state.tail->next_chain = p;
    }
    state.tail = p;

    /* Increment refernce count to ensure this pbuf is not freed by lwip */
    pbuf_ref(p);
}

/** 
 * Insert pbuf into transmit used queue. If no free buffers available or transmit used queue is full, 
 * stores pbuf to be sent upon buffers becoming available. 
 * */
static err_t lwip_eth_send(struct netif *netif, struct pbuf *p)
{
    if (p->tot_len > BUF_SIZE) {
        printf("LWIP|ERROR: attempted to send a packet of size %X > BUFFER SIZE %X\n", p->tot_len, BUF_SIZE);
        return ERR_MEM;
    }

    if (ring_full(state.tx_ring.used_ring)) {
        enqueue_pbufs(p);
        return ERR_OK;
    }
    
    buff_desc_t buffer;
    int err __attribute__((unused)) = dequeue_free(&(state.tx_ring), &buffer);
    assert(!err);

    unsigned char *frame = (unsigned char *)(buffer.offset + tx_buffer_data_region);
    unsigned int copied = 0;
    for (struct pbuf *curr = p; curr != NULL; curr = curr->next) {
        memcpy(frame + copied, curr->payload, curr->len);
        copied += curr->len;
    }

    cleanCache((unsigned long) frame, (unsigned long) frame + copied);

    buffer.len = copied;
    err = enqueue_used(&(state.tx_ring), buffer);
    assert(!err);

    notify_tx = true;

    return ERR_OK;
}

void transmit(void)
{
    bool reprocess = true;
    while (reprocess) {
        while(state.head != NULL && !ring_empty(state.tx_ring.free_ring) && !ring_full(state.tx_ring.used_ring)) {
            err_t err = lwip_eth_send(&state.netif, state.head);
            if (err == ERR_MEM) printf("LWIP|ERROR: attempted to send a packet of size %X > BUFFER SIZE %X\n", state.head->tot_len, BUF_SIZE);
            else if (err != ERR_OK) printf("LWIP|ERROR: unkown error when trying to send pbuf %X\n", state.head);
            
            struct pbuf *temp = state.head;
            state.head = temp->next_chain;
            if (state.head == NULL) state.tail = NULL;
            pbuf_free(temp);
        }

        /* Only request a signal if no more pbufs enqueud to send */
        if (state.head == NULL || !ring_empty(state.tx_ring.free_ring)) cancel_signal(state.tx_ring.free_ring);
        else request_signal(state.tx_ring.free_ring);
        reprocess = false;

        if (state.head != NULL && !ring_empty(state.tx_ring.free_ring) && !ring_full(state.tx_ring.used_ring)) {
            cancel_signal(state.tx_ring.free_ring);
            reprocess = true;
        }
    }
}

void receive(void)
{
    bool reprocess = true;
    while (reprocess) {
        while (!ring_empty(state.rx_ring.used_ring)) {
            buff_desc_t buffer;
            int err __attribute__((unused)) = dequeue_used(&state.rx_ring, &buffer);
            assert(!err);

            /* If client is communicating directly with driver, cache of this buffer must be invalidated 
            err = seL4_ARM_VSpace_Invalidate_Data(3, buffer.offset + rx_buffer_data_region, buffer.offset + rx_buffer_data_region + buffer.len);
            if (err) printf("LWIP|ERROR: ARM Vspace invalidate failed with err %d\n", err);
            assert(!err); */

            struct pbuf *p = create_interface_buffer(buffer.offset + rx_buffer_data_region, buffer.len);

            if (state.netif.input(p, &state.netif) != ERR_OK) {
                printf("LWIP|ERROR: unkown error inputting pbuf into network stack\n");
                pbuf_free(p);
            }
        }
        
        request_signal(state.rx_ring.used_ring);
        reprocess = false;

        if (!ring_empty(state.rx_ring.used_ring)) {
            cancel_signal(state.rx_ring.used_ring);
            reprocess = true;
        }
    }
}

/**
 * Initialise the network interface data structure.
 */
static err_t ethernet_init(struct netif *netif)
{
    if (netif->state == NULL) return ERR_ARG;
    state_t *data = netif->state;

    netif->hwaddr[0] = data->mac[0];
    netif->hwaddr[1] = data->mac[1];
    netif->hwaddr[2] = data->mac[2];
    netif->hwaddr[3] = data->mac[3];
    netif->hwaddr[4] = data->mac[4];
    netif->hwaddr[5] = data->mac[5];
    netif->mtu = ETHER_MTU;
    netif->hwaddr_len = ETHARP_HWADDR_LEN;
    netif->output = etharp_output;
    netif->linkoutput = lwip_eth_send;
    NETIF_INIT_SNMP(netif, snmp_ifType_ethernet_csmacd, LINK_SPEED);
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP | NETIF_FLAG_IGMP;
    return ERR_OK;
}

/* Callback function that prints DHCP supplied IP address and registers it with ARP component. */
static void netif_status_callback(struct netif *netif)
{
    if (dhcp_supplied_address(netif)) {
        /* CDTODO: Only send IP address to ARP if ARP exists */
        sel4cp_mr_set(0, ip4_addr_get_u32(netif_ip4_addr(netif)));
        sel4cp_mr_set(1, (state.mac[0] << 24) | (state.mac[1] << 16) | (state.mac[2] << 8) | (state.mac[3]));
        sel4cp_mr_set(2, (state.mac[4] << 24) | (state.mac[5] << 16));
        sel4cp_ppcall(ARP, sel4cp_msginfo_new(0, 3));

        printf("LWIP|NOTICE: DHCP request for %s returned IP address: %s\n", sel4cp_name, ip4addr_ntoa(netif_ip4_addr(netif)));
    }
}

static void get_mac(void)
{
    /* CDTODO: No more hardcoded MACs please! */
    state.mac[0] = 0x52;
    state.mac[1] = 0x54;
    state.mac[2] = 0x1;
    state.mac[3] = 0;
    state.mac[4] = 0;
    if (!strcmp(sel4cp_name, "client0")) state.mac[5] = 0;
    else state.mac[5] = 0x1;

    /* sel4cp_ppcall(RX_CH, sel4cp_msginfo_new(0, 0));
    uint32_t palr = sel4cp_mr_get(0);
    uint32_t paur = sel4cp_mr_get(1);
    state.mac[0] = palr >> 24;
    state.mac[1] = palr >> 16 & 0xff;
    state.mac[2] = palr >> 8 & 0xff;
    state.mac[3] = palr & 0xff;
    state.mac[4] = paur >> 24;
    state.mac[5] = paur >> 16 & 0xff;*/
}

void init(void)
{
    ring_init(&state.rx_ring, (ring_buffer_t *)rx_free, (ring_buffer_t *)rx_used, NUM_BUFFERS, NUM_BUFFERS);
    ring_init(&state.tx_ring, (ring_buffer_t *)tx_free, (ring_buffer_t *)tx_used, NUM_BUFFERS, NUM_BUFFERS);

    buffers_init((ring_buffer_t *)tx_free, 0, NUM_BUFFERS, BUF_SIZE);

    lwip_init();
    set_timeout();

    LWIP_MEMPOOL_INIT(RX_POOL);

    get_mac();

    /* Set dummy IP configuration values to get lwIP bootstrapped  */
    struct ip4_addr netmask, ipaddr, gw, multicast;
    ipaddr_aton("0.0.0.0", &gw);
    ipaddr_aton("0.0.0.0", &ipaddr);
    ipaddr_aton("0.0.0.0", &multicast);
    ipaddr_aton("255.255.255.0", &netmask);

    state.netif.name[0] = 'e';
    state.netif.name[1] = '0';

    if (!netif_add(&(state.netif), &ipaddr, &netmask, &gw, (void *)&state,
              ethernet_init, ethernet_input)) printf("LWIP|ERROR: Netif add returned NULL\n");

    netif_set_default(&(state.netif));
    netif_set_status_callback(&(state.netif), netif_status_callback);
    netif_set_up(&(state.netif));

    if (dhcp_start(&(state.netif))) printf("LWIP|ERROR: failed to start DHCP negotiation\n");

    setup_udp_socket();
    setup_utilization_socket();

    if (notify_rx && require_signal(state.rx_ring.free_ring)) {
        cancel_signal(state.rx_ring.free_ring);
        notify_rx = false;
        if (!have_signal) sel4cp_notify_delayed(RX_CH);
        else if (signal != BASE_OUTPUT_NOTIFICATION_CAP + RX_CH) sel4cp_notify(RX_CH);
    }

    if (notify_tx && require_signal(state.tx_ring.used_ring)) {
        notify_tx = false;
        if (!have_signal) {
            sel4cp_notify_delayed(TX_CH);
        } else if (signal != BASE_OUTPUT_NOTIFICATION_CAP + TX_CH) {
            sel4cp_notify(TX_CH);
        }
    }
}

void notified(sel4cp_channel ch)
{
    switch(ch) {
        case RX_CH:
            receive();
            break;
        case TIMER:
            sys_check_timeouts();
            set_timeout();
            break;
        case TX_CH:
            transmit();
            receive();
            break;
        default:
            printf("LWIP|LOG: received notification on unexpected channel: \n", ch);
            break;
    }
    
    if (notify_rx && require_signal(state.rx_ring.free_ring)) {
        cancel_signal(state.rx_ring.free_ring);
        notify_rx = false;
        if (!have_signal) sel4cp_notify_delayed(RX_CH);
        else if (signal != BASE_OUTPUT_NOTIFICATION_CAP + RX_CH) sel4cp_notify(RX_CH);
    }

    if (notify_tx && require_signal(state.tx_ring.used_ring)) {
        cancel_signal(state.tx_ring.used_ring);
        notify_tx = false;
        if (!have_signal) sel4cp_notify_delayed(TX_CH);
        else if (signal != BASE_OUTPUT_NOTIFICATION_CAP + TX_CH) sel4cp_notify(TX_CH);
    }
}