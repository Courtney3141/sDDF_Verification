/*
 * Copyright 2022, UNSW
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4cp.h>
#include <sel4/sel4.h>
#include <stdbool.h>
#include <stdint.h>

#include "eth.h"
#include "shared_ringbuffer.h"
#include "util.h"

/* Notification and PPC channels - ensure these align with .system file! */
#define IRQ_CH 0
#define TX_CH  1
#define RX_CH  2

/* HW ring buffer regions */
uintptr_t hw_ring_buffer_vaddr;
uintptr_t hw_ring_buffer_paddr;
uintptr_t rx_cookies;
uintptr_t tx_cookies;

/* Ring buffer regions */
uintptr_t rx_free;
uintptr_t rx_used;
uintptr_t tx_free;
uintptr_t tx_used;

/* Buffer data regions paddr */
uintptr_t rx_buffer_data_region_paddr;
uintptr_t tx_buffer_data_region_paddr;

uintptr_t uart_base;

/* Packet configuration */
#define MAX_PACKET_SIZE     1536

/* HW ring buffer configuration */
#define RX_COUNT 256
#define TX_COUNT 256

_Static_assert((RX_COUNT + TX_COUNT) * 2 * BUF_SIZE <= 0x200000, "Expect rx+tx buffers to fit in single 2MB page");
_Static_assert(sizeof(ring_buffer_t) <= 0x200000, "Expect ring buffer ring to fit in single 2MB page");

/* HW ring descriptor (shared with device) */
struct descriptor {
    uint16_t len;
    uint16_t stat;
    uint32_t addr;
};

/* HW ring buffer data type */
typedef struct {
    unsigned int head;                               /* index to insert at */
    unsigned int tail;                               /* index to remove from */
    volatile struct descriptor *descr;               /* buffer descripter array */
    buff_desc_t *descr_mdata;                        /* associated meta data array */
    unsigned int size;                               /* size of ring buffer */
} hw_ring_t;

/* HW ring buffers */
hw_ring_t rx; /* Rx NIC ring */
hw_ring_t tx; /* Tx NIC ring */

/* Ring handles */
ring_handle_t rx_ring;
ring_handle_t tx_ring;

/* Network configuration */
static uint8_t mac[6];

/* Ethernet device address */
volatile struct enet_regs *eth = (void *)(uintptr_t)0x2000000;

/* IRQ mask filtering receival and transmission of packets and bus errors */
uint32_t irq_mask = IRQ_MASK;

static void get_mac_addr(uint8_t *mac)
{
    uint32_t l, h;
    l = eth->palr;
    h = eth->paur;

    mac[0] = l >> 24;
    mac[1] = l >> 16 & 0xff;
    mac[2] = l >> 8 & 0xff;
    mac[3] = l & 0xff;
    mac[4] = h >> 24;
    mac[5] = h >> 16 & 0xff;
}

static void set_mac(uint8_t *mac)
{
    eth->palr = (mac[0] << 24) | (mac[1] << 16) | (mac[2] << 8) | (mac[3]);
    eth->paur = (mac[4] << 24) | (mac[5] << 16);
}

static inline bool hw_ring_full(hw_ring_t *ring)
{
    return !((ring->head - ring->tail + 1) % ring->size);
}

static inline bool hw_ring_empty(hw_ring_t *ring)
{
    return !((ring->head - ring->tail ) % ring->size);
}

static void update_ring_slot(hw_ring_t *ring, unsigned int idx, uintptr_t phys,
                                uint16_t len, uint16_t stat)
{
    volatile struct descriptor *d = &(ring->descr[idx]);
    d->addr = phys;
    d->len = len;

    /* Ensure all writes to the descriptor complete, before we set the flags
     * that makes hardware aware of this slot.
     */
    __sync_synchronize();

    d->stat = stat;
}

static inline void enable_irqs(uint32_t mask)
{
    eth->eimr = mask;
    irq_mask = mask;
}

static void rx_provide(void)
{
    bool reprocess = true;
    while (reprocess) {
        while (!hw_ring_full(&rx) && !ring_empty(rx_ring.free_ring)) {
            buff_desc_t buffer;
            int err __attribute__((unused)) = dequeue_free(&rx_ring, &buffer);
            assert(!err);

            uint16_t stat = RXD_EMPTY;
            if (rx.head + 1 == rx.size) stat |= WRAP;
            rx.descr_mdata[rx.head] = buffer;
            update_ring_slot(&rx, rx.head, buffer.offset + rx_buffer_data_region_paddr, 0, stat);

            THREAD_MEMORY_RELEASE();

            rx.head = (rx.head + 1) % rx.size;
        }

        /* Only request a notification from multiplexer if HW ring not full */
        if (!hw_ring_full(&rx)) request_signal(rx_ring.free_ring);
        else cancel_signal(rx_ring.free_ring);
        reprocess = false;

        if (!ring_empty(rx_ring.free_ring) && !hw_ring_full(&rx)) {
            cancel_signal(rx_ring.free_ring);
            reprocess = true;
        }
    }

    if (!(hw_ring_empty(&rx))) {
        /* Ensure rx IRQs are enabled */
        eth->rdar = RDAR_RDAR;
        if (!(irq_mask & NETIRQ_RXF)) enable_irqs(IRQ_MASK);
    } else {
        enable_irqs(NETIRQ_TXF | NETIRQ_EBERR);
    }
}

static void rx_return(void)
{
    if (ring_full(rx_ring.used_ring)) {
        /* Rx ring is full so diasble RX IRQs. */
        enable_irqs(NETIRQ_TXF | NETIRQ_EBERR);
        __sync_synchronize();
        return;
    }

    bool packets_transferred;
    while (!hw_ring_empty(&rx) && !ring_full(rx_ring.used_ring)) {
        /* If buffer slot is still empty, we have processed all packets the device has filled */
        volatile struct descriptor *d = &(rx.descr[rx.tail]);
        if (d->stat & RXD_EMPTY) break;

        buff_desc_t descr_mdata = rx.descr_mdata[rx.tail];
        descr_mdata.len = d->len;
        
        THREAD_MEMORY_RELEASE();

        rx.tail = (rx.tail + 1) % rx.size;

        int err __attribute__((unused)) = enqueue_used(&rx_ring, descr_mdata);
        assert(!err);

        packets_transferred = true;
    }

    if (packets_transferred && require_signal(rx_ring.used_ring)) {
        cancel_signal(rx_ring.used_ring);
        sel4cp_notify(RX_CH);
    }
}

static void tx_provide(void)
{
    bool reprocess = true;
    while (reprocess) {
        while (!(hw_ring_full(&tx)) && !ring_empty(tx_ring.used_ring)) {
            buff_desc_t buffer;
            int err __attribute__((unused)) = dequeue_used(&tx_ring, &buffer);
            assert(!err);

            uintptr_t phys = buffer.offset + tx_buffer_data_region_paddr;
        
            uint16_t stat = TXD_READY | TXD_ADDCRC | TXD_LAST;
            if (tx.head + 1 == tx.size) stat |= WRAP;
            tx.descr_mdata[tx.head] = buffer;
            update_ring_slot(&tx, tx.head, phys, buffer.len, stat);

            THREAD_MEMORY_RELEASE();

            tx.head = (tx.head + 1) % tx.size;
            if (!(eth->tdar & TDAR_TDAR)) eth->tdar = TDAR_TDAR;
        }
    
        request_signal(tx_ring.used_ring);
        reprocess = false;

        if (!hw_ring_full(&tx) && !ring_empty(tx_ring.used_ring)) {
            cancel_signal(tx_ring.used_ring);
            reprocess = true;
        }
    }
}

static void tx_return(void)
{
    bool enqueued;
    while (!hw_ring_empty(&tx) && !ring_full(tx_ring.free_ring)) {
        /* Ensure that this buffer has been sent by the device */
        volatile struct descriptor *d = &(tx.descr[tx.tail]);
        if (d->stat & TXD_READY) break;

        buff_desc_t descr_mdata = tx.descr_mdata[tx.tail];
        descr_mdata.len = 0;

        THREAD_MEMORY_RELEASE();

        tx.tail = (tx.tail + 1) % tx.size;

        int err __attribute__((unused)) = enqueue_free(&tx_ring, descr_mdata);
        assert(!err);
        enqueued = true;
    }

    if (enqueued && require_signal(tx_ring.free_ring)) {
        cancel_signal(tx_ring.free_ring);
        sel4cp_notify(TX_CH);
    }
}

static void handle_irq(void)
{
    uint32_t e = eth->eir & irq_mask;
    /* write to clear events */
    eth->eir = e;

    while (e & irq_mask) {
        if (e & NETIRQ_TXF) tx_return();
        if (e & NETIRQ_RXF) {
            rx_return();
            rx_provide();
        }
        if (e & NETIRQ_EBERR) printf("ETH|ERROR: System bus/uDMA\n");
        e = eth->eir & irq_mask;
        eth->eir = e;
    }
}

static void eth_setup(void)
{
    get_mac_addr(mac);

    /* Set up HW rings */
    rx.descr = (volatile struct descriptor *)hw_ring_buffer_vaddr;
    rx.descr_mdata = (buff_desc_t *)rx_cookies;
    rx.size = RX_COUNT;
    tx.descr = (volatile struct descriptor *)(hw_ring_buffer_vaddr + (sizeof(struct descriptor) * RX_COUNT));
    tx.descr_mdata = (buff_desc_t *)tx_cookies;
    tx.size = TX_COUNT;

    /* Perform reset */
    eth->ecr = ECR_RESET;
    while (eth->ecr & ECR_RESET);
    eth->ecr |= ECR_DBSWP;

    /* Clear and mask interrupts */
    eth->eimr = 0x00000000;
    eth->eir  = 0xffffffff;

    /* set MDIO freq */
    eth->mscr = 24 << 1;

    /* Disable */
    eth->mibc |= MIBC_DIS;
    while (!(eth->mibc & MIBC_IDLE));
    /* Clear */
    eth->mibc |= MIBC_CLEAR;
    while (!(eth->mibc & MIBC_IDLE));
    /* Restart */
    eth->mibc &= ~MIBC_CLEAR;
    eth->mibc &= ~MIBC_DIS;

    /* Descriptor group and individual hash tables - Not changed on reset */
    eth->iaur = 0;
    eth->ialr = 0;
    eth->gaur = 0;
    eth->galr = 0;

    /* Mac address needs setting again. */
    if (eth->palr == 0) set_mac(mac);

    eth->opd = PAUSE_OPCODE_FIELD;

    /* coalesce transmit IRQs to batches of 128 */
    eth->txic0 = ICEN | ICFT(128) | 0xFF;
    eth->tipg = TIPG;
    /* Transmit FIFO Watermark register - store and forward */
    eth->tfwr = STRFWD;
    /* clear rx store and forward. This must be done for hardware csums*/
    eth->rsfl = 0;
    /* Do not forward frames with errors + check the csum */
    eth->racc = RACC_LINEDIS | RACC_IPDIS | RACC_PRODIS;
    /* Add the checksum for known IP protocols */
    eth->tacc = TACC_PROCHK | TACC_IPCHK;

    /* Set RDSR */
    eth->rdsr = hw_ring_buffer_paddr;
    eth->tdsr = hw_ring_buffer_paddr + (sizeof(struct descriptor) * RX_COUNT);

    /* Size of max eth packet size */
    eth->mrbr = MAX_PACKET_SIZE;

    eth->rcr = RCR_MAX_FL(1518) | RCR_RGMII_EN | RCR_MII_MODE | RCR_PROMISCUOUS;
    eth->tcr = TCR_FDEN;

    /* set speed */
    eth->ecr |= ECR_SPEED;

    /* Set Enable  in ECR */
    eth->ecr |= ECR_ETHEREN;

    eth->rdar = RDAR_RDAR;

    /* enable events */
    eth->eir = eth->eir;
    eth->eimr = IRQ_MASK;
}

void init(void)
{
    eth_setup();

    ring_init(&rx_ring, (ring_buffer_t *)rx_free, (ring_buffer_t *)rx_used, NUM_BUFFERS, NUM_BUFFERS);
    ring_init(&tx_ring, (ring_buffer_t *)tx_free, (ring_buffer_t *)tx_used, NUM_BUFFERS, NUM_BUFFERS);

    buffers_init((ring_buffer_t *)rx_free, 0, NUM_BUFFERS, BUF_SIZE);

    rx_provide();
    tx_provide();
}

void notified(sel4cp_channel ch)
{
    switch(ch) {
        case IRQ_CH:
            handle_irq();
            /*
             * Delay calling into the kernel to ack the IRQ until the next loop
             * in the seL4CP event handler loop.
             */
            sel4cp_irq_ack_delayed(ch);
            break;
        case RX_CH:
            rx_provide();
            break;
        case TX_CH:
            tx_provide();
            break;
        default:
            printf("ETH|LOG: received notification on unexpected channel: %X\n", ch);
            break;
    }
}