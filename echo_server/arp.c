#include <string.h>

#include "cache.h"
#include "eth.h"
#include "lwip/ip_addr.h"
#include "netif/etharp.h"
#include "shared_ringbuffer.h"
#include "system.h"
#include "util.h"

/* Notification and PPC channels */
#define RX_CH 0
#define TX_CH 1
#define CLIENT_CH 2

/* PPC message labels */
#define REG_IP 0

/* Network configuration */
#define ETH_HWADDR_LEN 6
#define IPV4_PROTO_LEN 4
#define PADDING_SIZE 10
#define LWIP_IANA_HWTYPE_ETHERNET 1

#define NUM_ARP_CLIENTS (NUM_CLIENTS - 1)

/* Ring handles */
ring_handle_t rx_ring;
ring_handle_t tx_ring;

/* Ring buffer regions */
uintptr_t rx_free;
uintptr_t rx_used;
uintptr_t tx_free;
uintptr_t tx_used;

/* Buffer data regions */
uintptr_t rx_buffer_data_region;
uintptr_t tx_buffer_data_region;

uintptr_t uart_base;

/* Client network configuration */
uint8_t mac_addrs[NUM_ARP_CLIENTS][ETH_HWADDR_LEN];
uint32_t ipv4_addrs[NUM_ARP_CLIENTS];

struct __attribute__((__packed__)) arp_packet {
    uint8_t ethdst_addr[ETH_HWADDR_LEN];
    uint8_t ethsrc_addr[ETH_HWADDR_LEN];
    uint16_t type;
    uint16_t hwtype;
    uint16_t proto;
    uint8_t hwlen;
    uint8_t protolen;
    uint16_t opcode;
    uint8_t hwsrc_addr[ETH_HWADDR_LEN];
    uint32_t ipsrc_addr;
    uint8_t hwdst_addr[ETH_HWADDR_LEN];
    uint32_t ipdst_addr;
    uint8_t padding[10];
    uint32_t crc;
};

static int match_ip_to_client(uint32_t addr)
{
    for (int i = 0; i < NUM_ARP_CLIENTS; i++) {
        if (ipv4_addrs[i] == addr) {
            return i;
        }
    }

    return -1;
}

static int arp_reply(const uint8_t ethsrc_addr[ETH_HWADDR_LEN],
                const uint8_t ethdst_addr[ETH_HWADDR_LEN],
                const uint8_t hwsrc_addr[ETH_HWADDR_LEN], const uint32_t ipsrc_addr,
                const uint8_t hwdst_addr[ETH_HWADDR_LEN], const uint32_t ipdst_addr)
{
    if (ring_empty(tx_ring.free_ring)) {
        printf("ARP|LOG: Transmit free ring empty or transmit used ring full. Dropping reply\n");
        return -1;
    }

    buff_desc_t buffer;
    int err __attribute__((unused)) = dequeue_free(&tx_ring, &buffer);
    assert(!err);

    uintptr_t addr = tx_buffer_data_region + buffer.phys_or_offset;

    struct arp_packet *reply = (struct arp_packet *)addr;
    memcpy(&reply->ethdst_addr, ethdst_addr, ETH_HWADDR_LEN);
    memcpy(&reply->ethsrc_addr, ethsrc_addr, ETH_HWADDR_LEN);

    reply->type = lwip_htons(ETHTYPE_ARP);
    reply->hwtype = PP_HTONS(LWIP_IANA_HWTYPE_ETHERNET);
    reply->proto = PP_HTONS(ETHTYPE_IP);
    reply->hwlen = ETH_HWADDR_LEN;
    reply->protolen = IPV4_PROTO_LEN;
    reply->opcode = lwip_htons(ARP_REPLY);

    memcpy(&reply->hwsrc_addr, hwsrc_addr, ETH_HWADDR_LEN);
    reply->ipsrc_addr = ipsrc_addr;
    memcpy(&reply->hwdst_addr, hwdst_addr, ETH_HWADDR_LEN); 
    reply->ipdst_addr = ipdst_addr;
    memset(&reply->padding, 0, 10);

    buffer.len = 56;
    err = enqueue_used(&tx_ring, buffer);
    assert(!err);

    return 0;
}

void receive(void)
{
    bool transmitted = false;
    bool reprocess = true;
    while (reprocess) {
        while (!ring_empty(rx_ring.used_ring)) {
            buff_desc_t buffer;
            int err __attribute__((unused)) = dequeue_used(&rx_ring, &buffer);
            assert(!err);
            uintptr_t addr = rx_buffer_data_region + buffer.phys_or_offset;

            /* Check if packet is an ARP request */
            struct eth_hdr *ethhdr = (struct eth_hdr *)addr;
            if (ethhdr->type == PP_HTONS(ETHTYPE_ARP)) {
                struct arp_packet *pkt = (struct arp_packet *)addr;
                /* Check if it's a probe, ignore announcements */
                if (pkt->opcode == PP_HTONS(ARP_REQUEST)) {
                    /* Check it it's for a client */
                    int client = match_ip_to_client(pkt->ipdst_addr);
                    if (client >= 0) {
                        /* Send a response */
                        if (!arp_reply(mac_addrs[client], pkt->ethsrc_addr, mac_addrs[client], pkt->ipdst_addr,
                                    pkt->hwsrc_addr, pkt->ipsrc_addr)) transmitted = true;
                    }
                }
            }

            buffer.len = 0;
            err = enqueue_free(&rx_ring, buffer);
            assert(!err);
        }

        request_signal(rx_ring.used_ring);
        reprocess = false;

        if (!ring_empty(rx_ring.used_ring)) {
            cancel_signal(rx_ring.used_ring);
            reprocess = true;
        }
    }

    if (transmitted && require_signal(tx_ring.used_ring)) {
        cancel_signal(tx_ring.used_ring);
        sel4cp_notify_delayed(TX_CH);
    }
}

void notified(sel4cp_channel ch)
{
    receive();
}

seL4_MessageInfo_t protected(sel4cp_channel ch, sel4cp_msginfo msginfo)
{
    int client = ch - CLIENT_CH;
    if (client >= NUM_ARP_CLIENTS || client < 0) {
        printf("ARP|LOG: PPC from unkown client: %d\n", client);
        return sel4cp_msginfo_new(0, 0);
    }

    uint32_t ip_addr = sel4cp_mr_get(0);
    uint32_t mac_higher = sel4cp_mr_get(1);
    uint32_t mac_lower = sel4cp_mr_get(2);
    uint64_t mac = (((uint64_t) mac_higher) << 32) | mac_lower;

    char buf[16];
    switch (sel4cp_msginfo_get_label(msginfo)) {
        case REG_IP:
            printf("ARP|NOTICE: client%d registering ip address: %s with MAC: ", client, ipaddr_to_string(ip_addr, buf, 16));
            dump_mac(mac);
            ipv4_addrs[client] = ip_addr;
            break;
        default:
            printf("ARP|LOG: PPC from client%d with unknown message label: %X\n", ch);
            break;
    }

    return sel4cp_msginfo_new(0, 0);
}

void init(void)
{
    ring_init(&rx_ring, (ring_buffer_t *)rx_free, (ring_buffer_t *)rx_used, RX_RING_SIZE_ARP);
    ring_init(&tx_ring, (ring_buffer_t *)tx_free, (ring_buffer_t *)tx_used, TX_RING_SIZE_ARP);
    buffers_init((ring_buffer_t *)tx_free, 0, TX_RING_SIZE_ARP);

    mac_addr_init_sys(sel4cp_name, (uint8_t *) mac_addrs);
}