#include <microkit.h>

#include "lwip/ip.h"
#include "lwip/err.h"
#include "lwip/pbuf.h"
#include "lwip/udp.h"
#include "lwip/priv/tcp_priv.h"

#include "echo.h"

// pcb to dump
struct tcp_pcb* pcap_target;

// where to write pcap to
static struct udp_pcb* socket;
static ip_addr_t out_addr;
static u16_t out_port;

struct pcap_file_header {
    u32_t magic;
    u16_t major_version;
    u16_t minor_version;
    u32_t reserved1;
    u32_t reserved2;
    u32_t snaplen;
    u32_t linktype;
};

struct pcap_packet_header {
    u32_t time_s;
    u32_t time_us;
    u32_t captured_len;
    u32_t orig_len;
};

void lwip_capture_packet(struct pbuf* p)
{
    if (!out_addr.addr || !out_port) return; // no receiver

    microkit_ppcall(1, microkit_msginfo_new(0, 0));
    uint64_t time_us = seL4_GetMR(0);

    struct pcap_packet_header h;
    h.time_s = time_us / 1000000;
    h.time_us = time_us % 1000000;
    h.captured_len = p->tot_len;
    h.orig_len = p->tot_len;

    struct pbuf* packet = pbuf_alloc_reference(&h, sizeof(h), PBUF_REF);
    pbuf_cat(packet, pbuf_clone(PBUF_RAW, PBUF_RAM, p));
    udp_sendto(socket, packet, &out_addr, out_port);
    pbuf_free(packet);

    putC('.');
}

int lwip_hook_tcp_inpacket_pcb(struct tcp_pcb *pcb, struct tcp_hdr *hdr, u16_t optlen, u16_t opt1len, u8_t *opt2, struct pbuf *p)
{
    if (!pcb || pcb != pcap_target) return 0;
    if (!out_addr.addr || !out_port) return 0; // no receiver

    microkit_ppcall(1, microkit_msginfo_new(0, 0));
    uint64_t time_us = seL4_GetMR(0);

    struct pcap_packet_header h;
    h.time_s = time_us / 1000000;
    h.time_us = time_us % 1000000;
    h.captured_len = TCP_HLEN + optlen;
    h.orig_len = TCP_HLEN + optlen + p->tot_len;

    struct pbuf* packet = pbuf_alloc_reference(&h, sizeof(h), PBUF_REF);

    // temporarily convert TCP header back to network byte order
    hdr->src = lwip_htons(hdr->src);
    hdr->dest = lwip_htons(hdr->dest);
    hdr->seqno = lwip_htonl(hdr->seqno);
    hdr->ackno = lwip_htonl(hdr->ackno);
    hdr->wnd = lwip_htons(hdr->wnd);

    pbuf_cat(packet, pbuf_alloc_reference(hdr, TCP_HLEN + opt1len, PBUF_REF));
    if (opt2) {
        pbuf_cat(packet, pbuf_alloc_reference(opt2, optlen - opt1len, PBUF_REF));
    }

    udp_sendto(socket, packet, &out_addr, out_port);
    pbuf_free(packet);

    // convert TCP header back to host order
    hdr->src = lwip_ntohs(hdr->src);
    hdr->dest = lwip_ntohs(hdr->dest);
    hdr->seqno = lwip_ntohl(hdr->seqno);
    hdr->ackno = lwip_ntohl(hdr->ackno);
    hdr->wnd = lwip_ntohs(hdr->wnd);

    return 0;
}

int lwip_hook_tcp_outpacket_pcb(struct tcp_pcb *pcb, struct pbuf *p)
{
    if (!pcb || pcb != pcap_target) return 0;
    if (!out_addr.addr || !out_port) return 0; // no receiver

    microkit_ppcall(1, microkit_msginfo_new(0, 0));
    uint64_t time_us = seL4_GetMR(0);

    struct pcap_packet_header h;
    h.time_s = time_us / 1000000;
    h.time_us = time_us % 1000000;
    h.captured_len = p->tot_len;
    h.orig_len = p->tot_len;

    struct pbuf* packet = pbuf_alloc_reference(&h, sizeof(h), PBUF_REF);
    udp_sendto(socket, packet, &out_addr, out_port);
    pbuf_free(packet);

    udp_sendto(socket, p, &out_addr, out_port);

    return 0;
}

static void udp_recv_callback(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
    printf("PCAP UDP connect\n");

    // send pcap header
    struct pcap_file_header h;
    h.magic = 0xA1B2C3D4;
    h.major_version = 2;
    h.minor_version = 4;
    h.reserved1 = 0;
    h.reserved2 = 0;
    h.snaplen = -1;
    h.linktype = 1;
    struct pbuf* packet = pbuf_alloc_reference(&h, sizeof(h), PBUF_REF);
    udp_sendto(pcb, packet, addr, port);
    pbuf_free(packet);

    out_addr = *addr;
    out_port = port;

    pbuf_free(p);
}


int setup_pcap_socket(void)
{
    err_t err;

    socket = udp_new_ip_type(IPADDR_TYPE_V4);
    if (socket == NULL) {
        printf("Failed to open a UDP socket\n");
        return -1;
    }

    err = udp_bind(socket, IP_ANY_TYPE, 9999);
    if (err != ERR_OK) {
        printf("Failed to bind: %d\n", (int) err);
        return -1;
    }

    udp_recv(socket, udp_recv_callback, NULL);

    return 0;
}
