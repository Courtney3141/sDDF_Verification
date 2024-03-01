#include <string.h>
#include <microkit.h>

#include "echo.h"
#include "timer.h"
#include "util.h"
#include "lwip/ip.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"

uint64_t tx_bytes_total;

// Send ring buffer for holding sent data until it is acknowledged.
//
// * Tail should never overtake head, and tail == head for empty queue.
// * The TCP window should equal the remaining space in this ring buffer.
//
// TODO make this per-connection instead of global.
struct {
    // At most ECHO_QUEUE_SIZE - 1 bytes can be in the queue
    #define ECHO_QUEUE_SIZE (TCP_WND + 1)

    char buf[ECHO_QUEUE_SIZE];
    size_t tail; // data gets added at tail
    size_t head; // acknowledged data gets removed from head
} static echo_queue;

// Total free space remaining
static size_t echo_queue_space()
{
    return (echo_queue.head + ECHO_QUEUE_SIZE - echo_queue.tail - 1) % ECHO_QUEUE_SIZE;
}

// Number of bytes that can be added contiguously to tail
static size_t echo_queue_contiguous_space()
{
    if (echo_queue.tail >= echo_queue.head) return ECHO_QUEUE_SIZE - echo_queue.tail;
    return echo_queue.head - echo_queue.tail - 1;
}

// print statistics
static err_t tcp_echo_report(void* arg, struct tcp_pcb* pcb)
{
    printf("%u | tx=%d queue={tail=%d head=%d space=%d} rcv_wnd=%d sndbuf=%d queuelen=%d\n",
        sys_now(),
        tx_bytes_total,

        echo_queue.tail,
        echo_queue.head,
        echo_queue_space(),

        pcb->rcv_wnd,
        tcp_sndbuf(pcb),
        pcb->snd_queuelen
    );
    return ERR_OK;
}

static err_t tcp_echo_sent(void* arg, struct tcp_pcb* pcb, u16_t len)
{
    tx_bytes_total += len;

    /* printf("----- %u: sent: len=%d\n", sys_now(), len); */

    echo_queue.head = (echo_queue.head + len) % ECHO_QUEUE_SIZE;

    // tcp_recved is only for increasing the TCP window, and isn't required to
    // ACK incoming packets (that is done automatically on receive).
    tcp_recved(pcb, len);

    return ERR_OK;
}

static err_t tcp_echo_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    if (p == NULL) {
        printf("TCP closing\n");
        err = tcp_close(pcb);
        if (err) {
            printf("TCP close error: %s\n", lwip_strerr(err));
            return err;
        }
        return ERR_OK;
    }
    if (err) {
        printf("TCP recv error: %s\n", lwip_strerr(err));
        return err;
    }

    /*
    printf("----- %u: recv: tot_len=%d queuelen=%d sndbuf=%d qhead=%d qtail=%d qcap=%d\n",
        sys_now(),
        p->tot_len,
        (int) pcb->snd_queuelen,
        (int) tcp_sndbuf(pcb),
        (int) echo_queue.head,
        (int) echo_queue.tail,
        (int) echo_queue_capacity()
    );
    */

    assert(p->tot_len > 0);

    const u16_t capacity = min(min(echo_queue_space(), tcp_sndbuf(pcb)), p->tot_len);
    if (p->tot_len > capacity) {
        printf("%u: Can't handle packet of %d bytes: echo_queue_space=%d sndbuf=%d snd_queuelen=%d\n",
            sys_now(),
            echo_queue_space(),
            tcp_sndbuf(pcb),
            pcb->snd_queuelen
        );

        // This causes LWIP to wait a bit and try calling this function again
        // with the packet. To avoid double-sending any data in the packet, we
        // don't handle the packet at all, even if we would have space for part
        // of it.
        return ERR_MEM;
    }

    struct pbuf* data = NULL;
    u16_t offset = 0;
    while (offset < capacity) {
        const u16_t copied_len = pbuf_copy_partial(
            p,
            echo_queue.buf + echo_queue.head,
            min(echo_queue_contiguous_space(), capacity - offset),
            offset
        );

        err = tcp_write(pcb, echo_queue.buf + echo_queue.head, copied_len, 0);
        if (err) {
            printf("Failed to tcp_write: %s\n", lwip_strerr(err));
            printf("  snd_queuelen=%d snd_buf=%d\n", pcb->snd_queuelen, pcb->snd_buf);
            assert(false);
        }

        offset += copied_len;
        echo_queue.tail = (echo_queue.tail + copied_len) % ECHO_QUEUE_SIZE;
    }

    tcp_output(pcb);

    pbuf_free(p);
    return ERR_OK;
}

static void tcp_echo_err(void *arg, err_t err)
{
    printf("%u | TCP error: %s\n", sys_now(), lwip_strerr(err));
}

static err_t tcp_accept_callback(void *arg, struct tcp_pcb *pcb, err_t err) {
    printf("%u | TCP connected\n", sys_now());

    tcp_nagle_disable(pcb);

    tcp_arg(pcb, (void *)pcb);
    tcp_recv(pcb, tcp_echo_recv);
    tcp_sent(pcb, tcp_echo_sent);
    tcp_err(pcb, tcp_echo_err);
    tcp_poll(pcb, tcp_echo_report, 2);

    return ERR_OK;
}

int setup_tcp_socket(void)
{
    struct tcp_pcb *tcp_socket;

    tcp_socket = tcp_new_ip_type(IPADDR_TYPE_V4);
    if (tcp_socket == NULL) {
        printf("Failed to open a TCP socket");
        return -1;
    }

    err_t error = tcp_bind(tcp_socket, IP_ANY_TYPE, TCP_ECHO_PORT);
    if (error) {
        printf("Failed to bind TCP echo socket: %d\n", (int) error);
        return -1;
    }

    tcp_socket = tcp_listen_with_backlog_and_err(tcp_socket, 1, &error);
    if (error) {
        printf("Failed to listen on TCP echo socket: %d\n", (int) error);
        return -1;
    }
    tcp_accept(tcp_socket, tcp_accept_callback);

    return 0;
}