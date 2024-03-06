#include <string.h>
#include <microkit.h>

#include "echo.h"
#include "timer.h"
#include "util.h"
#include "lwip/ip.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"

// At most ECHO_QUEUE_SIZE - 1 bytes can be in the queue
#define ECHO_QUEUE_SIZE (TCP_WND + 1)

struct echo_state {
    // sending ring buffer
    size_t tail; // data gets added at tail
    size_t head; // moved forward for acknowledged data
    char buf[ECHO_QUEUE_SIZE];
};

LWIP_MEMPOOL_DECLARE(
    tcp_echo_state,
    8,
    sizeof(struct echo_state),
    "TCP echo server connection state"
);

static size_t queue_space(struct echo_state* state)
{
    return (state->head + ECHO_QUEUE_SIZE - state->tail - 1) % ECHO_QUEUE_SIZE;
}

static size_t queue_cont_space(struct echo_state* state)
{
    if (state->tail >= state->head) return ECHO_QUEUE_SIZE - state->tail;
    return state->head - state->tail - 1;
}

static err_t tcp_echo_sent(void* arg, struct tcp_pcb* pcb, u16_t len)
{
    struct echo_state* state = arg;

    state->head = (state->head + len) % ECHO_QUEUE_SIZE;

    // tcp_recved is only for increasing the TCP window, and isn't required to
    // ACK incoming packets (that is done automatically on receive).
    tcp_recved(pcb, len);

    return ERR_OK;
}

static err_t tcp_echo_recv(void* arg, struct tcp_pcb* pcb, struct pbuf* p, err_t err)
{
    struct echo_state* state = arg;

    if (p == NULL) {
        // closing
        printf("tcp_echo[%p]: closing\n", state);

        // TODO is this a use-after-free?
        LWIP_MEMPOOL_FREE(tcp_echo_state, state);

        err = tcp_close(pcb);
        if (err) {
            printf("tcp_echo[%p]: close error: %s\n", state, lwip_strerr(err));
            return err;
        }
        return ERR_OK;
    }
    if (err) {
        printf("tcp_echo[%p]: recv error: %s\n", state, lwip_strerr(err));
        return err;
    }

    assert(p->tot_len > 0);

    const size_t capacity = MIN(MIN(queue_space(state), tcp_sndbuf(pcb)), p->tot_len);
    if (p->tot_len > capacity) {
        printf("tcp_echo[%p]: can't handle packet of %d bytes: queue_space=%lu sndbuf=%d snd_queuelen=%d\n",
            state,
            p->tot_len,
            queue_space(state),
            tcp_sndbuf(pcb),
            pcb->snd_queuelen
        );

        // This causes LWIP to wait a bit and try calling this function again
        // with the packet. To avoid double-sending any data in the packet, we
        // don't handle the packet at all, even if we would have space for part
        // of it.
        return ERR_MEM;
    }

    size_t offset = 0;
    while (offset < capacity) {
        const u16_t copied_len = pbuf_copy_partial(
            p,
            state->buf + state->tail,
            MIN(queue_cont_space(state), capacity - offset),
            offset
        );

        err = tcp_write(pcb, state->buf + state->tail, copied_len, 0);
        if (err) {
            printf("tcp_echo[%p]: failed to write: %s\n", state, lwip_strerr(err));
            assert(false);
        }

        offset += copied_len;
        state->tail = (state->tail + copied_len) % ECHO_QUEUE_SIZE;
    }

    tcp_output(pcb);

    pbuf_free(p);
    return ERR_OK;
}

static void tcp_echo_err(void* arg, err_t err)
{
    struct echo_state* state = arg;

    printf("tcp_echo[%p]: %s\n", arg, lwip_strerr(err));

    LWIP_MEMPOOL_FREE(tcp_echo_state, state);
}

static err_t tcp_echo_accept(void* arg, struct tcp_pcb* pcb, err_t err)
{
    struct echo_state* state = LWIP_MEMPOOL_ALLOC(tcp_echo_state);
    if (state == NULL) {
        printf("tcp_echo: failed to alloc state\n");
        return ERR_MEM;
    }

    printf("tcp_echo[%p]: accept from %s port %d\n",
        state,
        ipaddr_ntoa(&pcb->remote_ip),
        pcb->remote_port
    );

    state->tail = 0;
    state->head = 0;

    tcp_nagle_disable(pcb);
    tcp_arg(pcb, state);
    tcp_sent(pcb, tcp_echo_sent);
    tcp_recv(pcb, tcp_echo_recv);
    tcp_err(pcb, tcp_echo_err);

    return ERR_OK;
}

int setup_tcp_socket(void)
{
    LWIP_MEMPOOL_INIT(tcp_echo_state);

    struct tcp_pcb* pcb;

    pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
    if (pcb == NULL) {
        printf("Failed to open TCP echo socket\n");
        return -1;
    }

    err_t error = tcp_bind(pcb, IP_ANY_TYPE, TCP_ECHO_PORT);
    if (error) {
        printf("Failed to bind TCP echo socket: %s\n", lwip_strerr(error));
        return -1;
    }

    pcb = tcp_listen_with_backlog_and_err(pcb, 1, &error);
    if (error) {
        printf("Failed to listen on TCP echo socket: %s\n", lwip_strerr(error));
        return -1;
    }

    tcp_accept(pcb, tcp_echo_accept);

    return 0;
}