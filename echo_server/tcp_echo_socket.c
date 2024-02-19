#include <string.h>
#include <microkit.h>

#include "lwip/ip.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "timer.h"

#include "echo.h"

#define TCP_ECHO_PORT 1237

uintptr_t tcp_recv_buffer;

static struct tcp_pcb *tcp_socket;

static inline void my_reverse(char s[])
{
    int i, j;
    char c;

    for (i = 0, j = strlen(s)-1; i<j; i++, j--) {
        c = s[i];
        s[i] = s[j];
        s[j] = c;
    }
}

static inline void my_itoa(uint64_t n, char s[])
{
    int i;
    uint64_t sign;

    if ((sign = n) < 0)  /* record sign */
        n = -n;          /* make n positive */
    i = 0;
    do {       /* generate digits in reverse order */
        s[i++] = n % 10 + '0';   /* get next digit */
    } while ((n /= 10) > 0);     /* delete it */
    if (sign < 0)
        s[i++] = '-';
    s[i] = '\0';
    my_reverse(s);
}

static err_t lwip_tcp_sent_callback(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    return ERR_OK;
}

static err_t lwip_tcp_recv_callback(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    if (p == NULL) {
        print("Closing conn\n");
        err = tcp_close(pcb);
        if (err) {
            print("Error closing\n");
        }
        return ERR_OK;
    }



    pbuf_copy_partial(p, (void *)tcp_recv_buffer, p->tot_len, 0);



    // uint64_t time_bef = sys_now();

    err = tcp_write(pcb, (void *)tcp_recv_buffer, p->tot_len, TCP_WRITE_FLAG_COPY);

    // uint64_t time_aft = sys_now();

    // char buffer[20];

    // // my_itoa(time_bef, buffer);
    // // print("Time before: ");
    // // print(buffer);
    // // my_itoa(time_aft, buffer);
    // my_itoa(time_aft-time_bef, buffer);
    // print(" Time diff: ");
    // print(buffer);
    // putC('\n');

    if (err) {
        err = tcp_output(pcb);
        if (err) {
            print("Message can't send\n");
        }
    }

    tcp_recved(pcb, p->tot_len);

    pbuf_free(p);

    return ERR_OK;

}

void lwip_tcp_err_callback(void *arg, err_t err) {

    switch (err) {
        case ERR_RST:
            print("Connection reset by peer\n");
            struct pcb *tcp_pcb = (struct pcb*)arg;
            tcp_close(tcp_pcb);
            break;
        case ERR_ABRT:
            print("Connection aborted\n");
            break;

        default:
            print("ERROR HAS OCCURED\n");
            // char buffer[100];
            // my_itoa(err, buffer);
            // print(buffer);
            // putC('\n');

    }

}

static err_t tcp_accept_callback(void *arg, struct tcp_pcb *pcb, err_t err) {
    print("TCP CONNECTED\n");

    tcp_nagle_disable(pcb);

    tcp_arg(pcb, (void *)pcb);
    tcp_recv(pcb, lwip_tcp_recv_callback);
    tcp_err(pcb, lwip_tcp_err_callback);

    return ERR_OK;
}



int setup_tcp_socket(void)
{
    tcp_socket = tcp_new_ip_type(IPADDR_TYPE_V4);
    if (tcp_socket == NULL) {
        microkit_dbg_puts("Failed to open a TCP socket");
        return -1;
    }

    int error = tcp_bind(tcp_socket, IP_ANY_TYPE, TCP_ECHO_PORT);
    if (error == ERR_OK) {
        tcp_socket = tcp_listen(tcp_socket);

        tcp_accept(tcp_socket, tcp_accept_callback);
    } else {
        microkit_dbg_puts("Failed to bind the TCP socket");
        return -1;
    }

    return 0;
}