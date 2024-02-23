#pragma once

#include "util.h"

#define ETH_HWADDR_LEN 6

static char * ipaddr_to_string(uint32_t s_addr, char *buf, int buflen)
{
    char inv[3], *rp;
    u8_t *ap, rem, n, i;
    int len = 0;

    rp = buf;
    ap = (u8_t *)&s_addr;
    for (n = 0; n < 4; n++) {
    i = 0;
    do {
        rem = *ap % (u8_t)10;
        *ap /= (u8_t)10;
        inv[i++] = (char)('0' + rem);
    } while (*ap);
    while (i--) {
        if (len++ >= buflen) {
        return NULL;
        }
        *rp++ = inv[i];
    }
    if (len++ >= buflen) {
        return NULL;
    }
    *rp++ = '.';
    ap++;
    }
    *--rp = 0;
    return buf;
}

static void dump_mac(uint64_t mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac >> 40, mac >> 32 & 0xff, mac >> 24 & 0xff, mac >> 16 & 0xff, mac >> 8 & 0xff, mac & 0xff);
}

static void set_mac_addr(uint8_t *mac, uint64_t val)
{
    mac[0] = val >> 40 & 0xff;
    mac[1] = val >> 32 & 0xff;
    mac[2] = val >> 24 & 0xff;
    mac[3] = val >> 16 & 0xff;
    mac[4] = val >> 8 & 0xff;
    mac[5] = val & 0xff;
}