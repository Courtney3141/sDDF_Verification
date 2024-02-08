/*
 * Copyright 2022, UNSW
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#define UART_REG(x) ((volatile uint32_t *)(UART_BASE + (x)))
#define UART_BASE 0x5000000 //0x30890000 in hardware on imx8mm.
#define STAT 0x98
#define TRANSMIT 0x40
#define STAT_TDRE (1 << 14)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

#ifdef __GNUC__
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x)   (!!(x))
#define unlikely(x) (!!(x))
#endif

static void putC(uint8_t ch)
{
    while (!(*UART_REG(STAT) & STAT_TDRE)) { }
    *UART_REG(TRANSMIT) = ch;
}

static void print(const char *s)
{
#ifndef NO_PRINTING
    while (*s) {
        putC(*s);
        s++;
    }
#endif
}

static char hexchar(unsigned int v)
{
    return v < 10 ? '0' + v : ('a' - 10) + v;
}

static void puthex64(uint64_t val)
{
    char buffer[16 + 3];
    buffer[0] = '0';
    buffer[1] = 'x';
    buffer[16 + 3 - 1] = 0;
    for (unsigned i = 16 + 1; i > 1; i--) {
        buffer[i] = hexchar(val & 0xf);
        val >>= 4;
    }
    print(buffer);
}

static char decchar(unsigned int v) {
    return '0' + v;
}

static void put8(uint8_t x)
{
    char tmp[4];
    unsigned i = 3;
    tmp[3] = 0;
    do {
        uint8_t c = x % 10;
        tmp[--i] = decchar(c);
        x /= 10;
    } while (x);
    print(&tmp[i]);
}

static void _assert_fail(const char  *assertion, const char  *file, unsigned int line, const char  *function)
{
    print("Failed assertion '");
    print(assertion);
    print("' at ");
    print(file);
    print(":");
    put8(line);
    print(" in function ");
    print(function);
    print("\n");
    while (1) {}
}

/* CDTODO: From here will be included into a netowrk util header */

#include "printf.h"
#include "cc.h"
#include <stdint.h>

/*
     MAC address for imx8mm 
    state.mac_addrs[0][0] = 0;
    state.mac_addrs[0][1] = 0x4;
    state.mac_addrs[0][2] = 0x9f;
    state.mac_addrs[0][3] = 0x5;
    state.mac_addrs[0][4] = 0xf8;
    state.mac_addrs[0][5] = 0xcc;
*/

/* Turns IP adddress into string */
static char * ipaddr_to_string(uint32_t s_addr, char *buf, int buflen)
{
    char inv[3];
    char *rp;
    u8_t *ap;
    u8_t rem;
    u8_t n;
    u8_t i;
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

/* Prints mac address */
static void dump_mac(uint8_t *mac)
{
    for (unsigned i = 0; i < 6; i++) {
        putC(hexchar((mac[i] >> 4) & 0xf));
        putC(hexchar(mac[i] & 0xf));
        if (i < 5) {
            putC(':');
        }
    }
}

#ifdef NO_ASSERT

#define assert(expr)

#else

#define assert(expr) \
    do { \
        if (!(expr)) { \
            _assert_fail(#expr, __FILE__, __LINE__, __FUNCTION__); \
        } \
    } while(0)

#endif