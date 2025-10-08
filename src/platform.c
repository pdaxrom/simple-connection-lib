/*
 * Platform-specific utilities implementation
 *
 * Copyright (c) 2025 Alexander Chukov <sashz@pdaXrom.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include "platform.h"

#ifdef _WIN32
static int winsock_inited = 0;

int simple_connection_winsock_init(void)
{
    WSADATA w;

    if (winsock_inited)
        return 0;

    if (WSAStartup(0x0101, &w) != 0) {
        fprintf(stderr, "Could not open Windows connection.\n");
        return -1;
    }

    winsock_inited = 1;
    return 0;
}
#endif

#ifdef sgi
static uint64_t htonll(uint64_t host_value)
{
    uint64_t result = 0;
    uint8_t *src = (uint8_t *)&host_value;
    uint8_t *dst = (uint8_t *)&result;

    for (int i = 0; i < 8; i++) {
        dst[i] = src[7 - i];
    }

    return result;
}

static uint64_t ntohll(uint64_t net_value)
{
    return htonll(net_value);
}

static char *strcasestr(const char *haystack, const char *needle)
{
    if (!*needle) {
        return (char *)haystack;
    }

    for (; *haystack; haystack++) {
        const char *h = haystack;
        const char *n = needle;

        while (*h && *n && (tolower((unsigned char)*h) == tolower((unsigned char)*n))) {
            h++;
            n++;
        }

        if (!*n) {
            return (char *)haystack;
        }
    }

    return NULL;
}
#endif
