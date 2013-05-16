/*
 * Unit-tests for TLS wrappers
 *
 * Copyright (C) 2013 Red Hat Inc.
 *
 * Authors:
 *  Paolo Bonzini <pbonzini@redhat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <glib.h>
#include <errno.h>
#include <string.h>

#include "qemu-common.h"
#include "qemu/atomic.h"
#include "qemu/thread.h"
#include "qemu/tls.h"

DECLARE_TLS(volatile long long, cnt);
DEFINE_TLS(volatile long long, cnt);

#define NUM_THREADS 10

int stop;

static void *test_thread(void *arg)
{
    volatile long long *p_cnt = tls_alloc_cnt();
    volatile long long **p_ret = arg;
    long long exp = 0;

    g_assert(tls_get_cnt() == p_cnt);
    *p_ret = p_cnt;
    g_assert(*p_cnt == 0);
    while (atomic_mb_read(&stop) == 0) {
        exp++;
        (*p_cnt)++;
        g_assert(*tls_get_cnt() == exp);
    }

    return NULL;
}

static void test_tls(void)
{
    volatile long long *addr[NUM_THREADS];
    QemuThread t[NUM_THREADS];
    int i;

    for (i = 0; i < NUM_THREADS; i++) {
        qemu_thread_create(&t[i], test_thread, &addr[i], QEMU_THREAD_JOINABLE);
    }
    g_usleep(1000000);
    atomic_mb_set(&stop, 1);
    for (i = 0; i < NUM_THREADS; i++) {
        qemu_thread_join(&t[i]);
    }
    for (i = 1; i < NUM_THREADS; i++) {
        g_assert(addr[i] != addr[i - 1]);
    }
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/tls", test_tls);
    return g_test_run();
}
