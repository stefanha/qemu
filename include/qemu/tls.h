/*
 * Abstraction layer for defining and using TLS variables
 *
 * Copyright (c) 2011, 2013 Red Hat, Inc
 * Copyright (c) 2011 Linaro Limited
 *
 * Authors:
 *  Paolo Bonzini <pbonzini@redhat.com>
 *  Peter Maydell <peter.maydell@linaro.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef QEMU_TLS_H
#define QEMU_TLS_H

#if defined __linux__
#define DECLARE_TLS(type, x)                     \
extern __thread typeof(type) x;                  \
                                                 \
static inline typeof(type) *tls_get_##x(void)    \
{                                                \
    return &x;                                   \
}                                                \
                                                 \
static inline typeof(type) *tls_alloc_##x(void)  \
{                                                \
    return &x;                                   \
}                                                \
                                                 \
extern int dummy_##__LINE__

#define DEFINE_TLS(type, x)                  \
__thread typeof(type) x

#elif defined CONFIG_POSIX
typedef struct QEMUTLSValue {
    pthread_key_t k;
    pthread_once_t o;
} QEMUTLSValue;

#define DECLARE_TLS(type, x)                     \
extern QEMUTLSValue x;                           \
extern void init_##x(void);                      \
                                                 \
static inline typeof(type) *tls_get_##x(void)    \
{                                                \
    return pthread_getspecific(x.k);             \
}                                                \
                                                 \
static inline typeof(type) *tls_alloc_##x(void)  \
{                                                \
    void *datum = g_malloc0(sizeof(type));       \
    pthread_once(&x.o, init_##x);                \
    pthread_setspecific(x.k, datum);             \
    return datum;                                \
}                                                \
                                                 \
extern int dummy_##__LINE__

#define DEFINE_TLS(type, x)                  \
void init_##x(void) {                        \
    pthread_key_create(&x.k, g_free);        \
}                                            \
                                             \
QEMUTLSValue x = { .o = PTHREAD_ONCE_INIT }

#elif defined CONFIG_WIN32

/* The initial contents of TLS variables are placed in the .tls section.
 * The linker takes all section starting with ".tls$", sorts them and puts
 * the contents in a single ".tls" section.  qemu-thread-win32.c defines
 * special symbols in .tls$000 and .tls$ZZZ that represent the beginning
 * and end of TLS memory.  The linker and run-time library then cooperate
 * to copy memory between those symbols in the TLS area of new threads.
 *
 * _tls_index holds the number of our module.  The executable should be
 * zero, DLLs are numbered 1 and up.  The loader fills it in for us.
 *
 * Thus, Teb->ThreadLocalStoragePointer[_tls_index] is the base of
 * the TLS segment for this (thread, module) pair.  Each segment has
 * the same layout as this module's .tls segment and is initialized
 * with the content of the .tls segment; 0 is the _tls_start variable.
 * So, tls_get_##x passes us the offset of the passed variable relative to
 * _tls_start, and we return that same offset plus the base of segment.
 */

typedef struct _TEB {
    NT_TIB NtTib;
    void *EnvironmentPointer;
    void *x[3];
    char **ThreadLocalStoragePointer;
} TEB, *PTEB;

extern int _tls_index;
extern int _tls_start;

static inline void *tls_var(size_t offset)
{
    PTEB Teb = NtCurrentTeb();
    return (char *)(Teb->ThreadLocalStoragePointer[_tls_index]) + offset;
}

#define DECLARE_TLS(type, x)                                         \
extern typeof(type) tls_##x __attribute__((section(".tls$QEMU")));   \
                                                                     \
static inline typeof(type) *tls_get_##x(void)                        \
{                                                                    \
    return tls_var((ULONG_PTR)&(tls_##x) - (ULONG_PTR)&_tls_start);  \
}                                                                    \
                                                                     \
static inline typeof(type) *tls_alloc_##x(void)                      \
{                                                                    \
    typeof(type) *addr = tls_get_##x();                              \
    memset((void *)addr, 0, sizeof(type));                           \
    return addr;                                                     \
}                                                                    \
                                                                     \
extern int dummy_##__LINE__

#define DEFINE_TLS(type, x)                                          \
typeof(type) tls_##x __attribute__((section(".tls$QEMU")))

#else
#error No TLS abstraction available on this platform
#endif

#endif
