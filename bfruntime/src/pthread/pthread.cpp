//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <cerrno>
#include <cstring>
#include <cstdint>

#include <unistd.h>
#include <pthread.h>

#include <bfgsl.h>
#include <bfdebug.h>
#include <bfexports.h>
#include <bfthreadcontext.h>

#define MAX_THREAD_SPECIFIC_DATA 512

extern "C" EXPORT_SYM int
pthread_cond_broadcast(pthread_cond_t *cond)
{
    if (cond == nullptr) {
        return -EINVAL;
    }

    *cond = PTHREAD_COND_INITIALIZER;
    return 0;
}

extern "C" EXPORT_SYM int
pthread_cond_destroy(pthread_cond_t *)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" EXPORT_SYM int
pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr)
{
    if (attr != nullptr) {
        ARG_UNSUPPORTED("attr");
    }

    if (cond == nullptr) {
        return -EINVAL;
    }

    *cond = PTHREAD_COND_INITIALIZER;
    return 0;
}

extern "C" EXPORT_SYM int
pthread_cond_signal(pthread_cond_t *)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" EXPORT_SYM int
pthread_cond_timedwait(pthread_cond_t *, pthread_mutex_t *, const struct timespec *)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" EXPORT_SYM int
pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
    if (cond == nullptr || mutex == nullptr) {
        return -EINVAL;
    }

    pthread_mutex_unlock(mutex);
    while (!__sync_bool_compare_and_swap(cond, PTHREAD_COND_INITIALIZER, 0)) {
        pthread_mutex_lock(mutex);
    }

    return 0;
}

extern "C" EXPORT_SYM int
pthread_detach(pthread_t)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" EXPORT_SYM int
pthread_equal(pthread_t, pthread_t)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" EXPORT_SYM void *
pthread_getspecific(pthread_key_t key)
{
    if (key > MAX_THREAD_SPECIFIC_DATA) {
        return nullptr;
    }

    return thread_context_tlsptr()[key];
}

extern "C" EXPORT_SYM int
pthread_join(pthread_t, void **)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" EXPORT_SYM int
pthread_key_create(pthread_key_t *key, void (*destructor)(void *))
{
    static int64_t g_keys = 0;

    // TODO:
    //
    // Libcxx is providing a destructor now (as of 6.0), so we should
    // implement this feature. For now, ignoring this works, but it might
    // lead to a buggy teardown in the future.
    //

    // if (destructor != nullptr) {
    //     ARG_UNSUPPORTED("destructor");
    // }
    bfignored(destructor);

    if (key == nullptr) {
        return -EINVAL;
    }

    *key = gsl::narrow_cast<pthread_key_t>(__sync_fetch_and_add(&g_keys, 1));

    return 0;
}

extern "C" EXPORT_SYM int
pthread_key_delete(pthread_key_t)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" EXPORT_SYM int
pthread_mutex_destroy(pthread_mutex_t *)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" EXPORT_SYM int
pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr)
{
    if (attr != nullptr) {
        ARG_UNSUPPORTED("attr");
    }

    if (mutex == nullptr) {
        return -EINVAL;
    }

    *mutex = PTHREAD_MUTEX_INITIALIZER;
    return 0;
}

extern "C" EXPORT_SYM int
pthread_mutex_lock(pthread_mutex_t *mutex)
{
    if (mutex == nullptr) {
        return -EINVAL;
    }

    while (!__sync_bool_compare_and_swap(mutex, PTHREAD_MUTEX_INITIALIZER, 0))
    { };

    return 0;
}

extern "C" EXPORT_SYM int
pthread_mutex_trylock(pthread_mutex_t *)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" EXPORT_SYM int
pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    if (mutex == nullptr) {
        return -EINVAL;
    }

    *mutex = PTHREAD_MUTEX_INITIALIZER;
    return 0;
}

extern "C" EXPORT_SYM int
pthread_mutexattr_destroy(pthread_mutexattr_t *)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" EXPORT_SYM int
pthread_mutexattr_init(pthread_mutexattr_t *)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" EXPORT_SYM int
pthread_mutexattr_settype(pthread_mutexattr_t *, int)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" EXPORT_SYM int
pthread_once(pthread_once_t *once, void (*init)(void))
{
    if (once == nullptr || init == nullptr || once->is_initialized == 0) {
        return -EINVAL;
    }

    if (__sync_bool_compare_and_swap(&once->init_executed, 0, 1)) {
        (*init)();
    }

    return 0;
}

extern "C" EXPORT_SYM pthread_t
pthread_self(void)
{
    UNHANDLED();
    return 1;
}

extern "C" EXPORT_SYM int
pthread_setspecific(pthread_key_t key, const void *data)
{
    if (key > MAX_THREAD_SPECIFIC_DATA) {
        return -EINVAL;
    }

    thread_context_tlsptr()[key] = const_cast<void *>(data);
    return 0;
}

extern "C" void **_thread_context_tlsptr(void);
extern "C" uint64_t _thread_context_cpuid(void);

extern "C" EXPORT_SYM void **
WEAK_SYM thread_context_tlsptr(void)
{ return _thread_context_tlsptr(); }

extern "C" EXPORT_SYM uint64_t
WEAK_SYM thread_context_cpuid(void)
{ return _thread_context_cpuid(); }
