//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// TIDY_EXCLUSION=-cert-fio38-c,-misc-non-copyable-objects
//
// Reason:
//    This test is a false positive as it is triggering on the implementation
//    of the pthread library, when the test is really meant for users of the
//    pthread library. For an additional reference, please see the following:
//
//    https://github.com/llvm-mirror/clang-tools-extra/blob/master/clang-tidy/
//        misc/NonCopyableObjects.cpp
//
//    Also note that we disable two tests as they are the same test with
//    different names
//

// TIDY_EXCLUSION=-cppcoreguidelines-pro*
//
// Reason:
//     Although written in C++, this code needs to implement C specific logic
//     that by its very definition will not adhere to the core guidelines
//     similar to libc which is needed by all C++ implementations.
//

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

extern "C" int
pthread_cond_broadcast(pthread_cond_t *__cond)
{
    if (__cond == nullptr) {
        return -EINVAL;
    }

    *__cond = PTHREAD_COND_INITIALIZER;
    return 0;
}

extern "C" int
pthread_cond_destroy(pthread_cond_t * /*unused*/)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" int
pthread_cond_init(pthread_cond_t *__cond, const pthread_condattr_t *__attr)
{
    if (__attr != nullptr) {
        ARG_UNSUPPORTED("attr");
    }

    if (__cond == nullptr) {
        return -EINVAL;
    }

    *__cond = PTHREAD_COND_INITIALIZER;
    return 0;
}

extern "C" int
pthread_cond_signal(pthread_cond_t * /*unused*/)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" int
pthread_cond_timedwait(
    pthread_cond_t * /*unused*/,
    pthread_mutex_t * /*unused*/,
    const struct timespec * /*unused*/)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" int
pthread_cond_wait(pthread_cond_t *__cond, pthread_mutex_t *__mutex)
{
    if (__cond == nullptr || __mutex == nullptr) {
        return -EINVAL;
    }

    pthread_mutex_unlock(__mutex);
    while (!__sync_bool_compare_and_swap(__cond, PTHREAD_COND_INITIALIZER, 0)) {
        pthread_mutex_lock(__mutex);
    }

    return 0;
}

extern "C" int
pthread_detach(pthread_t /*unused*/)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" int
pthread_equal(pthread_t /*unused*/, pthread_t /*unused*/)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" void *
pthread_getspecific(pthread_key_t __key)
{
    if (__key > MAX_THREAD_SPECIFIC_DATA) {
        return nullptr;
    }

    return reinterpret_cast<void *>(thread_context_tlsptr()[__key]);
}

extern "C" int
pthread_join(pthread_t /*unused*/, void ** /*unused*/)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" int
pthread_key_create(pthread_key_t *__key, void (*__destructor)(void *))
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
    bfignored(__destructor);

    if (__key == nullptr) {
        return -EINVAL;
    }

    *__key = gsl::narrow_cast<pthread_key_t>(__sync_fetch_and_add(&g_keys, 1));

    return 0;
}

extern "C" int
pthread_key_delete(pthread_key_t /*unused*/)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" int
pthread_mutex_destroy(pthread_mutex_t * /*unused*/)
{
    return 0;
}

extern "C" int
pthread_mutex_init(pthread_mutex_t *__mutex, const pthread_mutexattr_t *__attr)
{
    if (__attr != nullptr) {
        ARG_UNSUPPORTED("attr");
    }

    if (__mutex == nullptr) {
        return -EINVAL;
    }

    *__mutex = PTHREAD_MUTEX_INITIALIZER;
    return 0;
}

extern "C" int
pthread_mutex_lock(pthread_mutex_t *__mutex)
{
    if (__mutex == nullptr) {
        return -EINVAL;
    }

    while (!__sync_bool_compare_and_swap(__mutex, PTHREAD_MUTEX_INITIALIZER, 0))
    { };

    return 0;
}

extern "C" int
pthread_mutex_trylock(pthread_mutex_t * /*unused*/)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" int
pthread_mutex_unlock(pthread_mutex_t *__mutex)
{
    if (__mutex == nullptr) {
        return -EINVAL;
    }

    *__mutex = PTHREAD_MUTEX_INITIALIZER;
    return 0;
}

extern "C" int
pthread_mutexattr_destroy(pthread_mutexattr_t * /*unused*/)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" int
pthread_mutexattr_init(pthread_mutexattr_t * /*unused*/)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" int
pthread_mutexattr_settype(pthread_mutexattr_t * /*unused*/, int /*unused*/)
{
    UNHANDLED();
    return -ENOSYS;
}

extern "C" int
pthread_once(pthread_once_t *__once_control, void (*__init_routine)())
{
    if (__once_control == nullptr ||
        __init_routine == nullptr ||
        __once_control->is_initialized == 0) {
        return -EINVAL;
    }

    if (__sync_bool_compare_and_swap(&__once_control->init_executed, 0, 1)) {
        (*__init_routine)();
    }

    return 0;
}

extern "C" pthread_t
pthread_self(void)
{
    UNHANDLED();
    return 1;
}

extern "C" int
pthread_setspecific(pthread_key_t __key, const void *__value)
{
    if (__key > MAX_THREAD_SPECIFIC_DATA) {
        return -EINVAL;
    }

    thread_context_tlsptr()[__key] = reinterpret_cast<uint64_t>(__value);
    return 0;
}

extern "C" uint64_t *_thread_context_tlsptr(void);
extern "C" uint64_t _thread_context_cpuid(void);

extern "C" uint64_t *
WEAK_SYM thread_context_tlsptr(void)
{ return _thread_context_tlsptr(); }

extern "C" uint64_t
WEAK_SYM thread_context_cpuid(void)
{ return _thread_context_cpuid(); }
