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

// TIDY_EXCLUSION=-readability-non-const-parameter
//
// Reason:
//     This file implements C specific functions with defintions that we do
//     not have control over. As a result, this test triggers a false
//     positive
//

// TIDY_EXCLUSION=-cppcoreguidelines-pro*
//
// Reason:
//     Although written in C++, this code needs to implement C specific logic
//     that by its very definition will not adhere to the core guidelines
//     similar to libc which is needed by all C++ implementations.
//

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdlib>

#include <regex.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/times.h>

#include <bfgsl.h>
#include <bfdebug.h>
#include <bfexports.h>
#include <bfconstants.h>
#include <bfehframelist.h>
#include <bfdwarf.h>

extern "C" clock_t
times(struct tms *buf)
{
    bfignored(buf);

    UNHANDLED();

    return 0;
}

extern "C" int
execve(const char *__path, char *const __argv[], char *const __envp[])
{
    bfignored(__path);
    bfignored(__argv);
    bfignored(__envp);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" pid_t
getpid(void)
{
    return 1;
}

extern "C" int
isatty(int __fildes)
{
    bfignored(__fildes);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" off_t
lseek(int __fildes, off_t __offset, int __whence)
{
    bfignored(__fildes);
    bfignored(__offset);
    bfignored(__whence);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" void
_init(void)
{ }

extern "C" int
kill(pid_t _pid, int _sig)
{
    bfignored(_pid);
    bfignored(_sig);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" pid_t
wait(int *status)
{
    bfignored(status);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" _READ_WRITE_RETURN_TYPE
read(int __fd, void *__buf, size_t __nbyte)
{
    bfignored(__fd);
    bfignored(__buf);
    bfignored(__nbyte);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
unlink(const char *__path)
{
    bfignored(__path);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" pid_t
fork(void)
{
    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" void *
sbrk(ptrdiff_t __incr)
{
    bfignored(__incr);

    UNHANDLED();

    errno = -ENOSYS;
    return reinterpret_cast<void *>(-1);
}

extern "C" int
regcomp(regex_t *preg, const char *regex, int cflags)
{
    bfignored(preg);
    bfignored(regex);
    bfignored(cflags);

    UNHANDLED();

    return REG_NOMATCH;
}

extern "C" int
gettimeofday(struct timeval *__p, void *__tz)
{
    bfignored(__p);
    bfignored(__tz);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
clock_gettime(clockid_t clock_id, struct timespec *tp) __THROW
{
    bfignored(clock_id);
    bfignored(tp);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
regexec(const regex_t *preg, const char *string,
        size_t nmatch, regmatch_t pmatch[], int eflags)
{
    bfignored(preg);
    bfignored(string);
    bfignored(nmatch);
    bfignored(pmatch);
    bfignored(eflags);

    UNHANDLED();

    return REG_NOMATCH;
}

extern "C" void
_fini(void)
{ }

extern "C" int
stat(const char *__path, struct stat *__sbuf)
{
    bfignored(__path);
    bfignored(__sbuf);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
link(const char *__path1, const char *__path2)
{
    bfignored(__path1);
    bfignored(__path2);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" void
_exit(int __status)
{
    bfignored(__status);

    while (true)
    { }
}

extern "C" int
open(const char *file, int mode, ...)
{
    bfignored(file);
    bfignored(mode);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" void
regfree(regex_t *preg)
{
    UNHANDLED();

    bfignored(preg);
}

extern "C" int
fcntl(int fd, int cmd, ...)
{
    bfignored(fd);
    bfignored(cmd);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
mkdir(const char *_path, mode_t __mode)
{
    bfignored(_path);
    bfignored(__mode);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
posix_memalign(void **memptr, size_t alignment, size_t size)
{
    bfignored(alignment);

    // TODO:
    //
    // At some point, we need to implement the alignment part of
    // this function, but it is being used by C++17 so the implementation
    // below works for now.
    //

    if ((*memptr = _malloc_r(nullptr, size)) != nullptr) {
        return 0;
    }

    return -ENOMEM;
}

extern "C" int
close(int __fildes)
{
    bfignored(__fildes);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
sigprocmask(int how, const sigset_t *set, sigset_t *oset)
{
    bfignored(how);
    bfignored(set);
    bfignored(oset);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" long
sysconf(int __name)
{
    bfignored(__name);

    UNHANDLED();

    errno = -EINVAL;
    return -1;
}

extern "C" int
nanosleep(const struct timespec *rqtp, struct timespec *rmtp)
{
    bfignored(rqtp);
    bfignored(rmtp);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
fstat(int __fd, struct stat *__sbuf)
{
    bfignored(__fd);
    bfignored(__sbuf);

    errno = -ENOSYS;
    return -1;
}

extern "C" int
getentropy(void *buf, size_t buflen)
{
    bfignored(buf);
    bfignored(buflen);

    errno = -EIO;
    return -1;
}

extern "C" double
ldexp(double x, int exp)
{ return __builtin_ldexp(x, exp); }

extern "C" int
sched_yield(void)
{ return 0; }

extern "C" float
__mulsc3(float a, float b, float c, float d)
{
    bfignored(a);
    bfignored(b);
    bfignored(c);
    bfignored(d);

    UNHANDLED();

    return 0;
}

extern "C" double
__muldc3(double a, double b, double c, double d)
{
    bfignored(a);
    bfignored(b);
    bfignored(c);
    bfignored(d);

    UNHANDLED();

    return 0;
}

extern "C" long double
__mulxc3(long double a, long double b, long double c, long double d)
{
    bfignored(a);
    bfignored(b);
    bfignored(c);
    bfignored(d);

    UNHANDLED();

    return 0;
}

int __g_eh_frame_list_num = 0;
eh_frame_t __g_eh_frame_list[MAX_NUM_MODULES] = {};
int __g_dwarf_sections_num = 0;
dwarf_sections_t __g_dwarf_sections[MAX_NUM_MODULES] = {};

extern "C" struct eh_frame_t *
get_eh_frame_list() noexcept
{ return __g_eh_frame_list; }

extern "C" struct dwarf_sections_t *
get_dwarf_sections() noexcept
{ return __g_dwarf_sections; }

extern "C" void *
malloc(size_t __size)
{ return _malloc_r(nullptr, __size); }

extern "C" void
free(void *__ptr)
{ _free_r(nullptr, __ptr); }

extern "C" void *
calloc(size_t __nmemb, size_t __size)
{ return _calloc_r(nullptr, __nmemb, __size); }

extern "C" void *
realloc(void *__r, size_t __size)
{ return _realloc_r(nullptr, __r, __size); }

extern "C" void *
WEAK_SYM _malloc_r(struct _reent * /*unused*/, size_t /*unused*/)
{ return nullptr; }

extern "C" void
WEAK_SYM _free_r(struct _reent * /*unused*/, void * /*unused*/)
{ }

extern "C" void *
WEAK_SYM _calloc_r(struct _reent * /*unused*/, size_t /*unused*/, size_t /*unused*/)
{ return nullptr; }

extern "C" void *
WEAK_SYM _realloc_r(struct _reent * /*unused*/, void * /*unused*/, size_t /*unused*/)
{ return nullptr; }

extern "C" int
WEAK_SYM write(int /*unused*/, const void * /*unused*/, size_t /*unused*/)
{ return 0; }
