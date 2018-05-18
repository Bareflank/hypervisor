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

extern "C" EXPORT_SYM clock_t
times(struct tms *buf)
{
    bfignored(buf);

    UNHANDLED();

    return 0;
}

extern "C" EXPORT_SYM int
execve(const char *__path, char *const __argv[], char *const __envp[])
{
    bfignored(__path);
    bfignored(__argv);
    bfignored(__envp);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM pid_t
getpid(void)
{
    return 1;
}

extern "C" EXPORT_SYM int
isatty(int __fildes)
{
    bfignored(__fildes);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM off_t
lseek(int __fildes, off_t __offset, int __whence)
{
    bfignored(__fildes);
    bfignored(__offset);
    bfignored(__whence);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM void
_init(void)
{ }

extern "C" EXPORT_SYM int
kill(pid_t _pid, int _sig)
{
    bfignored(_pid);
    bfignored(_sig);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM pid_t
wait(int *status)
{
    bfignored(status);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM _READ_WRITE_RETURN_TYPE
read(int __fd, void *__buf, size_t __nbyte)
{
    bfignored(__fd);
    bfignored(__buf);
    bfignored(__nbyte);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM int
unlink(const char *__path)
{
    bfignored(__path);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM pid_t
fork(void)
{
    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM void *
sbrk(ptrdiff_t __incr)
{
    bfignored(__incr);

    UNHANDLED();

    errno = -ENOSYS;
    return reinterpret_cast<void *>(-1);
}

extern "C" EXPORT_SYM int
regcomp(regex_t *preg, const char *regex, int cflags)
{
    bfignored(preg);
    bfignored(regex);
    bfignored(cflags);

    UNHANDLED();

    return REG_NOMATCH;
}

extern "C" EXPORT_SYM int
gettimeofday(struct timeval *__p, void *__tz)
{
    bfignored(__p);
    bfignored(__tz);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM int
clock_gettime(clockid_t clock_id, struct timespec *tp) __THROW
{
    bfignored(clock_id);
    bfignored(tp);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM int
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

extern "C" EXPORT_SYM void
_fini(void)
{ }

extern "C" EXPORT_SYM int
stat(const char *__path, struct stat *__sbuf)
{
    bfignored(__path);
    bfignored(__sbuf);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM int
link(const char *__path1, const char *__path2)
{
    bfignored(__path1);
    bfignored(__path2);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM void
_exit(int __status)
{
    bfignored(__status);

    while (true)
    { }
}

extern "C" EXPORT_SYM int
open(const char *file, int mode, ...)
{
    bfignored(file);
    bfignored(mode);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM void
regfree(regex_t *preg)
{
    UNHANDLED();

    bfignored(preg);
}

extern "C" EXPORT_SYM int
fcntl(int fd, int cmd, ...)
{
    bfignored(fd);
    bfignored(cmd);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM int
mkdir(const char *_path, mode_t __mode)
{
    bfignored(_path);
    bfignored(__mode);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM int
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

extern "C" EXPORT_SYM int
close(int __fildes)
{
    bfignored(__fildes);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM int
sigprocmask(int how, const sigset_t *set, sigset_t *oset)
{
    bfignored(how);
    bfignored(set);
    bfignored(oset);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM long
sysconf(int __name)
{
    bfignored(__name);

    UNHANDLED();

    errno = -EINVAL;
    return -1;
}

extern "C" EXPORT_SYM int
nanosleep(const struct timespec *rqtp, struct timespec *rmtp)
{
    bfignored(rqtp);
    bfignored(rmtp);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM int
fstat(int __fd, struct stat *__sbuf)
{
    bfignored(__fd);
    bfignored(__sbuf);

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM int
getentropy(void *buf, size_t buflen)
{
    bfignored(buf);
    bfignored(buflen);

    errno = -EIO;
    return -1;
}

extern "C" EXPORT_SYM double
ldexp(double x, int exp)
{ return __builtin_ldexp(x, exp); }

extern "C" EXPORT_SYM int
sched_yield(void)
{ return 0; }

extern "C" EXPORT_SYM float
__mulsc3(float a, float b, float c, float d)
{
    bfignored(a);
    bfignored(b);
    bfignored(c);
    bfignored(d);

    UNHANDLED();

    return 0;
}

extern "C" EXPORT_SYM double
__muldc3(double a, double b, double c, double d)
{
    bfignored(a);
    bfignored(b);
    bfignored(c);
    bfignored(d);

    UNHANDLED();

    return 0;
}

extern "C" EXPORT_SYM long double
__mulxc3(long double a, long double b, long double c, long double d)
{
    bfignored(a);
    bfignored(b);
    bfignored(c);
    bfignored(d);

    UNHANDLED();

    return 0;
}

EXPORT_SYM int __g_eh_frame_list_num = 0;
EXPORT_SYM eh_frame_t __g_eh_frame_list[MAX_NUM_MODULES] = {};
EXPORT_SYM int __g_dwarf_sections_num = 0;
EXPORT_SYM dwarf_sections_t __g_dwarf_sections[MAX_NUM_MODULES] = {};

extern "C" EXPORT_SYM struct eh_frame_t *
get_eh_frame_list() noexcept
{ return __g_eh_frame_list; }

extern "C" EXPORT_SYM struct dwarf_sections_t *
get_dwarf_sections() noexcept
{ return __g_dwarf_sections; }

extern "C" EXPORT_SYM void *
malloc(size_t __size)
{ return _malloc_r(nullptr, __size); }

extern "C" EXPORT_SYM void
free(void *__ptr)
{ _free_r(nullptr, __ptr); }

extern "C" EXPORT_SYM void *
calloc(size_t __nmemb, size_t __size)
{ return _calloc_r(nullptr, __nmemb, __size); }

extern "C" EXPORT_SYM void *
realloc(void *__r, size_t __size)
{ return _realloc_r(nullptr, __r, __size); }

extern "C" EXPORT_SYM void *
WEAK_SYM _malloc_r(struct _reent * /*unused*/, size_t /*unused*/)
{ return nullptr; }

extern "C" EXPORT_SYM void
WEAK_SYM _free_r(struct _reent * /*unused*/, void * /*unused*/)
{ }

extern "C" EXPORT_SYM void *
WEAK_SYM _calloc_r(struct _reent * /*unused*/, size_t /*unused*/, size_t /*unused*/)
{ return nullptr; }

extern "C" EXPORT_SYM void *
WEAK_SYM _realloc_r(struct _reent * /*unused*/, void * /*unused*/, size_t /*unused*/)
{ return nullptr; }

extern "C" EXPORT_SYM int
WEAK_SYM write(int /*unused*/, const void * /*unused*/, size_t /*unused*/)
{ return 0; }
