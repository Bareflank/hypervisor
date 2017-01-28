//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#include <stddef.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/times.h>
#include <regex.h>

#define UNHANDLED() \
    { \
        const char *str_text = "\033[1;33mWARNING\033[0m: unsupported libc function called = "; \
        const char *str_func = __PRETTY_FUNCTION__; \
        const char *str_endl = "\n"; \
        write(0, str_text, strlen(str_text)); \
        write(0, str_func, strlen(str_func)); \
        write(0, str_endl, strlen(str_endl)); \
    }

extern "C" clock_t
times(struct tms *buf)
{
    (void) buf;

    UNHANDLED();

    return 0;
}

extern "C" int
execve(const char *path, char *const argv[], char *const envp[])
{
    (void) path;
    (void) argv;
    (void) envp;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" pid_t
getpid(void)
{
    UNHANDLED();

    return 0;
}

extern "C" int
isatty(int fd)
{
    (void) fd;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" off_t
lseek(int fd, off_t offset, int whence)
{
    (void) fd;
    (void) offset;
    (void) whence;

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
    (void) _pid;
    (void) _sig;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" pid_t
wait(int *status)
{
    (void) status;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" _READ_WRITE_RETURN_TYPE
read(int fd, void *buffer, size_t length)
{
    (void) fd;
    (void) buffer;
    (void) length;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
unlink(const char *file)
{
    (void) file;

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
    (void) __incr;

    UNHANDLED();

    errno = -ENOSYS;
    return reinterpret_cast<void *>(-1);
}

extern "C" int
regcomp(regex_t *preg, const char *regex, int cflags)
{
    (void) preg;
    (void) regex;
    (void) cflags;

    UNHANDLED();

    return REG_NOMATCH;
}

extern "C" int
gettimeofday(struct timeval *tp, void *tzp)
{
    (void) tp;
    (void) tzp;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
clock_gettime(clockid_t clk_id, struct timespec *tp) __THROW
{
    (void) clk_id;
    (void) tp;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
regexec(const regex_t *preg, const char *string,
        size_t nmatch, regmatch_t pmatch[], int eflags)
{
    (void) preg;
    (void) string;
    (void) nmatch;
    (void) pmatch;
    (void) eflags;

    UNHANDLED();

    return REG_NOMATCH;
}

extern "C" void
_fini(void)
{ }

extern "C" int
stat(const char *pathname, struct stat *buf)
{
    (void) pathname;
    (void) buf;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
link(const char *oldpath, const char *newpath)
{
    (void) oldpath;
    (void) newpath;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" void
_exit(int status)
{
    (void) status;

    UNHANDLED();

    while (1);
}

extern "C" int
open(const char *file, int mode, ...)
{
    (void) file;
    (void) mode;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" void
regfree(regex_t *preg)
{
    UNHANDLED();

    (void) preg;
}

extern "C" int
fcntl(int fd, int cmd, ...)
{
    (void) fd;
    (void) cmd;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
mkdir(const char *path, mode_t mode)
{
    (void) path;
    (void) mode;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
posix_memalign(void **memptr, size_t alignment, size_t size)
{
    (void) memptr;
    (void) alignment;
    (void) size;

    UNHANDLED();

    return 0;
}

extern "C" int
close(int fd)
{
    (void) fd;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" int
sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
    (void) how;
    (void) set;
    (void) oldset;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" long
sysconf(int name)
{
    (void) name;

    UNHANDLED();

    errno = -EINVAL;
    return -1;
}

extern "C" int
nanosleep(const struct timespec *req, struct timespec *rem)
{
    (void) req;
    (void) rem;

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" void *
malloc(size_t size)
{
    return _malloc_r(0, size);
}

extern "C" void
free(void *ptr)
{
    _free_r(0, ptr);
}

extern "C" void *
calloc(size_t nmemb, size_t size)
{
    return _calloc_r(0, nmemb, size);
}

extern "C" void *
realloc(void *ptr, size_t size)
{
    return _realloc_r(0, ptr, size);
}

extern "C" int
fstat(int file, struct stat *sbuf)
{
    (void) file;
    (void) sbuf;

    errno = -ENOSYS;
    return -1;
}

extern "C" int
getentropy(void *buf, size_t buflen)
{
    (void) buf;
    (void) buflen;

    errno = -EIO;
    return -1;
}

extern "C" int
__fpclassifyf(float val)
{
    (void) val;
    return 0;  // FP_NAN
}

extern "C" int
__fpclassifyd(double val)
{
    (void) val;
    return 0;  // FP_NAN
}

extern "C" double
ldexp(double x, int exp)
{
    return __builtin_ldexp(x, exp);
}

extern "C" float
nanf(const char *tagp)
{
    return __builtin_nanf(tagp);
}

extern "C" int
sched_yield(void)
{
    return 0;
}
