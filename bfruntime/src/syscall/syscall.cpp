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
#include <bfexports.h>
#include <bfconstants.h>
#include <bfehframelist.h>
#include <bfdwarf.h>

#define UNHANDLED() \
    { \
        const char *str_text = "\033[1;33mWARNING\033[0m: unsupported libc function called = "; \
        const char *str_func = __PRETTY_FUNCTION__; \
        const char *str_endl = "\n"; \
        write(1, str_text, strlen(str_text)); \
        write(1, str_func, strlen(str_func)); \
        write(1, str_endl, strlen(str_endl)); \
    }

extern "C" EXPORT_SYM clock_t
times(struct tms *buf)
{
    bfignored(buf);

    UNHANDLED();

    return 0;
}

extern "C" EXPORT_SYM int
execve(const char *path, char *const argv[], char *const envp[])
{
    bfignored(path);
    bfignored(argv);
    bfignored(envp);

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
isatty(int fd)
{
    bfignored(fd);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM off_t
lseek(int fd, off_t offset, int whence)
{
    bfignored(fd);
    bfignored(offset);
    bfignored(whence);

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
read(int fd, void *buffer, size_t length)
{
    bfignored(fd);
    bfignored(buffer);
    bfignored(length);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM int
unlink(const char *file)
{
    bfignored(file);

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
gettimeofday(struct timeval *tp, void *tzp)
{
    bfignored(tp);
    bfignored(tzp);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM int
clock_gettime(clockid_t clk_id, struct timespec *tp) __THROW
{
    bfignored(clk_id);
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
stat(const char *pathname, struct stat *buf)
{
    bfignored(pathname);
    bfignored(buf);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM int
link(const char *oldpath, const char *newpath)
{
    bfignored(oldpath);
    bfignored(newpath);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM void
_exit(int status)
{
    bfignored(status);

    while (1)
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
mkdir(const char *path, mode_t mode)
{
    bfignored(path);
    bfignored(mode);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM int
posix_memalign(void **memptr, size_t alignment, size_t size)
{
    bfignored(memptr);
    bfignored(alignment);
    bfignored(size);

    UNHANDLED();

    return 0;
}

extern "C" EXPORT_SYM int
close(int fd)
{
    bfignored(fd);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM int
sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
    bfignored(how);
    bfignored(set);
    bfignored(oldset);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM long
sysconf(int name)
{
    bfignored(name);

    UNHANDLED();

    errno = -EINVAL;
    return -1;
}

extern "C" EXPORT_SYM int
nanosleep(const struct timespec *req, struct timespec *rem)
{
    bfignored(req);
    bfignored(rem);

    UNHANDLED();

    errno = -ENOSYS;
    return -1;
}

extern "C" EXPORT_SYM int
fstat(int file, struct stat *sbuf)
{
    bfignored(file);
    bfignored(sbuf);

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

EXPORT_SYM uintptr_t __stack_chk_guard = 0x595e9fbd94fda766;

extern "C" EXPORT_SYM void
__stack_chk_fail(void) noexcept
{
    auto msg = "__stack_chk_fail: buffer overflow detected!!!\n";
    write(1, msg, strlen(msg));
    abort();
}

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
malloc(size_t size)
{ return _malloc_r(0, size); }

extern "C" EXPORT_SYM void
free(void *ptr)
{ _free_r(0, ptr); }

extern "C" EXPORT_SYM void *
calloc(size_t nmemb, size_t size)
{ return _calloc_r(0, nmemb, size); }

extern "C" EXPORT_SYM void *
realloc(void *ptr, size_t size)
{ return _realloc_r(0, ptr, size); }

extern "C" EXPORT_SYM void *
WEAK_SYM _malloc_r(struct _reent *, size_t)
{ return nullptr; }

extern "C" EXPORT_SYM void
WEAK_SYM _free_r(struct _reent *, void *)
{ }

extern "C" EXPORT_SYM void *
WEAK_SYM _calloc_r(struct _reent *, size_t, size_t)
{ return nullptr; }

extern "C" EXPORT_SYM void *
WEAK_SYM _realloc_r(struct _reent *, void *, size_t)
{ return nullptr; }

extern "C" EXPORT_SYM int
WEAK_SYM write(int, const void *, size_t)
{ return 0; }
