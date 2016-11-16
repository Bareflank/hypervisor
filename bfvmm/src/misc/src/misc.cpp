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

#if !defined(NO_HYPER_TEST) && !defined(NO_HYPER_LIBCXX_TEST)

#include <vcpu/vcpu_manager.h>
#include <serial/serial_port_intel_x64.h>

extern "C" int
write(int file, const void *buffer, size_t count)
{
    if (buffer == nullptr || count == 0)
        return 0;

    if (file != 1 && file != 2)
        return 0;

    try
    {
        std::string str(static_cast<const char *>(buffer), count);
        if (str.length() >= 26 && str.compare(0, 8, "$vcpuid=") == 0)
        {
            str.erase(0, 8);

            auto vcpuid_str = str.substr(0, 18);
            auto vcpuid_num = std::stoull(vcpuid_str, 0, 16);

            str.erase(0, 18);

            g_vcm->write(vcpuid_num, str);
            return static_cast<int>(count);
        }
        else
        {
            g_vcm->write(0, str);
            serial_port_intel_x64::instance()->write(str);
            return static_cast<int>(count);
        }
    }
    catch (...) { }

    return 0;
}

extern "C" int
fstat(int file, struct stat *sbuf)
{
    (void) file;
    (void) sbuf;

    errno = -ENOSYS;
    return -1;
}

#endif

#if defined(NO_HYPER_TEST)

#include <debug_ring/debug_ring.h>
#include <serial/serial_port_intel_x64.h>

debug_ring *dr = nullptr;

extern "C" int
write(int file, const void *buffer, size_t count)
{
    if (buffer == nullptr || count == 0)
        return 0;

    try
    {
        if (file == 1 || file == 2)
        {
            auto str = std::string(static_cast<const char *>(buffer), count);

            if (dr == nullptr)
                dr = new debug_ring(0);

            dr->write(str);
            serial_port_intel_x64::instance()->write(str);
            return static_cast<int>(count);
        }
    }
    catch (...) { }

    return 0;
}

#endif

#if defined(NO_HYPER_LIBCXX_TEST)

#include <stddef.h>

extern "C" int
write(int file, const void *buffer, size_t count)
{
    (void) file;
    (void) buffer;
    (void) count;

    return 0;
}

extern "C" void
abort(void)
{
    while (true);
}

extern "C" void
__cxa_end_catch(void)
{  }

extern "C" void
__cxa_begin_catch(void)
{  }

extern "C" void
__gxx_personality_v0(void)
{  }

namespace std
{
void terminate()
{ }
}

extern "C" void *
memset(void *s, int c, size_t n)
{
    (void) s;
    (void) c;
    (void) n;

    return nullptr;
}

extern "C" size_t
strlen(const char *str)
{
    (void) str;

    return 0;
}

#endif

#if defined(NO_HYPER_TEST) || defined(NO_HYPER_LIBCXX_TEST)

#include <string.h>
#include <stddef.h>
#include <memory.h>
#include <constants.h>
#include <eh_frame_list.h>

extern "C" int
fstat(int file, struct stat *sbuf)
{
    (void) file;
    (void) sbuf;

    return -1;
}

extern "C" int64_t
start_vmm(uint64_t arg) noexcept
{
    (void) arg;

    auto msg = "start_vmm\n";
    write(1, msg, strlen(msg));

    return 0;
}

extern "C" int64_t
stop_vmm(uint64_t arg) noexcept
{
    (void) arg;

    auto msg = "stop_vmm\n";
    write(1, msg, strlen(msg));

    return 0;
}

extern "C" int64_t
add_md(memory_descriptor *md) noexcept
{
    (void) md;

    return 0;
}

#endif

uintptr_t __stack_chk_guard = 0x595e9fbd94fda766;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"

extern "C" void
__stack_chk_fail(void) noexcept
{
    auto msg = "__stack_chk_fail: buffer overflow detected!!!\n";
    write(1, msg, strlen(msg));
    abort();
}

#pragma GCC diagnostic pop

#include <eh_frame_list.h>

auto g_eh_frame_list_num = 0ULL;
eh_frame_t g_eh_frame_list[MAX_NUM_MODULES] = {};

extern "C" struct eh_frame_t *
get_eh_frame_list() noexcept
{
    return g_eh_frame_list;
}

extern "C" int64_t
register_eh_frame(void *addr, uint64_t size) noexcept
{
    if (addr == nullptr || size == 0)
        return REGISTER_EH_FRAME_SUCCESS;

    if (g_eh_frame_list_num >= MAX_NUM_MODULES)
        return REGISTER_EH_FRAME_FAILURE;

    g_eh_frame_list[g_eh_frame_list_num].addr = addr;
    g_eh_frame_list[g_eh_frame_list_num].size = size;
    g_eh_frame_list_num++;

    return REGISTER_EH_FRAME_SUCCESS;
}

extern "C" int
___xpg_strerror_r(int errnum, char *buf, size_t buflen)
{
    (void) errnum;

    __builtin_memset(buf, 0, buflen);
    return 0;
}
