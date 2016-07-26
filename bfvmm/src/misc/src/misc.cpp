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

#include <debug.h>
#include <vcpu/vcpu_manager.h>
#include <serial/serial_port_intel_x64.h>

extern "C" int
write(int file, const void *buffer, size_t count)
{
    static auto been_called_before = false;
    auto str = std::string((char *)buffer, count);

    if (buffer == nullptr || count == 0)
        return 0;

    if (file == 0)
        return 0;

    if (been_called_before == false)
    {
        been_called_before = true;

        bfinfo << std::hex;
        bfdebug << "serial_port_intel_x64: open on 0x"
                << serial_port_intel_x64::instance()->port() << bfendl;
        bfinfo << std::dec;
    }

    if (file == 1 || file == 2)
    {
        g_vcm->write(-1, str);
        serial_port_intel_x64::instance()->write(str);
    }
    else if (file >= bfostream_offset)
    {
        auto vcpuid = ((file - bfostream_offset) >> bfostream_shift);
        g_vcm->write(vcpuid, str);
    }
    else
    {
        auto str = std::to_string(file);
        auto msg = "write: unknown ostream handle: " + str + "\n";
        g_vcm->write(-1, msg.c_str());
        serial_port_intel_x64::instance()->write(msg);

        return 0;
    }

    return count;
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

    if (file == 1 || file == 2)
    {
        auto str = std::string((char *)buffer, count);

        if (dr == nullptr)
            dr = new debug_ring(0);

        dr->write(str);
        serial_port_intel_x64::instance()->write(str);
        return count;
    }

    return 0;
}

#endif

#if defined(NO_HYPER_LIBCXX_TEST)

extern "C" int
write(int file, const void *buffer, size_t count)
{
    (void) file;
    (void) buffer;
    (void) count;

    return 0;
}

#endif

#if defined(NO_HYPER_TEST) || defined(NO_HYPER_LIBCXX_TEST)

#include <string.h>
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
init_vmm(int64_t arg)
{
    (void) arg;

    auto msg = "init_vmm\n";
    write(1, msg, strlen(msg));

    return 0;
}

extern "C" int64_t
start_vmm(int64_t arg)
{
    (void) arg;

    auto msg = "start_vmm\n";
    write(1, msg, strlen(msg));

    return 0;
}

extern "C" int64_t
stop_vmm(int64_t arg)
{
    (void) arg;

    auto msg = "stop_vmm\n";
    write(1, msg, strlen(msg));

    return 0;
}

extern "C" int64_t
add_mdl(memory_descriptor *mdl, int64_t num)
{
    (void) mdl;
    (void) num;

    return 0;
}

#endif

uintptr_t __stack_chk_guard = 0x595e9fbd94fda766;

extern "C" void
__stack_chk_fail(void)
{
    auto msg = "__stack_chk_fail: buffer overflow detected!!!\n";
    write(1, msg, strlen(msg));
    abort();
}

#include <eh_frame_list.h>

auto g_eh_frame_list_num = 0ULL;
eh_frame_t g_eh_frame_list[MAX_NUM_MODULES] = {};

extern "C" struct eh_frame_t *
get_eh_frame_list()
{
    return g_eh_frame_list;
}

extern "C" int64_t
register_eh_frame(void *addr, uint64_t size)
{
    if (addr == nullptr || size == 0)
        return REGISTER_EH_FRAME_FAILURE;

    if (g_eh_frame_list_num >= MAX_NUM_MODULES)
        return REGISTER_EH_FRAME_FAILURE;

    g_eh_frame_list[g_eh_frame_list_num].addr = addr;
    g_eh_frame_list[g_eh_frame_list_num].size = size;
    g_eh_frame_list_num++;

    return REGISTER_EH_FRAME_SUCCESS;
}
