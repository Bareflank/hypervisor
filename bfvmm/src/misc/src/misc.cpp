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

    if (file == 1 || file == 2)
    {
        auto str = std::string((char *)buffer, count);

        g_vcm->write(-1, str);
        serial_port_intel_x64::instance()->write(str);

        return count;
    }

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

#if defined(NO_HYPER_TEST) || defined(NO_HYPER_LIBCXX_TEST)

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

    return 0;
}

extern "C" int64_t
start_vmm(int64_t arg)
{
    (void) arg;

    return 0;
}

extern "C" int64_t
stop_vmm(int64_t arg)
{
    (void) arg;

    return 0;
}

extern "C" int64_t
add_mdl(memory_descriptor *mdl, int64_t num)
{
    (void) mdl;
    (void) num;

    return 0;
}

auto g_eh_frame_list_num = 0ULL;
eh_frame_t g_eh_frame_list[MAX_NUM_MODULES] = {};

extern "C" struct eh_frame_t *
get_eh_frame_list()
{
    return g_eh_frame_list;
}

extern "C" void
register_eh_frame(void *addr, uint64_t size)
{
    if (addr == nullptr || size == 0)
        return;

    if (g_eh_frame_list_num >= MAX_NUM_MODULES)
        return;

    g_eh_frame_list[g_eh_frame_list_num].addr = addr;
    g_eh_frame_list[g_eh_frame_list_num].size = size;
    g_eh_frame_list_num++;
}

#endif

#if defined(NO_HYPER_TEST)

#include <serial/serial_port_intel_x64.h>

extern "C" int
write(int file, const void *buffer, size_t count)
{
    if (buffer == nullptr || count == 0)
        return 0;

    if (file == 1 || file == 2)
    {
        serial_port_intel_x64::instance()->write(std::string((char *)buffer, count));
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
